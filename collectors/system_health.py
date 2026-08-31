from __future__ import annotations

import asyncio
import inspect
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx

from config import CaddyConfig, ConfigManager, HostConfig
from models import HostMetric

from .caddy_scraper import CaddyScrapeError, CaddyScraper, CaddyScrapeResult

logger = logging.getLogger(__name__)

DEFAULT_HOST_INTERVAL = 5.0
DEFAULT_CADDY_INTERVAL = 15.0

# SECURITY/portability: HOST_ROOT lets the monitor read the real machine's
# filesystems when they are bind-mounted under a prefix (e.g. /host) in the
# container. Defaults to / (read the container's own /proc) so behaviour is
# unchanged outside a container. The disk-usage root follows the same prefix.
_HOST_ROOT = os.environ.get("HOST_ROOT", "").rstrip("/")
_PROC_ROOT = Path(f"{_HOST_ROOT}/proc") if _HOST_ROOT else Path("/proc")


class _ProcReader(Protocol):
    def read_text(self, path: str | Path) -> str: ...


class _DefaultProcReader:
    __slots__ = ()

    def read_text(self, path: str | Path) -> str:
        return Path(path).read_text(encoding="utf-8")


_DEFAULT_READER: _ProcReader = _DefaultProcReader()


def _read_proc_stat(reader: _ProcReader = _DEFAULT_READER) -> tuple[int, int]:
    text = reader.read_text(_PROC_ROOT / "stat")
    parts = text.split("\n")[0].split()
    fields = [int(f) for f in parts[1:]]
    idle = fields[3] if len(fields) > 3 else 0
    total = sum(fields)
    return idle, total


def _read_proc_meminfo(reader: _ProcReader = _DEFAULT_READER) -> float:
    text = reader.read_text(_PROC_ROOT / "meminfo")
    info: dict[str, int] = {}
    for line in text.splitlines():
        if ":" in line:
            key, rest = line.split(":", 1)
            parts = rest.split()
            if parts:
                info[key] = int(parts[0]) * 1024
    total = info.get("MemTotal", 0)
    if total <= 0:
        return 0.0
    free = info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0) + info.get("SReclaimable", 0)
    return max(0.0, min(100.0, (1.0 - free / total) * 100.0))


def _read_proc_diskstats(reader: _ProcReader = _DEFAULT_READER) -> tuple[int, int]:
    text = reader.read_text(_PROC_ROOT / "diskstats")
    total_read_bytes = 0
    total_write_bytes = 0
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 14:
            continue
        name = parts[2]
        if not name.startswith(("sd", "vd", "nvme", "dm-")):
            continue
        total_read_bytes += int(parts[5]) * 512
        total_write_bytes += int(parts[9]) * 512
    return total_read_bytes, total_write_bytes


def _read_proc_net_dev(reader: _ProcReader = _DEFAULT_READER) -> tuple[int, int]:
    text = reader.read_text(_PROC_ROOT / "net" / "dev")
    total_recv = 0
    total_sent = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("Inter", "face")):
            continue
        parts = line.split()
        if len(parts) >= 10:
            total_recv += int(parts[1])
            total_sent += int(parts[9])
    return total_sent, total_recv


def _read_proc_loadavg(reader: _ProcReader = _DEFAULT_READER) -> float:
    text = reader.read_text(_PROC_ROOT / "loadavg")
    return float(text.split()[0])


def _read_proc_pressure(reader: _ProcReader = _DEFAULT_READER) -> tuple[float | None, float | None, float | None]:
    def _read_one(name: str) -> float | None:
        try:
            text = reader.read_text(_PROC_ROOT / "pressure" / name)
        except (FileNotFoundError, ValueError, IndexError, OSError):
            return None
        else:
            for line in text.splitlines():
                if line.startswith("some"):
                    parts = line.split()
                    for part in parts:
                        if part.startswith("avg10="):
                            return float(part.split("=", 1)[1])
            return None

    return _read_one("cpu"), _read_one("memory"), _read_one("io")


@dataclass(slots=True)
class _CounterSnapshot:
    timestamp: float
    disk_read_bytes: int
    disk_write_bytes: int
    net_sent_bytes: int
    net_recv_bytes: int


class HostMetricsCollector:
    def __init__(
        self,
        host_id: str = "localhost",
        *,
        disk_path: str | None = None,
        reader: _ProcReader | None = None,
    ) -> None:
        self._host_id = host_id
        self._disk_path = disk_path if disk_path is not None else (_HOST_ROOT or "/")
        self._reader = reader or _DEFAULT_READER
        self._snapshot: _CounterSnapshot | None = None
        self._prev_idle, self._prev_total = _read_proc_stat(self._reader)

    def collect_sync(self) -> HostMetric:
        now = time.monotonic()
        reader = self._reader

        idle, total = _read_proc_stat(reader)
        d_idle = idle - self._prev_idle
        d_total = total - self._prev_total
        self._prev_idle, self._prev_total = idle, total
        cpu_percent = max(0.0, min(100.0, (1.0 - d_idle / d_total) * 100.0)) if d_total > 0 else 0.0

        memory_percent = _read_proc_meminfo(reader)
        disk_percent = _get_disk_usage(reader, self._disk_path)
        load_avg = _read_proc_loadavg(reader)
        disk_read_bytes, disk_write_bytes = _read_proc_diskstats(reader)
        net_sent_bytes, net_recv_bytes = _read_proc_net_dev(reader)

        prev = self._snapshot
        if prev is None or now - prev.timestamp <= 0.0:
            disk_read_bps = disk_write_bps = net_sent_bps = net_recv_bps = 0.0
        else:
            elapsed = now - prev.timestamp
            disk_read_bps = max(0.0, (disk_read_bytes - prev.disk_read_bytes) / elapsed)
            disk_write_bps = max(0.0, (disk_write_bytes - prev.disk_write_bytes) / elapsed)
            net_sent_bps = max(0.0, (net_sent_bytes - prev.net_sent_bytes) / elapsed)
            net_recv_bps = max(0.0, (net_recv_bytes - prev.net_recv_bytes) / elapsed)

        self._snapshot = _CounterSnapshot(
            timestamp=now,
            disk_read_bytes=disk_read_bytes,
            disk_write_bytes=disk_write_bytes,
            net_sent_bytes=net_sent_bytes,
            net_recv_bytes=net_recv_bytes,
        )

        psi_cpu, psi_mem, psi_io = _read_proc_pressure(reader)

        return HostMetric(
            host_id=self._host_id,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            disk_percent=disk_percent,
            load_avg=load_avg,
            disk_read_bps=disk_read_bps,
            disk_write_bps=disk_write_bps,
            net_bytes_sent_per_sec=net_sent_bps,
            net_bytes_recv_per_sec=net_recv_bps,
            psi_cpu_some_avg10=psi_cpu,
            psi_memory_some_avg10=psi_mem,
            psi_io_some_avg10=psi_io,
        )

    async def collect(self) -> HostMetric:
        return await asyncio.to_thread(self.collect_sync)


def _get_disk_usage(reader: _ProcReader, path: str) -> float:
    import os

    try:
        st = os.statvfs(path)
        total = st.f_frsize * st.f_blocks
        if total <= 0:
            return 0.0
        free = st.f_frsize * st.f_bavail
        return max(0.0, min(100.0, (1.0 - free / total) * 100.0))
    except (OSError, ZeroDivisionError):
        return 0.0


class SystemHealthDaemon:
    def __init__(
        self,
        *,
        host: HostConfig | None = None,
        caddy: CaddyConfig | None = None,
        host_interval: float = DEFAULT_HOST_INTERVAL,
        caddy_interval: float = DEFAULT_CADDY_INTERVAL,
        client: httpx.AsyncClient | None = None,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if host_interval <= 0.0 or caddy_interval <= 0.0:
            raise ValueError("intervals must be positive")
        self.host_interval = host_interval
        self.caddy_interval = caddy_interval
        self.missed_scrape = 0
        self._host = HostMetricsCollector((host or HostConfig()).host_id)
        self._caddy = CaddyScraper(caddy or CaddyConfig(), client=client)
        self._sleeper = sleeper
        self._stop_event: asyncio.Event | None = None
        self._tasks: list[asyncio.Task[None]] = []

    @classmethod
    def from_config(cls, config: ConfigManager, **kwargs) -> SystemHealthDaemon:
        kwargs.setdefault("host_interval", config.polling.interval_seconds)
        kwargs.setdefault("caddy_interval", config.polling.interval_seconds)
        return cls(
            host=config.collectors.host,
            caddy=config.collectors.caddy,
            **kwargs,
        )

    def _record_failure(self, source: str, exc: BaseException) -> None:
        logger.error("system health scrape failed for %s: %s", source, exc)
        self.missed_scrape += 1

    @staticmethod
    async def _emit(sink: Callable[[object], object], item: object) -> None:
        result = sink(item)
        if inspect.isawaitable(result):
            await result

    async def _host_loop(self, sink: Callable[[object], object]) -> None:
        while not self._stop_event.is_set():
            try:
                metric = await self._host.collect()
                await self._emit(sink, metric)
            except Exception as exc:  # noqa: BLE001
                self._record_failure("host", exc)
            await self._sleeper(self.host_interval)

    async def _caddy_loop(self, sink: Callable[[object], object]) -> None:
        while not self._stop_event.is_set():
            try:
                result: CaddyScrapeResult = await self._caddy.scrape_with_details()
                await self._emit(sink, result)
            except CaddyScrapeError as exc:
                self._record_failure("caddy", exc)
            except Exception as exc:  # noqa: BLE001
                self._record_failure("caddy", exc)
            await self._sleeper(self.caddy_interval)

    async def run_forever(self, sink: Callable[[object], object]) -> None:
        self._stop_event = asyncio.Event()
        async with asyncio.TaskGroup() as tg:
            self._tasks = [
                tg.create_task(self._host_loop(sink), name="host-metrics"),
                tg.create_task(self._caddy_loop(sink), name="caddy-scrape"),
            ]

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        # Both loops spend most of their time inside a sleep of up to
        # caddy_interval; the flag alone would make shutdown wait that out.
        for task in self._tasks:
            if not task.done():
                task.cancel()

    async def aclose(self) -> None:
        await self.stop()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks = []
        # Close the HTTP client only once the caddy loop has actually stopped.
        await self._caddy.aclose()

    async def __aenter__(self) -> SystemHealthDaemon:
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.aclose()
