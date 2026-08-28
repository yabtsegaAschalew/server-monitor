from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from collectors import CaddyScraper, CaddyScrapeResult, SystemHealthDaemon
from collectors.system_health import HostMetricsCollector
from config import CaddyConfig, ConfigManager
from models import HostMetric

CADDY_METRICS_URL = "http://localhost:2019/metrics"


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self._now = start

    def advance(self, seconds: float) -> None:
        self._now += seconds

    def __call__(self) -> float:
        return self._now


class FakeSleeper:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        await asyncio.sleep(0)


async def wait_until(predicate: Callable[[], bool], *, timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.001)


class FakeProcReader:
    def __init__(self) -> None:
        self.cpu_idle = 5000
        self.cpu_total = 10000
        self.mem_total_kb = 16_000_000
        self.mem_free_kb = 2_000_000
        self.mem_buffers_kb = 500_000
        self.mem_cached_kb = 3_000_000
        self.mem_sreclaimable_kb = 500_000
        self.disk_read_sectors = 1000
        self.disk_write_sectors = 2000
        self.net_sent_bytes = 3000
        self.net_recv_bytes = 4000
        self.load1 = "1.5"
        self.psi_cpu = "some avg10=0.50 avg60=0.30"
        self.psi_mem = "some avg10=1.20 avg60=0.80"
        self.psi_io = "some avg10=0.10 avg60=0.05"

    def read_text(self, path: str | Path) -> str:
        p = str(path)
        if p.endswith("/stat"):
            return f"cpu  {self.cpu_total - self.cpu_idle} 0 0 {self.cpu_idle} 0 0 0 0 0 0\n"
        if p.endswith("/meminfo"):
            return (
                f"MemTotal:       {self.mem_total_kb} kB\n"
                f"MemFree:        {self.mem_free_kb} kB\n"
                f"Buffers:        {self.mem_buffers_kb} kB\n"
                f"Cached:         {self.mem_cached_kb} kB\n"
                f"SReclaimable:   {self.mem_sreclaimable_kb} kB\n"
            )
        if p.endswith("/diskstats"):
            return f"  8  0 sda 0 0 {self.disk_read_sectors} 0 0 0 {self.disk_write_sectors} 0 0 0 0\n"
        if p.endswith("/net/dev"):
            hdr = "Inter|face bytes packets errs drop fifo frame compressed multicast|"
            tail = "bytes packets errs drop fifo frame compressed\n"
            return f"{hdr}{tail}  eth0: {self.net_recv_bytes} 0 0 0 0 0 0 0 {self.net_sent_bytes} 0 0 0 0 0 0 0\n"
        if p.endswith("/loadavg"):
            return f"{self.load1} 1.2 1.0 1/400 1234\n"
        if p.endswith("/pressure/cpu"):
            return f"{self.psi_cpu}\nfull avg10=0.10\n"
        if p.endswith("/pressure/memory"):
            return f"{self.psi_mem}\nfull avg10=0.40\n"
        if p.endswith("/pressure/io"):
            return f"{self.psi_io}\nfull avg10=0.02\n"
        raise FileNotFoundError(p)


def fake_proc(
    monkeypatch: pytest.MonkeyPatch,
    *,
    cpu_idle: int = 5000,
    cpu_total: int = 10000,
    mem_total_kb: int = 16_000_000,
    mem_free_kb: int = 2_000_000,
    mem_buffers_kb: int = 500_000,
    mem_cached_kb: int = 3_000_000,
    mem_sreclaimable_kb: int = 500_000,
    disk_read_sectors: int = 1000,
    disk_write_sectors: int = 2000,
    net_sent_bytes: int = 3000,
    net_recv_bytes: int = 4000,
    load1: str = "1.5",
    psi_cpu: str = "some avg10=0.50 avg60=0.30",
    psi_mem: str = "some avg10=1.20 avg60=0.80",
    psi_io: str = "some avg10=0.10 avg60=0.05",
) -> FakeProcReader:
    reader = FakeProcReader()
    reader.cpu_idle = cpu_idle
    reader.cpu_total = cpu_total
    reader.mem_total_kb = mem_total_kb
    reader.mem_free_kb = mem_free_kb
    reader.mem_buffers_kb = mem_buffers_kb
    reader.mem_cached_kb = mem_cached_kb
    reader.mem_sreclaimable_kb = mem_sreclaimable_kb
    reader.disk_read_sectors = disk_read_sectors
    reader.disk_write_sectors = disk_write_sectors
    reader.net_sent_bytes = net_sent_bytes
    reader.net_recv_bytes = net_recv_bytes
    reader.load1 = load1
    reader.psi_cpu = psi_cpu
    reader.psi_mem = psi_mem
    reader.psi_io = psi_io
    monkeypatch.setattr("collectors.system_health._DEFAULT_READER", reader)
    return reader


def caddy_text(total: int = 1000, errors: int = 100, in_flight: int = 42) -> str:
    two = total - errors
    four = errors // 2
    five = errors - four
    return (
        "# HELP caddy_http_requests_total Counter of HTTP requests processed.\n"
        "# TYPE caddy_http_requests_total counter\n"
        f'caddy_http_requests_total{{handler="file_server",status="2xx"}} {two}\n'
        f'caddy_http_requests_total{{handler="file_server",status="4xx"}} {four}\n'
        f'caddy_http_requests_total{{handler="file_server",status="5xx"}} {five}\n'
        "# HELP caddy_http_request_duration_seconds Histogram of HTTP request latencies.\n"
        "# TYPE caddy_http_request_duration_seconds histogram\n"
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="0.005"}} {int(total * 0.2)}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="0.01"}} {int(total * 0.3)}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="0.05"}} {int(total * 0.5)}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="0.1"}} {int(total * 0.6)}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="1"}} {total}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="+Inf"}} {total}\n'
        f'caddy_http_request_duration_seconds_sum{{handler="file_server"}} 1234.5\n'
        f'caddy_http_request_duration_seconds_count{{handler="file_server"}} {total}\n'
        "# HELP caddy_http_requests_in_flight Number of HTTP requests currently being handled.\n"
        "# TYPE caddy_http_requests_in_flight gauge\n"
        f'caddy_http_requests_in_flight{{handler="file_server"}} {in_flight}\n'
    )


def make_daemon(*, sleeper: FakeSleeper | None = None, **kwargs) -> SystemHealthDaemon:
    return SystemHealthDaemon(
        caddy=CaddyConfig(metrics_url=CADDY_METRICS_URL),
        sleeper=sleeper or FakeSleeper(),
        **kwargs,
    )


async def test_host_metric_collection_mocked(monkeypatch) -> None:
    reader = fake_proc(monkeypatch, cpu_idle=5000, cpu_total=10000, load1="1.5")
    collector = HostMetricsCollector("node-01")
    reader.cpu_idle = 9000
    reader.cpu_total = 18000

    metric = await collector.collect()

    assert isinstance(metric, HostMetric)
    assert metric.host_id == "node-01"
    assert metric.cpu_percent == pytest.approx(50.0)
    assert metric.memory_percent == pytest.approx(62.5)
    assert metric.disk_read_bps == 0.0
    assert metric.disk_write_bps == 0.0
    assert metric.net_bytes_sent_per_sec == 0.0
    assert metric.net_bytes_recv_per_sec == 0.0
    assert metric.load_avg == 1.5
    assert metric.psi_cpu_some_avg10 == 0.50
    assert metric.psi_memory_some_avg10 == 1.20
    assert metric.psi_io_some_avg10 == 0.10


async def test_host_rates_computed_from_counter_delta(monkeypatch) -> None:
    reader = fake_proc(
        monkeypatch,
        disk_read_sectors=0,
        disk_write_sectors=0,
        net_sent_bytes=0,
        net_recv_bytes=0,
    )
    clock = FakeClock()
    monkeypatch.setattr("collectors.system_health.time.monotonic", clock)
    collector = HostMetricsCollector("node-01")
    await collector.collect()

    reader.disk_read_sectors = 1000
    reader.disk_write_sectors = 2000
    reader.net_sent_bytes = 3000
    reader.net_recv_bytes = 4000
    clock.advance(2.0)
    metric = await collector.collect()

    assert metric.disk_read_bps == pytest.approx(1000 * 512 / 2.0)
    assert metric.disk_write_bps == pytest.approx(2000 * 512 / 2.0)
    assert metric.net_bytes_sent_per_sec == pytest.approx(1500.0)
    assert metric.net_bytes_recv_per_sec == pytest.approx(2000.0)


async def test_host_rates_clamp_to_zero_after_counter_reset(monkeypatch) -> None:
    reader = fake_proc(
        monkeypatch,
        disk_read_sectors=100,
        disk_write_sectors=200,
        net_sent_bytes=300,
        net_recv_bytes=400,
    )
    clock = FakeClock()
    monkeypatch.setattr("collectors.system_health.time.monotonic", clock)
    collector = HostMetricsCollector("node-01")
    await collector.collect()

    reader.disk_read_sectors = 0
    reader.disk_write_sectors = 0
    reader.net_sent_bytes = 0
    reader.net_recv_bytes = 0
    clock.advance(1.0)
    metric = await collector.collect()

    assert metric.disk_read_bps == 0.0
    assert metric.disk_write_bps == 0.0
    assert metric.net_bytes_sent_per_sec == 0.0
    assert metric.net_bytes_recv_per_sec == 0.0


async def test_caddy_scrape_with_details_extracts_status_distribution(respx_mock) -> None:
    respx_mock.get(CADDY_METRICS_URL).mock(return_value=httpx.Response(200, text=caddy_text()))
    scraper = CaddyScraper(CaddyConfig(metrics_url=CADDY_METRICS_URL))

    result = await scraper.scrape_with_details()

    assert isinstance(result, CaddyScrapeResult)
    assert result.two_xx == 900
    assert result.four_xx == 50
    assert result.five_xx == 50
    assert result.metric.active_conns == 42
    assert result.histogram_buckets[0] == (0.005, 200.0)
    assert result.histogram_buckets[-1][0] == float("inf")
    await scraper.aclose()


async def test_daemon_runs_loops_on_configured_intervals(monkeypatch, respx_mock) -> None:
    respx_mock.get(CADDY_METRICS_URL).mock(return_value=httpx.Response(200, text=caddy_text()))
    fake_proc(monkeypatch)
    sleeper = FakeSleeper()
    daemon = make_daemon(sleeper=sleeper, host_interval=0.25, caddy_interval=15.0)
    host_items: list[HostMetric] = []
    caddy_items: list[CaddyScrapeResult] = []

    async def sink(item: object) -> None:
        if isinstance(item, HostMetric):
            host_items.append(item)
        elif isinstance(item, CaddyScrapeResult):
            caddy_items.append(item)

    task = asyncio.create_task(daemon.run_forever(sink))
    try:
        await wait_until(lambda: len(host_items) >= 2 and len(caddy_items) >= 2)
        assert len(host_items) >= 2
        assert len(caddy_items) >= 2
        assert 0.25 in sleeper.calls
        assert 15.0 in sleeper.calls
    finally:
        await daemon.stop()
        await task
        await daemon.aclose()


@pytest.mark.parametrize("failure", ["connect", "status"])
async def test_caddy_failure_increments_missed_scrape_and_continues(respx_mock, failure: str) -> None:
    route = respx_mock.get(CADDY_METRICS_URL)
    if failure == "connect":
        route.mock(side_effect=httpx.ConnectError("connection refused"))
    else:
        route.mock(return_value=httpx.Response(500, text="boom"))

    daemon = make_daemon(host_interval=0.01, caddy_interval=0.01)
    items: list[object] = []
    task = asyncio.create_task(daemon.run_forever(items.append))

    try:
        await wait_until(lambda: daemon.missed_scrape >= 2)

        route.mock(return_value=httpx.Response(200, text=caddy_text()))
        await wait_until(lambda: sum(isinstance(i, CaddyScrapeResult) for i in items) >= 2)
        stable_count = daemon.missed_scrape
        assert stable_count >= 2

        await wait_until(lambda: sum(isinstance(i, CaddyScrapeResult) for i in items) >= 4)
        assert daemon.missed_scrape == stable_count
    finally:
        await daemon.stop()
        await task
        await daemon.aclose()


async def test_host_failure_is_contained(monkeypatch, respx_mock) -> None:
    respx_mock.get(CADDY_METRICS_URL).mock(return_value=httpx.Response(200, text=caddy_text()))
    fake_proc(monkeypatch)

    original_read_text = FakeProcReader.read_text

    def boom(self_inner, path):
        if str(path).endswith("/meminfo"):
            raise RuntimeError("memory read failed")
        return original_read_text(self_inner, path)

    monkeypatch.setattr(FakeProcReader, "read_text", boom)

    daemon = make_daemon(host_interval=0.01, caddy_interval=0.01)
    items: list[object] = []
    task = asyncio.create_task(daemon.run_forever(items.append))

    try:
        await wait_until(lambda: daemon.missed_scrape >= 2)
        assert sum(isinstance(i, CaddyScrapeResult) for i in items) >= 1
    finally:
        await daemon.stop()
        await task
        await daemon.aclose()


async def test_daemon_stop_and_aclose_are_clean(respx_mock) -> None:
    respx_mock.get(CADDY_METRICS_URL).mock(return_value=httpx.Response(200, text=caddy_text()))
    daemon = make_daemon(host_interval=0.01, caddy_interval=0.01)

    task = asyncio.create_task(daemon.run_forever(lambda item: None))
    try:
        await asyncio.sleep(0.02)
        await daemon.stop()
        await task
    finally:
        await daemon.aclose()


def test_daemon_rejects_non_positive_intervals() -> None:
    with pytest.raises(ValueError, match="positive"):
        SystemHealthDaemon(host_interval=0.0)


def test_daemon_from_config_maps_collector_settings() -> None:
    config = ConfigManager(
        polling={"interval_seconds": 7.5},
        thresholds={},
        collectors={
            "host": {"host_id": "edge-host"},
            "caddy": {"instance_id": "edge-01", "metrics_url": CADDY_METRICS_URL},
        },
    )

    daemon = SystemHealthDaemon.from_config(config)
    assert daemon.host_interval == 7.5
    assert daemon.caddy_interval == 7.5
    assert daemon._host._host_id == "edge-host"
    assert daemon._caddy._config.instance_id == "edge-01"
    assert daemon._caddy._config.metrics_url == CADDY_METRICS_URL
