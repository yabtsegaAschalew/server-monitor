from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import random
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import httpx

from config import ConfigManager, DockerConfig, DockerTransportMode
from models import DockerEvent, utcnow

from .errors import CollectorError

logger = logging.getLogger(__name__)

_STREAM_TIMEOUT = httpx.Timeout(connect=10.0, read=None, write=10.0, pool=10.0)


class DockerStreamError(CollectorError):
    pass


@dataclass(frozen=True, slots=True)
class CrashLoopEvent:
    container_id: str
    container_name: str
    event_count: int
    window_seconds: float
    timestamp: object = field(default_factory=utcnow)


_DOCKER_STATUSES = frozenset({"created", "start", "stop", "die", "restart", "health_status", "kill", "oom", "pause"})


def _parse_int(value: str | int | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _failure_reason(status: str, exit_code: int | None, signal: str | None) -> str | None:
    if status == "oom":
        return "out of memory"
    if status == "kill":
        return f"killed by signal {signal}" if signal else "killed"
    if status == "die" and exit_code is not None and exit_code != 0:
        reason = f"exited with code {exit_code}"
        if signal:
            reason = f"{reason} (signal {signal})"
        return reason
    if status == "restart":
        return "container restarted"
    return None


def _build_httpx_client(config: DockerConfig) -> httpx.AsyncClient:
    """Build an httpx AsyncClient with the appropriate transport.

    SECURITY: When transport_mode is TCP_PROXY, traffic flows through
    docker-socket-proxy which enforces read-only Docker API access,
    preventing container exec, creation, or deletion via the monitor.

    SECURITY: When transport_mode is UNIX_SOCKET, httpx connects directly
    to the Docker daemon socket. No proxy-mediated restrictions apply.
    The socket's OS permissions (docker group) are the only access control.
    """
    if config.transport_mode == DockerTransportMode.UNIX_SOCKET and config.socket_path:
        transport = httpx.AsyncHTTPTransport(uds=config.socket_path)
        return httpx.AsyncClient(transport=transport, timeout=_STREAM_TIMEOUT)

    return httpx.AsyncClient(timeout=_STREAM_TIMEOUT)


def _build_event_url(config: DockerConfig) -> str:
    """Compute the events endpoint URL.

    For TCP proxy mode: {base_url}/events
    For UDS mode: http://docker/events (dummy host required by httpx for UDS transport)
    """
    if config.transport_mode == DockerTransportMode.UNIX_SOCKET:
        return "http://docker/events"
    return f"{config.base_url.rstrip('/')}/events"


def parse_event(payload: dict) -> DockerEvent | None:
    status = payload.get("Action") or payload.get("status")
    if not isinstance(status, str):
        return None

    actor = payload.get("Actor") or {}
    attributes = actor.get("Attributes") or {}
    container_id = payload.get("id") or actor.get("ID")
    if not container_id:
        return None

    if status not in _DOCKER_STATUSES:
        return None

    exit_code = _parse_int(attributes.get("exitCode"))
    try:
        return DockerEvent(
            container_id=container_id,
            container_name=attributes.get("name") or container_id,
            status=status,
            image=attributes.get("image") or payload.get("from"),
            exit_code=exit_code,
            failure_reason=_failure_reason(status, exit_code, attributes.get("signal")),
        )
    except Exception:
        logger.exception("invalid docker event payload for %s", status)
        return None


class CrashLoopDetector:
    __slots__ = ("_access_order", "_max_events", "_now", "_window_seconds", "_windows")

    def __init__(
        self,
        *,
        window_seconds: float = 900.0,
        max_events: int = 3,
        event_buffer_maxlen: int = 100,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._window_seconds = window_seconds
        self._max_events = max_events
        self._now = now
        self._windows: dict[str, deque[float]] = {}
        self._access_order: deque[str] = deque(maxlen=event_buffer_maxlen)

    def _evict_stale(self) -> None:
        now = self._now()
        cutoff = now - 2.0 * self._window_seconds
        stale = [cid for cid, window in self._windows.items() if (not window) or (window[-1] < cutoff)]
        for cid in stale:
            del self._windows[cid]

    def _touch(self, container_id: str) -> None:
        if container_id in self._windows:
            try:
                self._access_order.remove(container_id)
            except ValueError:
                pass
        self._access_order.append(container_id)

    def record(self, container_id: str, ts: float | None = None) -> bool:
        window = self._windows.setdefault(container_id, deque())
        now = ts if ts is not None else self._now()
        cutoff = now - self._window_seconds
        while window and window[0] <= cutoff:
            window.popleft()
        window.append(now)
        self._touch(container_id)
        if len(self._windows) % 64 == 0:
            self._evict_stale()
        return len(window) > self._max_events

    def count(self, container_id: str, ts: float | None = None) -> int:
        window = self._windows.get(container_id)
        if not window:
            return 0
        now = ts if ts is not None else self._now()
        cutoff = now - self._window_seconds
        while window and window[0] <= cutoff:
            window.popleft()
        return len(window)


class DockerMonitor:
    def __init__(
        self,
        config: DockerConfig | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._config = config or DockerConfig()
        self._event_url = _build_event_url(self._config)
        logger.info(
            "docker monitor transport=%s target=%s",
            self._config.transport_mode.value,
            self._event_url,
        )
        self._client = client if client is not None else _build_httpx_client(self._config)
        self._owns_client = client is None
        self._sleeper = sleeper
        self._now = now
        self._detector = CrashLoopDetector(
            window_seconds=self._config.crash_loop_window_seconds,
            max_events=self._config.max_restarts,
            event_buffer_maxlen=self._config.event_buffer_maxlen,
            now=now,
        )
        self.reconnects = 0
        self._stop_event: asyncio.Event | None = None
        self._tasks: list[asyncio.Task[None]] = []

    @classmethod
    def from_config(cls, config: ConfigManager, **kwargs) -> DockerMonitor:
        docker_config = config.collectors.docker
        # SECURITY: Environment overrides allow runtime transport switching.
        # DOCKER_SOCKET_PATH takes precedence (forces UDS mode).
        # DOCKER_BASE_URL overrides the TCP proxy target.
        # DOCKER_EVENTS_URL is supported for backward compatibility with
        # existing compose deployments — it sets the base URL (strips /events).
        if socket_path := os.environ.get("DOCKER_SOCKET_PATH"):
            docker_config = docker_config.model_copy(
                update={"transport_mode": DockerTransportMode.UNIX_SOCKET, "socket_path": socket_path}
            )
        elif base_url := os.environ.get("DOCKER_BASE_URL"):
            docker_config = docker_config.model_copy(update={"base_url": base_url})
        elif events_url := os.environ.get("DOCKER_EVENTS_URL"):
            # Backward compat: derive base_url from full events URL
            base = events_url.removesuffix("/events")
            docker_config = docker_config.model_copy(update={"base_url": base})
        kwargs.setdefault("config", docker_config)
        return cls(**kwargs)

    @staticmethod
    async def _emit(sink: Callable[[object], object], item: object) -> None:
        result = sink(item)
        if inspect.isawaitable(result):
            await result

    def _record_disconnect(self, reason: str) -> None:
        logger.error("docker events stream disconnected: %s", reason)

    async def _consume_stream(self, sink: Callable[[object], object]) -> bool:
        received_any = False
        try:
            async with self._client.stream("GET", self._event_url) as response:
                if response.status_code >= 400:
                    raise DockerStreamError(f"GET {self._event_url} returned status {response.status_code}")
                async for raw_line in response.aiter_lines():
                    if self._stop_event is not None and self._stop_event.is_set():
                        break
                    line = raw_line.strip()
                    if not line:
                        continue
                    received_any = True
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        logger.exception("skipping malformed docker event line")
                        continue
                    event = parse_event(payload)
                    if event is None:
                        continue
                    await self._emit(sink, event)
                    if event.status in self._config.filtered_actions:
                        flagged = self._detector.record(event.container_id, self._now())
                        if flagged:
                            await self._emit(
                                sink,
                                CrashLoopEvent(
                                    container_id=event.container_id,
                                    container_name=event.container_name,
                                    event_count=self._detector.count(event.container_id, self._now()),
                                    window_seconds=self._config.crash_loop_window_seconds,
                                ),
                            )
        except httpx.HTTPError as exc:
            raise DockerStreamError(f"GET {self._event_url} failed: {exc}") from exc
        return received_any

    async def _event_loop(self, sink: Callable[[object], object]) -> None:
        backoff = self._config.backoff_initial_seconds
        attempts = 0
        while not self._stop_event.is_set():
            if self._config.max_attempts is not None and attempts >= self._config.max_attempts:
                logger.error("docker events stream giving up after %d reconnect attempts", attempts)
                break
            received_any = False
            try:
                received_any = await self._consume_stream(sink)
                attempts += 1
                self._record_disconnect("stream closed by server")
            except asyncio.CancelledError:
                logger.info("docker event loop cancelled, shutting down")
                raise
            except Exception as exc:  # noqa: BLE001
                attempts += 1
                self._record_disconnect(str(exc))
            self.reconnects += 1
            if received_any:
                backoff = self._config.backoff_initial_seconds
                attempts = 0
            else:
                jitter = random.uniform(0, self._config.backoff_jitter_ratio * backoff)
                await self._sleeper(backoff + jitter)
                backoff = min(backoff * 2, self._config.backoff_max_seconds)

    async def get_container_stats(self, container_id: str) -> dict | None:
        """Fetch one-shot resource stats for a container.

        SECURITY: Uses GET /containers/{id}/stats?stream=false&one-shot=true
        which is a read-only endpoint available through docker-socket-proxy.
        For UDS mode, connects directly to the Docker daemon socket.

        Returns parsed JSON stats dict or None on failure.
        """
        # Derive base from event_url by stripping /events suffix
        base = self._event_url.rsplit("/events", 1)[0]
        url = f"{base}/containers/{container_id}/stats"
        try:
            response = await self._client.get(url, params={"stream": "false", "one-shot": "true"})
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError:
            logger.warning("failed to fetch stats for container %s", container_id)
            return None

    async def run_forever(self, sink: Callable[[object], object]) -> None:
        self._stop_event = asyncio.Event()
        async with asyncio.TaskGroup() as tg:
            tg.create_task(self._event_loop(sink))

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()

    async def aclose(self) -> None:
        await self.stop()
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> DockerMonitor:
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.aclose()
