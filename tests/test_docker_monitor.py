from __future__ import annotations

import asyncio
import json
from collections.abc import Callable

import httpx
import pytest

from collectors import CrashLoopEvent, DockerMonitor, parse_event
from collectors.docker_monitor import (
    CrashLoopDetector,
    DockerStreamError,
    _build_event_url,
    _build_httpx_client,
)
from config import ConfigManager, DockerConfig, DockerTransportMode
from models import DockerEvent

BASE_URL = "http://localhost:2375"
EVENTS_URL = f"{BASE_URL}/events"


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


class BytesStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:

        pass


async def wait_until(predicate: Callable[[], bool], *, timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.001)


def stream_response(lines: list[str]) -> httpx.Response:

    payload = "\n".join(lines).encode("utf-8")
    return httpx.Response(200, stream=BytesStream([payload]))


def one_shot_stream(*lines: str) -> httpx.Response:
    return stream_response(list(lines))


CONTAINER_ID = "a1b2c3d4e5f6"


def docker_event(
    status: str,
    container_id: str = CONTAINER_ID,
    name: str = "web-01",
    image: str = "nginx:latest",
    exit_code: int | None = None,
    signal: int | None = None,
) -> dict:
    attributes: dict[str, str] = {"name": name, "image": image}
    if exit_code is not None:
        attributes["exitCode"] = str(exit_code)

    if signal is not None:
        attributes["signal"] = str(signal)
    return {
        "status": status,
        "Action": status,
        "id": container_id,
        "from": image,
        "Type": "container",
        "Actor": {"ID": container_id, "Attributes": attributes},
        "time": 1620000000,
    }


def make_monitor(**config_kwargs) -> DockerMonitor:
    return DockerMonitor(
        DockerConfig(base_url=BASE_URL, **config_kwargs),
        sleeper=FakeSleeper(),
        now=FakeClock(),
    )


def test_parse_die_event() -> None:

    event = parse_event(docker_event("die", exit_code=137, signal=9))

    assert event is not None
    assert event.container_id == CONTAINER_ID

    assert event.container_name == "web-01"
    assert event.status == "die"
    assert event.image == "nginx:latest"

    assert event.exit_code == 137
    assert event.failure_reason == "exited with code 137 (signal 9)"


def test_parse_oom_event() -> None:
    event = parse_event(docker_event("oom", exit_code=137))

    assert event is not None

    assert event.failure_reason == "out of memory"


def test_parse_kill_event() -> None:
    event = parse_event(docker_event("kill", signal=9))

    assert event is not None
    assert event.failure_reason == "killed by signal 9"


def test_parse_pause_event() -> None:
    event = parse_event(docker_event("pause"))

    assert event is not None
    assert event.status == "pause"
    assert event.failure_reason is None


def test_parse_restart_event() -> None:
    event = parse_event(docker_event("restart"))

    assert event is not None

    assert event.failure_reason == "container restarted"


def test_parse_die_clean_exit_has_no_reason() -> None:
    event = parse_event(docker_event("die", exit_code=0))
    assert event is not None
    assert event.failure_reason is None


def test_parse_unknown_status_returns_none() -> None:
    assert parse_event(docker_event("exec_start")) is None


def test_parse_network_disconnect_returns_none() -> None:
    assert parse_event(docker_event("disconnect")) is None


def test_parse_missing_container_id_returns_none() -> None:
    payload = docker_event("die")
    payload["id"] = None

    payload["Actor"]["ID"] = None
    assert parse_event(payload) is None


@pytest.mark.parametrize(
    "bad_id",
    [
        "../../v1.41/containers/other",
        "abc123?stream=true",
        "c1",
        "z" * 12,
        "a1b2c3d4e5f6/exec",
    ],
)
def test_parse_event_rejects_malformed_container_id(bad_id: str) -> None:
    """Malformed IDs must not reach the DB.

    get_container_stats() interpolates the stored ID into a Docker API path, so
    anything that is not plain hex is a path-manipulation vector.


    """
    payload = docker_event("die")
    payload["id"] = bad_id

    payload["Actor"]["ID"] = bad_id
    assert parse_event(payload) is None


def test_sliding_window_flags_after_max_events() -> None:

    clock = FakeClock()
    detector = CrashLoopDetector(now=clock)

    assert detector.record("c1", clock()) is False
    assert detector.record("c1", clock()) is False
    assert detector.record("c1", clock()) is False
    assert detector.record("c1", clock()) is True
    assert detector.count("c1", clock()) == 4


def test_sliding_window_expires_old_events() -> None:
    clock = FakeClock()
    detector = CrashLoopDetector(window_seconds=900.0, now=clock)

    for _ in range(4):
        detector.record("c1", clock())
    assert detector.record("c1", clock()) is True

    clock.advance(901.0)
    assert detector.record("c1", clock()) is False
    assert detector.count("c1", clock()) == 1


def test_sliding_window_per_container_independent() -> None:
    clock = FakeClock()
    detector = CrashLoopDetector(now=clock)

    for _ in range(4):
        detector.record("a", clock())
    for _ in range(3):
        detector.record("b", clock())

    assert detector.count("b", clock()) == 3
    assert detector.record("a", clock()) is True
    assert detector.record("b", clock()) is True


def test_crash_loop_detector_uses_slots() -> None:
    detector = CrashLoopDetector()
    assert hasattr(detector, "__slots__")
    assert not hasattr(detector, "__dict__")


async def test_monitor_streams_events_and_flags_crash_loop(respx_mock) -> None:
    lines = [json.dumps(docker_event("die", exit_code=1)) for _ in range(4)]
    first = {"used": False}

    def handler(request) -> httpx.Response:

        if not first["used"]:
            first["used"] = True
            return stream_response(lines)
        return stream_response([])

    respx_mock.get(EVENTS_URL).mock(side_effect=handler)
    monitor = make_monitor()
    items: list[object] = []
    task = asyncio.create_task(monitor.run_forever(items.append))

    await wait_until(lambda: any(isinstance(i, CrashLoopEvent) for i in items))
    await monitor.stop()
    await task
    await monitor.aclose()

    events = [i for i in items if isinstance(i, DockerEvent)]

    crashes = [i for i in items if isinstance(i, CrashLoopEvent)]
    assert len(events) == 4
    assert len(crashes) == 1
    assert crashes[0].container_id == CONTAINER_ID

    assert crashes[0].container_name == "web-01"
    assert crashes[0].event_count == 4


async def test_monitor_backoff_doubles_with_jitter(respx_mock) -> None:
    respx_mock.get(EVENTS_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    sleeper = FakeSleeper()
    monitor = DockerMonitor(
        DockerConfig(base_url=BASE_URL, backoff_jitter_ratio=0.0),
        sleeper=sleeper,
        now=FakeClock(),
    )

    task = asyncio.create_task(monitor.run_forever(lambda item: None))
    await wait_until(lambda: len(sleeper.calls) >= 8)
    await monitor.stop()
    await task
    await monitor.aclose()

    assert sleeper.calls[:5] == [1.0, 2.0, 4.0, 8.0, 16.0]

    assert sleeper.calls[5] == 30.0
    assert all(call == 30.0 for call in sleeper.calls[5:])
    assert monitor.reconnects == len(sleeper.calls)


async def test_monitor_backoff_includes_jitter(respx_mock) -> None:
    respx_mock.get(EVENTS_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    sleeper = FakeSleeper()
    monitor = DockerMonitor(
        DockerConfig(base_url=BASE_URL, backoff_jitter_ratio=0.25),
        sleeper=sleeper,
        now=FakeClock(),
    )

    task = asyncio.create_task(monitor.run_forever(lambda item: None))

    await wait_until(lambda: len(sleeper.calls) >= 3)
    await monitor.stop()
    await task
    await monitor.aclose()

    assert 1.0 <= sleeper.calls[0] <= 1.25
    assert 2.0 <= sleeper.calls[1] <= 2.5


async def test_monitor_backoff_resets_after_successful_events(respx_mock) -> None:

    calls = {"count": 0}

    def handler(request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            return stream_response([json.dumps(docker_event("die", exit_code=1))])
        raise httpx.ConnectError("connection refused")

    respx_mock.get(EVENTS_URL).mock(side_effect=handler)
    sleeper = FakeSleeper()
    monitor = DockerMonitor(
        DockerConfig(base_url=BASE_URL, backoff_jitter_ratio=0.0),
        sleeper=sleeper,
        now=FakeClock(),
    )

    task = asyncio.create_task(monitor.run_forever(lambda item: None))
    await wait_until(lambda: len(sleeper.calls) >= 3)

    await monitor.stop()
    await task
    await monitor.aclose()

    assert sleeper.calls[:3] == [1.0, 2.0, 4.0]


async def test_monitor_gives_up_after_max_attempts(respx_mock) -> None:
    respx_mock.get(EVENTS_URL).mock(side_effect=httpx.ConnectError("connection refused"))

    sleeper = FakeSleeper()
    monitor = DockerMonitor(
        DockerConfig(base_url=BASE_URL, max_attempts=3, backoff_jitter_ratio=0.0),
        sleeper=sleeper,
        now=FakeClock(),
    )

    task = asyncio.create_task(monitor.run_forever(lambda item: None))
    await asyncio.wait_for(task, timeout=5.0)
    await monitor.aclose()

    assert monitor.reconnects == 3

    assert sleeper.calls == [1.0, 2.0, 4.0]


async def test_monitor_skips_malformed_line_and_continues(respx_mock) -> None:
    first = {"used": False}
    lines = ["this is not json", json.dumps(docker_event("die", exit_code=1))]

    def handler(request) -> httpx.Response:
        if not first["used"]:
            first["used"] = True
            return stream_response(lines)
        return stream_response([])

    respx_mock.get(EVENTS_URL).mock(side_effect=handler)
    monitor = make_monitor()
    items: list[object] = []
    task = asyncio.create_task(monitor.run_forever(items.append))

    await wait_until(lambda: sum(isinstance(i, DockerEvent) for i in items) >= 1)
    await monitor.stop()
    await task
    await monitor.aclose()

    assert sum(isinstance(i, DockerEvent) for i in items) == 1
    assert sum(isinstance(i, DockerEvent) for i in items if i.exit_code == 1) == 1


async def test_monitor_http_error_raises_stream_error(respx_mock) -> None:

    respx_mock.get(EVENTS_URL).mock(return_value=httpx.Response(500, text="boom"))

    monitor = make_monitor()
    with pytest.raises(DockerStreamError, match="500"):
        await monitor._consume_stream(lambda item: None)
    await monitor.aclose()


async def test_monitor_stop_and_aclose_are_clean(respx_mock) -> None:
    respx_mock.get(EVENTS_URL).mock(return_value=stream_response([]))
    monitor = make_monitor()

    task = asyncio.create_task(monitor.run_forever(lambda item: None))

    await asyncio.sleep(0.02)

    await monitor.stop()
    await task
    await monitor.aclose()


async def test_from_config_reads_collectors_docker() -> None:
    config = ConfigManager(
        polling={"interval_seconds": 5.0},
        thresholds={},
        collectors={"docker": {"base_url": BASE_URL, "max_attempts": 2}},
    )

    monitor = DockerMonitor.from_config(config)
    try:
        assert monitor._config.base_url == BASE_URL
        assert monitor._config.max_attempts == 2
    finally:
        await monitor.aclose()


async def test_from_config_env_override_base_url(monkeypatch) -> None:
    config = ConfigManager(
        polling={"interval_seconds": 5.0},
        thresholds={},
        collectors={"docker": {"base_url": BASE_URL}},
    )
    monkeypatch.setenv("DOCKER_BASE_URL", "http://docker-socket-proxy:2375")

    monitor = DockerMonitor.from_config(config)
    try:
        assert monitor._config.base_url == "http://docker-socket-proxy:2375"
    finally:
        await monitor.aclose()


async def test_from_config_env_override_events_url_backward_compat(monkeypatch) -> None:
    config = ConfigManager(
        polling={"interval_seconds": 5.0},
        thresholds={},
        collectors={"docker": {"base_url": BASE_URL}},
    )
    monkeypatch.setenv("DOCKER_EVENTS_URL", "http://docker-socket-proxy:2375/events")

    monitor = DockerMonitor.from_config(config)
    try:
        assert monitor._config.base_url == "http://docker-socket-proxy:2375"
    finally:
        await monitor.aclose()


async def test_from_config_env_override_socket_path(monkeypatch) -> None:

    config = ConfigManager(
        polling={"interval_seconds": 5.0},
        thresholds={},
        collectors={"docker": {"base_url": BASE_URL}},
    )
    monkeypatch.setenv("DOCKER_SOCKET_PATH", "/var/run/docker.sock")

    monitor = DockerMonitor.from_config(config)
    try:
        assert monitor._config.transport_mode == DockerTransportMode.UNIX_SOCKET
        assert monitor._config.socket_path == "/var/run/docker.sock"
    finally:
        await monitor.aclose()


async def test_consume_stream_appends_since_to_url(respx_mock) -> None:
    requested_ids: list[str] = []
    event = json.dumps(docker_event("die", exit_code=1))

    def handler(request) -> httpx.Response:
        requested_ids.append(str(request.url))
        return stream_response([event])

    respx_mock.get(url__regex=r".*/events.*").mock(side_effect=handler)
    monitor = make_monitor()
    items: list[object] = []

    await monitor._consume_stream(items.append, since=1_620_000_123)

    await monitor.aclose()

    assert len(items) == 1
    assert requested_ids, "expected at least one request"
    assert "since=1620000123" in requested_ids[0]
    assert monitor._last_event_time is not None


async def test_consume_stream_without_since_omits_param(respx_mock) -> None:
    requested_ids: list[str] = []
    event = json.dumps(docker_event("die", exit_code=1))

    def handler(request) -> httpx.Response:
        requested_ids.append(str(request.url))
        return stream_response([event])

    respx_mock.get(url__regex=r".*/events.*").mock(side_effect=handler)
    monitor = make_monitor()
    items: list[object] = []

    await monitor._consume_stream(items.append)
    await monitor.aclose()

    assert len(items) == 1
    assert requested_ids, "expected at least one request"
    assert "since=" not in requested_ids[0]


async def test_consume_stream_tracks_opened_at(respx_mock) -> None:
    clock = FakeClock()
    respx_mock.get(EVENTS_URL).mock(return_value=stream_response([json.dumps(docker_event("die", exit_code=1))]))
    monitor = DockerMonitor(DockerConfig(base_url=BASE_URL), now=clock)
    try:
        await monitor._consume_stream(lambda item: None)
        assert monitor._stream_opened_at == clock()

        assert monitor._last_event_time == clock()
    finally:
        await monitor.aclose()


async def test_event_loop_catches_up_after_disconnect(respx_mock) -> None:
    """After a disconnect, the next connect must request events since the last
    known event time, so nothing that happened during the outage is lost."""
    captured: list[float | None] = []
    calls = {"count": 0}

    def handler(request) -> httpx.Response:
        captured.append(request.url.params.get("since"))
        calls["count"] += 1
        if calls["count"] == 1:
            return stream_response([json.dumps(docker_event("die", exit_code=1))])

        raise httpx.ConnectError("connection refused")

    respx_mock.get(url__regex=r".*/events.*").mock(side_effect=handler)
    sleeper = FakeSleeper()
    clock = FakeClock()
    monitor = DockerMonitor(
        DockerConfig(base_url=BASE_URL, backoff_jitter_ratio=0.0),
        sleeper=sleeper,
        now=clock,
    )

    task = asyncio.create_task(monitor.run_forever(lambda item: None))
    await wait_until(lambda: len(captured) >= 2)

    await monitor.stop()
    await task
    await monitor.aclose()

    assert captured[0] is None
    assert captured[1] == str(int(clock()))


async def test_event_loop_catches_up_after_each_successful_cycle(respx_mock) -> None:
    """A graceful close with events must not blind the next reconnect: it should
    still request events since the last known event time."""
    captured: list[float | None] = []

    calls = {"count": 0}

    def handler(request) -> httpx.Response:
        captured.append(request.url.params.get("since"))
        calls["count"] += 1
        if calls["count"] < 3:
            return stream_response([json.dumps(docker_event("die", exit_code=1))])
        raise httpx.ConnectError("connection refused")

    respx_mock.get(url__regex=r".*/events.*").mock(side_effect=handler)
    sleeper = FakeSleeper()
    clock = FakeClock()
    monitor = DockerMonitor(
        DockerConfig(base_url=BASE_URL, backoff_jitter_ratio=0.0),
        sleeper=sleeper,
        now=clock,
    )

    task = asyncio.create_task(monitor.run_forever(lambda item: None))
    await wait_until(lambda: len(captured) >= 3)
    await monitor.stop()
    await task
    await monitor.aclose()

    assert captured[0] is None
    assert captured[1] is not None
    assert captured[2] is not None


def test_build_event_url_tcp_proxy() -> None:
    config = DockerConfig(base_url="http://proxy:2375")
    assert _build_event_url(config) == "http://proxy:2375/events"


def test_build_event_url_uds() -> None:
    config = DockerConfig(
        transport_mode=DockerTransportMode.UNIX_SOCKET,
        socket_path="/var/run/docker.sock",
    )
    assert _build_event_url(config) == "http://docker/events"


def test_build_httpx_client_tcp_proxy() -> None:
    config = DockerConfig(base_url="http://localhost:2375")
    client = _build_httpx_client(config)
    assert isinstance(client, httpx.AsyncClient)
    assert client._transport is not None


def test_build_httpx_client_uds() -> None:
    config = DockerConfig(
        transport_mode=DockerTransportMode.UNIX_SOCKET,
        socket_path="/var/run/docker.sock",
    )
    client = _build_httpx_client(config)
    assert isinstance(client, httpx.AsyncClient)


def test_config_requires_socket_path_for_uds() -> None:
    with pytest.raises(ValueError, match="socket_path is required"):
        DockerConfig(transport_mode=DockerTransportMode.UNIX_SOCKET)


def test_config_default_is_tcp_proxy() -> None:
    config = DockerConfig()
    assert config.transport_mode == DockerTransportMode.TCP_PROXY
    assert config.base_url == "http://localhost:2375"
    assert config.backoff_max_seconds == 30.0
    assert config.backoff_jitter_ratio == 0.25
    assert config.event_buffer_maxlen == 100
