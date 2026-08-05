"""Tests for the standalone Caddy Prometheus scraper.

``CaddyScraper`` fetches Caddy's ``/metrics`` endpoint over HTTP and parses the
Prometheus text payload into a ``CaddyMetric``. HTTP is mocked with ``respx`` so
no real sockets are touched; a deterministic ``FakeClock`` drives the
rate/error-rate delta calculations.
"""

from __future__ import annotations

import httpx
import pytest

from collectors import CaddyScraper
from collectors.caddy_scraper import CaddyScrapeError
from config import CaddyConfig
from models import CaddyMetric

CADDY_METRICS_URL = "http://localhost:2019/metrics"


class FakeClock:
    """Deterministic clock so rate/timeout calculations are exact."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._now = start

    def advance(self, seconds: float) -> None:
        self._now += seconds

    def __call__(self) -> float:
        return self._now


def caddy_text(total: int = 1000, errors: int = 100, in_flight: int = 42) -> str:
    """Synthesise a Caddy-style Prometheus text payload for tests.

    Buckets are scaled from ``total`` so the p99 estimate is deterministic:
    with ``total=1000``, bucket counts are 200..1000 and p99 lands at 975ms.
    """
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
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="0.025"}} {int(total * 0.4)}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="0.05"}} {int(total * 0.5)}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="0.1"}} {int(total * 0.6)}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="0.25"}} {int(total * 0.7)}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="0.5"}} {int(total * 0.8)}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="1"}} {total}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="2.5"}} {total}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="5"}} {total}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="10"}} {total}\n'
        f'caddy_http_request_duration_seconds_bucket{{handler="file_server",le="+Inf"}} {total}\n'
        f'caddy_http_request_duration_seconds_sum{{handler="file_server"}} 1234.5\n'
        f'caddy_http_request_duration_seconds_count{{handler="file_server"}} {total}\n'
        "# HELP caddy_http_requests_in_flight Number of HTTP requests currently being handled.\n"
        "# TYPE caddy_http_requests_in_flight gauge\n"
        f'caddy_http_requests_in_flight{{handler="file_server"}} {in_flight}\n'
    )


def caddy_scraper(**kwargs) -> CaddyScraper:
    return CaddyScraper(
        CaddyConfig(instance_id="edge-01", metrics_url=CADDY_METRICS_URL),
        **kwargs,
    )


async def test_caddy_scrape_parses_metrics(respx_mock) -> None:
    respx_mock.get(CADDY_METRICS_URL).mock(return_value=httpx.Response(200, text=caddy_text()))
    scraper = caddy_scraper(now=FakeClock())
    metric = await scraper.scrape()

    assert isinstance(metric, CaddyMetric)
    assert metric.instance_id == "edge-01"
    # First scrape: no baseline, so no request rate yet.
    assert metric.requests_per_second == 0.0
    assert metric.error_rate == pytest.approx(0.10)  # (50+50)/1000
    assert metric.p99_latency_ms == pytest.approx(975.0, abs=1.0)
    assert metric.active_conns == 42
    await scraper.aclose()


async def test_caddy_rate_and_error_rate_from_delta(respx_mock) -> None:
    state = {"total": 1000, "errors": 100}

    def handler(request) -> httpx.Response:
        return httpx.Response(200, text=caddy_text(total=state["total"], errors=state["errors"]))

    respx_mock.get(CADDY_METRICS_URL).mock(side_effect=handler)
    clock = FakeClock()
    scraper = caddy_scraper(now=clock)
    await scraper.scrape()

    state["total"] = 2000
    state["errors"] = 200
    clock.advance(2.0)
    metric = await scraper.scrape()

    assert metric.requests_per_second == pytest.approx(500.0)  # 1000 reqs / 2s
    assert metric.error_rate == pytest.approx(0.10)  # 100 errors / 1000 reqs
    await scraper.aclose()


async def test_caddy_missing_families_default_to_zero(respx_mock) -> None:
    respx_mock.get(CADDY_METRICS_URL).mock(return_value=httpx.Response(200, text="# no metrics yet\n"))
    scraper = caddy_scraper()
    metric = await scraper.scrape()

    assert metric.requests_per_second == 0.0
    assert metric.error_rate == 0.0
    assert metric.p99_latency_ms == 0.0
    assert metric.active_conns == 0
    await scraper.aclose()


async def test_caddy_unreachable_raises(respx_mock) -> None:
    respx_mock.get(CADDY_METRICS_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    scraper = caddy_scraper()
    with pytest.raises(CaddyScrapeError, match="GET"):
        await scraper.scrape()
    await scraper.aclose()


async def test_caddy_http_error_status_raises(respx_mock) -> None:
    respx_mock.get(CADDY_METRICS_URL).mock(return_value=httpx.Response(500, text="internal error"))
    scraper = caddy_scraper()
    with pytest.raises(CaddyScrapeError, match="GET"):
        await scraper.scrape()
    await scraper.aclose()


async def test_caddy_unparseable_payload_raises(respx_mock) -> None:
    respx_mock.get(CADDY_METRICS_URL).mock(
        return_value=httpx.Response(200, text="this is not prometheus \x00 text")
    )
    scraper = caddy_scraper()
    with pytest.raises(CaddyScrapeError, match="parse"):
        await scraper.scrape()
    await scraper.aclose()
