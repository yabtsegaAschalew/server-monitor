"""Async scraper for Caddy's Prometheus metrics endpoint.

Caddy exposes Prometheus text format at the admin endpoint (``/metrics``) when
metrics are enabled. This scraper fetches the payload with ``httpx`` and parses
it with ``prometheus_client``'s text parser to derive the fields that
``CaddyMetric`` needs:

* ``requests_per_second`` -- delta of the summed ``caddy_http_requests_total``
  counter across two scrapes, divided by the elapsed wall-clock time (0.0 on
  the first scrape).
* ``error_rate`` -- ratio of 4xx/5xx statuses to all requests, computed over
  the same delta window (instantaneous on the first scrape).
* ``p99_latency_ms`` -- p99 quantile estimated from the cumulative
  ``caddy_http_request_duration_seconds`` histogram buckets.
* ``active_conns`` -- summed ``caddy_http_requests_in_flight`` gauge.

A scrape that cannot fetch or parse the payload raises ``CaddyScrapeError``.
Callers must not treat a failed scrape as a healthy zero-traffic signal, which
would otherwise trip the ``requests_per_second`` low-throughput threshold.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import httpx
from prometheus_client.parser import text_string_to_metric_families

from config import CaddyConfig
from models import CaddyMetric

from .errors import CollectorError

CADDY_REQUESTS_TOTAL = "caddy_http_requests_total"
CADDY_DURATION_HISTOGRAM = "caddy_http_request_duration_seconds"
CADDY_IN_FLIGHT = "caddy_http_requests_in_flight"


class CaddyScrapeError(CollectorError):
    """Raised when the Caddy metrics endpoint is unreachable or unparseable."""


def _histogram_quantile(quantile: float, buckets: list[tuple[float, float]]) -> float:
    """Estimate a quantile from cumulative Prometheus histogram buckets.

    ``buckets`` is a list of ``(upper_bound, cumulative_count)`` pairs sorted
    ascending. The estimate interpolates linearly inside the bucket that first
    crosses the quantile's rank, mirroring PromQL's ``histogram_quantile``.
    """
    if not buckets:
        return 0.0
    total = buckets[-1][1]
    if total <= 0.0:
        return 0.0
    rank = quantile * total
    previous_upper = 0.0
    previous_count = 0.0
    for upper, count in buckets:
        if count >= rank:
            width = count - previous_count
            if width <= 0.0:
                return previous_upper
            fraction = (rank - previous_count) / width
            return previous_upper + (upper - previous_upper) * fraction
        previous_upper, previous_count = upper, count
    return previous_upper


class CaddyScraper:
    """Scrapes Caddy's Prometheus endpoint into a ``CaddyMetric`` payload."""

    def __init__(
        self,
        config: CaddyConfig | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._config = config or CaddyConfig()
        self._client = client if client is not None else httpx.AsyncClient()
        self._owns_client = client is None
        self._now = now
        self._previous_total = 0.0
        self._previous_errors = 0.0
        self._previous_ts: float | None = None

    # --------------------------------------------------------------- parse

    @staticmethod
    def _status_breakdown(family) -> tuple[float, float]:
        """Return ``(total, error_count)`` from a ``*_total`` counter family."""
        total = 0.0
        errors = 0.0
        for sample in family.samples:
            total += sample.value
            status = sample.labels.get("status") or sample.labels.get("status_code") or ""
            if status.startswith(("4", "5")):
                errors += sample.value
        return total, errors

    @staticmethod
    def _histogram_buckets(family) -> list[tuple[float, float]]:
        """Collect ``(le, cumulative_count)`` buckets from a histogram family."""
        buckets: list[tuple[float, float]] = []
        for sample in family.samples:
            if not sample.name.endswith("_bucket"):
                continue
            le = sample.labels.get("le")
            if le is None:
                continue
            try:
                buckets.append((float(le), sample.value))
            except ValueError:
                continue
        buckets.sort(key=lambda pair: pair[0])
        return buckets

    @staticmethod
    def _sum_family(family) -> float:
        return sum(sample.value for sample in family.samples)

    # ------------------------------------------------------------- public

    async def scrape(self) -> CaddyMetric:
        """Fetch and parse a fresh Caddy metrics sample."""
        try:
            response = await self._client.get(self._config.metrics_url)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise CaddyScrapeError(f"GET {self._config.metrics_url} failed: {exc}") from exc

        try:
            families: dict[str, object] = {}
            for family in text_string_to_metric_families(response.text):
                # The text parser normalises counter names by stripping the
                # "_total" suffix; index by both spellings so lookups work
                # regardless of parser behaviour.
                families[family.name] = family
                if family.type == "counter":
                    if family.name.endswith("_total"):
                        families[family.name[: -len("_total")]] = family
                    else:
                        families[family.name + "_total"] = family
        except Exception as exc:
            raise CaddyScrapeError(f"failed to parse Prometheus text: {exc}") from exc

        requests_family = families.get(CADDY_REQUESTS_TOTAL)
        total, errors = self._status_breakdown(requests_family) if requests_family is not None else (0.0, 0.0)

        histogram = families.get(CADDY_DURATION_HISTOGRAM)
        p99_latency_ms = 0.0
        if histogram is not None:
            buckets = self._histogram_buckets(histogram)
            p99_latency_ms = _histogram_quantile(0.99, buckets) * 1000.0

        in_flight = families.get(CADDY_IN_FLIGHT)
        active_conns = self._sum_family(in_flight) if in_flight is not None else 0.0

        now = self._now()
        elapsed = now - self._previous_ts if self._previous_ts is not None else 0.0
        if self._previous_ts is None:
            requests_per_second = 0.0
            error_rate = errors / total if total > 0.0 else 0.0
        else:
            delta_total = max(0.0, total - self._previous_total)
            delta_errors = max(0.0, errors - self._previous_errors)
            requests_per_second = delta_total / elapsed if elapsed > 0.0 else 0.0
            error_rate = delta_errors / delta_total if delta_total > 0.0 else 0.0

        self._previous_total = total
        self._previous_errors = errors
        self._previous_ts = now

        return CaddyMetric(
            instance_id=self._config.instance_id,
            requests_per_second=requests_per_second,
            error_rate=error_rate,
            p99_latency_ms=p99_latency_ms,
            active_conns=int(active_conns),
        )

    async def aclose(self) -> None:
        """Release the internal HTTP client if this scraper created it."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> CaddyScraper:
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.aclose()
