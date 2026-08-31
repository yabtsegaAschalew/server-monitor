from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx
from prometheus_client.parser import text_string_to_metric_families
from prometheus_client.samples import Sample

from config import CaddyConfig
from models import CaddyMetric

from .errors import CollectorError

logger = logging.getLogger(__name__)

CADDY_REQUESTS_TOTAL = "caddy_http_requests_total"
CADDY_DURATION_HISTOGRAM = "caddy_http_request_duration_seconds"
CADDY_IN_FLIGHT = "caddy_http_requests_in_flight"

# The scrape streams at the transport layer but still materialises the filtered
# lines. A Caddy with high label cardinality can emit tens of thousands of
# series per family, so cap what we retain rather than trusting the endpoint.
_MAX_LINES_PER_FAMILY = 50_000

# Explicit end-to-end bound. httpx's default 5s read timeout applies per chunk,
# so a slow-drip endpoint could hold the stream open indefinitely without ever
# tripping it.
_SCRAPE_TIMEOUT = httpx.Timeout(connect=5.0, read=5.0, write=5.0, pool=5.0)
_SCRAPE_DEADLINE_SECONDS = 30.0

_KNOWN_FAMILIES: frozenset[str] = frozenset(
    {
        CADDY_REQUESTS_TOTAL,
        CADDY_DURATION_HISTOGRAM,
        CADDY_IN_FLIGHT,
    }
)


class CaddyScrapeError(CollectorError):
    pass


@dataclass(frozen=True, slots=True)
class CaddyScrapeResult:
    metric: CaddyMetric
    two_xx: float
    four_xx: float
    five_xx: float
    histogram_buckets: tuple[tuple[float, float], ...] = ()


def _histogram_quantile(quantile: float, buckets: list[tuple[float, float]]) -> float:
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
    def __init__(
        self,
        config: CaddyConfig | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self._config = config or CaddyConfig()
        self._client = client if client is not None else httpx.AsyncClient(timeout=_SCRAPE_TIMEOUT)
        self._owns_client = client is None
        self._now = now
        self._previous_total = 0.0
        self._previous_errors = 0.0
        self._previous_ts: float | None = None

    async def _stream_filtered(self) -> dict[str, list[str]]:
        line_bufs: dict[str, list[str]] = {name: [] for name in _KNOWN_FAMILIES}
        current_family: str | None = None
        truncated: set[str] = set()
        try:
            async with asyncio.timeout(_SCRAPE_DEADLINE_SECONDS):
                async with self._client.stream("GET", self._config.metrics_url) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        stripped = line.strip()
                        if not stripped:
                            continue
                        if stripped.startswith("# HELP "):
                            rest = stripped[len("# HELP ") :]
                            candidate = rest.split(None, 1)[0].split("{")[0].strip()
                            if candidate in _KNOWN_FAMILIES:
                                current_family = candidate
                                line_bufs[current_family].append(stripped)
                            else:
                                current_family = None
                        elif stripped.startswith("# TYPE "):
                            rest = stripped[len("# TYPE ") :]
                            candidate = rest.split(None, 1)[0].split("{")[0].strip()
                            if candidate in _KNOWN_FAMILIES:
                                if current_family is None:
                                    current_family = candidate
                                line_bufs[current_family].append(stripped)
                            else:
                                # Must reset, exactly as the HELP branch does.
                                # Leaving current_family pointing at the previous
                                # (known) family made every sample line of this
                                # unrelated family get parsed as if it belonged
                                # to it, silently corrupting request counts,
                                # error rate and p99.
                                current_family = None
                        elif current_family is not None:
                            buf = line_bufs[current_family]
                            if len(buf) >= _MAX_LINES_PER_FAMILY:
                                if current_family not in truncated:
                                    truncated.add(current_family)
                                    logger.warning(
                                        "caddy family %s exceeded %d series; truncating scrape",
                                        current_family,
                                        _MAX_LINES_PER_FAMILY,
                                    )
                                continue
                            buf.append(stripped)
        except TimeoutError as exc:
            raise CaddyScrapeError(
                f"GET {self._config.metrics_url} exceeded {_SCRAPE_DEADLINE_SECONDS:.0f}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise CaddyScrapeError(f"GET {self._config.metrics_url} failed: {exc}") from exc
        return line_bufs

    @staticmethod
    def _histogram_buckets(samples: list[Sample]) -> list[tuple[float, float]]:
        buckets: list[tuple[float, float]] = []
        for sample in samples:
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
    def _sum_samples(samples: list[Sample]) -> float:
        return sum(s.value for s in samples)

    @staticmethod
    def _samples_from_lines(line_bufs: dict[str, list[str]]) -> dict[str, list[Sample]]:
        samples_by_family: dict[str, list[Sample]] = {}
        for name, lines in line_bufs.items():
            if not lines:
                continue
            text = "\n".join(lines) + "\n"
            try:
                for family in text_string_to_metric_families(text):
                    samples_by_family[name] = list(family.samples)
                    break
            except Exception as exc:
                raise CaddyScrapeError(f"failed to parse Prometheus text for {name}: {exc}") from exc
        return samples_by_family

    def _build_metric_from_samples(self, samples_by_family: dict[str, list[Sample]], now: float) -> CaddyMetric:
        req_samples = samples_by_family.get(CADDY_REQUESTS_TOTAL, [])
        total, errors = self._status_breakdown_samples(req_samples)

        hist_samples = samples_by_family.get(CADDY_DURATION_HISTOGRAM, [])
        buckets = self._histogram_buckets(hist_samples)
        p99_latency_ms = _histogram_quantile(0.99, buckets) * 1000.0

        in_flight_samples = samples_by_family.get(CADDY_IN_FLIGHT, [])
        active_conns = self._sum_samples(in_flight_samples)

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

    @staticmethod
    def _status_breakdown_samples(samples: list[Sample]) -> tuple[float, float]:
        total = 0.0
        errors = 0.0
        for sample in samples:
            total += sample.value
            status = sample.labels.get("status") or sample.labels.get("status_code") or ""
            if status.startswith(("4", "5")):
                errors += sample.value
        return total, errors

    async def scrape(self) -> CaddyMetric:
        samples_by_family = self._samples_from_lines(await self._stream_filtered())
        return self._build_metric_from_samples(samples_by_family, self._now())

    async def scrape_with_details(self) -> CaddyScrapeResult:
        samples_by_family = self._samples_from_lines(await self._stream_filtered())
        metric = self._build_metric_from_samples(samples_by_family, self._now())

        req_samples = samples_by_family.get(CADDY_REQUESTS_TOTAL, [])
        two_xx, four_xx, five_xx = self._status_counts_samples(req_samples)

        hist_samples = samples_by_family.get(CADDY_DURATION_HISTOGRAM, [])
        buckets = self._histogram_buckets(hist_samples)

        return CaddyScrapeResult(
            metric=metric,
            two_xx=two_xx,
            four_xx=four_xx,
            five_xx=five_xx,
            histogram_buckets=tuple(buckets),
        )

    @staticmethod
    def _status_counts_samples(samples: list[Sample]) -> tuple[float, float, float]:
        two_xx = 0.0
        four_xx = 0.0
        five_xx = 0.0
        for sample in samples:
            status = sample.labels.get("status") or sample.labels.get("status_code") or ""
            if status.startswith("2"):
                two_xx += sample.value
            elif status.startswith("4"):
                four_xx += sample.value
            elif status.startswith("5"):
                five_xx += sample.value
        return two_xx, four_xx, five_xx

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> CaddyScraper:
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.aclose()
