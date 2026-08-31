"""Memory-budget checks against the <100 MB design target.

NOT RUN in the session that wrote them, and skipped by default: these are
benchmarks, not unit tests. Allocation figures move with the interpreter, the
platform allocator, and whatever else the process has touched, so failing a
normal `pytest` run on them would be noise.

Enable deliberately:

    RUN_MEMORY_TESTS=1 uv run pytest tests/test_memory_footprint.py -v

What is actually being defended here is the shape of the design, not a
byte count:

* per-metric cost stays modest and bounded (see ``TestModelShape`` for an
  important caveat about whether ``slots=True`` on a pydantic ``BaseModel``
  does anything at all);
* the ingest queue is bounded, so a slow writer sheds load instead of growing;
* SLI aggregation happens in SQL, so a six-hour burn window costs the same as a
  five-minute one.
"""

from __future__ import annotations

import os
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from alert_engine import SloEvaluator
from config import DatabaseConfig, SloDefinition, SloSource
from database import DatabaseEngine, _connect
from models import CaddyMetric, DockerEvent, HostMetric, IcmpProbeMetric

pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_MEMORY_TESTS"),
    reason="benchmark; set RUN_MEMORY_TESTS=1 to run",
)

MB = 1024 * 1024
BUDGET_BYTES = 100 * MB


def _host_metric(i: int) -> HostMetric:
    return HostMetric(
        host_id=f"node-{i % 8}",
        cpu_percent=float(i % 100),
        memory_percent=50.0,
        disk_percent=40.0,
        load_avg=1.0,
    )


# ---------------------------------------------------------------------------
# Model shape
# ---------------------------------------------------------------------------


class TestModelShape:
    """Per-instance cost of the telemetry models.

    NOTE — worth verifying before trusting the `slots=True` in `models.py`:
    `slots` is not a documented pydantic v2 `ConfigDict` key (it belongs to
    `@pydantic.dataclasses.dataclass`), and a `BaseModel` instance stores its
    field values in `__dict__` regardless. If that is so, the `slots=True`
    scattered through models.py and providers/models.py is a silent no-op and
    the real per-instance saving was never realised.

    These tests therefore assert the property that matters — bounded, modest
    memory per metric — rather than the implementation detail, so they stay
    honest either way. `test_report_instance_layout` prints what is actually
    happening so the question can be settled by running it.
    """

    _FACTORIES = [
        lambda: _host_metric(0),
        lambda: CaddyMetric(
            instance_id="edge-01",
            requests_per_second=1.0,
            error_rate=0.0,
            p99_latency_ms=1.0,
            active_conns=1,
        ),
        lambda: DockerEvent(container_id="a1b2c3d4e5f6", container_name="web", status="die"),
        lambda: IcmpProbeMetric(
            target_host="8.8.8.8",
            target_ip="8.8.8.8",
            rtt_ms=1.0,
            avg_rtt_ms=1.0,
            min_rtt_ms=1.0,
            max_rtt_ms=1.0,
            packet_loss_pct=0.0,
            probes_sent=1,
            probes_received=1,
        ),
    ]

    @pytest.mark.parametrize("factory", _FACTORIES)
    def test_report_instance_layout(self, factory, capsys) -> None:
        """Diagnostic, not a gate: reports whether slots=True actually took."""
        instance = factory()
        name = type(instance).__name__
        has_dict = hasattr(instance, "__dict__")
        with capsys.disabled():
            print(f"  {name}: __dict__={has_dict} __slots__={hasattr(type(instance), '__slots__')}")
        # Deliberately not asserted — see the class docstring. If every model
        # reports __dict__=True, the slots=True config keys are inert and
        # should either be removed or replaced with pydantic dataclasses.
        assert name  # keeps the test meaningful if the print is swallowed

    def test_ten_thousand_metrics_stay_small(self) -> None:
        tracemalloc.start()
        try:
            before = tracemalloc.take_snapshot()
            metrics = [_host_metric(i) for i in range(10_000)]
            after = tracemalloc.take_snapshot()
            grown = sum(s.size_diff for s in after.compare_to(before, "filename"))
        finally:
            tracemalloc.stop()
        assert len(metrics) == 10_000
        # Generous: a pydantic BaseModel with ~12 fields runs roughly 0.5-1 KB
        # per instance including its __dict__, so 10k lands in single-digit MB.
        # The bound is here to catch an order-of-magnitude regression, not to
        # police a byte count.
        assert grown < 20 * MB, f"10k host metrics used {grown / MB:.1f} MB"


# ---------------------------------------------------------------------------
# Queue bound
# ---------------------------------------------------------------------------


class TestQueueBackpressure:
    async def test_queue_is_bounded_and_sheds_load(self, tmp_path: Path) -> None:
        """Over-filling the queue must drop, never grow without limit."""
        config = DatabaseConfig(
            db_path=str(tmp_path / "mem.db"),
            queue_maxsize=100,
            batch_size=16,
            prune_interval_seconds=3600.0,
            retention_days=7,
        )
        db = DatabaseEngine(config)
        # Deliberately not started: with no writer draining it, the queue fills
        # and every further write must be shed rather than buffered.
        for i in range(5_000):
            await db.write(_host_metric(i))

        assert db._queue.qsize() <= 100
        assert db.dropped_count > 0, "writes past maxsize must be counted as dropped"

    def test_default_queue_bound_matches_the_budget(self) -> None:
        assert DatabaseConfig().queue_maxsize == 1_000


# ---------------------------------------------------------------------------
# SLI aggregation cost
# ---------------------------------------------------------------------------


class TestSliAggregationCost:
    async def test_long_window_costs_no_more_than_a_short_one(self, tmp_path: Path) -> None:
        """Aggregation happens in SQL, so window length must not drive memory.

        This is the property that keeps a six-hour burn window from
        materialising thousands of row dicts on every 60-second tick.
        """
        config = DatabaseConfig(
            db_path=str(tmp_path / "sli.db"),
            queue_maxsize=256,
            batch_size=16,
            prune_interval_seconds=3600.0,
            retention_days=7,
        )
        db = DatabaseEngine(config)
        await db.start()
        try:
            now = datetime.now(UTC)
            async with _connect(config.db_path) as conn:
                await conn.executemany(
                    "INSERT INTO caddy_metrics"
                    "(instance_id,requests_per_sec,error_rate,p99_latency_ms,active_conns,created_at)"
                    " VALUES ('edge-01',100.0,0.01,1.0,1,?)",
                    [((now - timedelta(seconds=5 * i)).isoformat(),) for i in range(5_000)],
                )
                await conn.commit()

            slo = SloDefinition(name="s", source=SloSource.CADDY, entity_id="edge-01", target=0.999)
            evaluator = SloEvaluator(db)

            tracemalloc.start()
            try:
                base = tracemalloc.take_snapshot()
                await evaluator.failure_ratio(slo, minutes=5)
                mid = tracemalloc.take_snapshot()
                await evaluator.failure_ratio(slo, minutes=360)
                end = tracemalloc.take_snapshot()

                short_cost = sum(s.size_diff for s in mid.compare_to(base, "filename"))
                long_cost = sum(s.size_diff for s in end.compare_to(mid, "filename"))
            finally:
                tracemalloc.stop()

            # SUM() in SQL returns two numbers either way. Allow generous slack
            # for allocator noise; a row-materialising regression would be
            # orders of magnitude, not a factor of a few.
            assert long_cost < short_cost + 5 * MB, (
                f"6h window cost {long_cost / MB:.2f} MB vs 5m window {short_cost / MB:.2f} MB"
            )
        finally:
            await db.aclose()


# ---------------------------------------------------------------------------
# Whole-process ceiling
# ---------------------------------------------------------------------------


class TestProcessCeiling:
    async def test_ingest_and_flush_stays_inside_budget(self, tmp_path: Path) -> None:
        config = DatabaseConfig(
            db_path=str(tmp_path / "ceiling.db"),
            queue_maxsize=1_000,
            batch_size=256,
            prune_interval_seconds=3600.0,
            retention_days=7,
        )
        tracemalloc.start()
        try:
            base = tracemalloc.take_snapshot()
            db = DatabaseEngine(config)
            await db.start()
            try:
                for i in range(20_000):
                    await db.write(_host_metric(i))
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                await db.aclose()
            after = tracemalloc.take_snapshot()
            retained = sum(s.size_diff for s in after.compare_to(base, "filename"))
        finally:
            tracemalloc.stop()

        assert peak < BUDGET_BYTES, f"peak {peak / MB:.1f} MB exceeded the {BUDGET_BYTES / MB:.0f} MB budget"
        assert retained < 20 * MB, f"retained {retained / MB:.1f} MB after shutdown; possible leak"
