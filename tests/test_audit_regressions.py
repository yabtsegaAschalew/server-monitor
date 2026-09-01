"""Regression tests for the silent-failure classes found in the security audit.

Each test here corresponds to a bug that shipped while the suite was green,
because nothing exercised the seam where the failure occurred. They are grouped
in one file so the class of mistake stays visible.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from collectors.caddy_scraper import CaddyScrapeResult
from config import DatabaseConfig, interpolate_env, interpolate_tree
from database import DatabaseEngine, _WriterWorker
from models import CaddyMetric


def _db_config(tmp_path: Path, **overrides: object) -> DatabaseConfig:
    return DatabaseConfig(
        db_path=str(tmp_path / "regressions.db"),
        queue_maxsize=int(overrides.get("queue_maxsize", 256)),
        batch_size=int(overrides.get("batch_size", 16)),
        prune_interval_seconds=float(overrides.get("prune_interval_seconds", 3600.0)),
        retention_days=int(overrides.get("retention_days", 7)),
    )


def _caddy_metric(instance_id: str = "edge-01") -> CaddyMetric:
    return CaddyMetric(
        instance_id=instance_id,
        requests_per_second=150.0,
        error_rate=0.02,
        p99_latency_ms=45.0,
        active_conns=12,
    )


def test_to_row_unwraps_caddy_scrape_result() -> None:
    """SystemHealthDaemon emits CaddyScrapeResult, not CaddyMetric.

    _to_row only matched CaddyMetric, so every Caddy sample fell through to
    `return None` and was dropped without a log line — the caddy_metrics table
    stayed empty for the life of the process.
    """
    result = CaddyScrapeResult(metric=_caddy_metric(), two_xx=10.0, four_xx=1.0, five_xx=0.0)

    row = _WriterWorker._to_row(result)

    assert row is not None, "CaddyScrapeResult must be persistable"
    table, values = row

    assert table == "caddy"
    assert values[0] == "edge-01"


def test_to_row_still_accepts_a_bare_caddy_metric() -> None:

    row = _WriterWorker._to_row(_caddy_metric())
    assert row is not None
    assert row[0] == "caddy"


async def test_caddy_scrape_result_round_trips_to_sqlite(tmp_path: Path) -> None:
    """End to end: what the collector emits is what the table receives."""
    config = _db_config(tmp_path, batch_size=1)
    db = DatabaseEngine(config)
    await db.start()
    try:
        await db.write(CaddyScrapeResult(metric=_caddy_metric(), two_xx=1.0, four_xx=0.0, five_xx=0.0))
        rows: list[dict] = []
        for _ in range(50):
            rows = await db.query_recent_caddy_metrics("edge-01", minutes=60)
            if rows:
                break

            await asyncio.sleep(0.05)
        assert rows, "caddy metrics must be persisted, not silently dropped"
        assert rows[0]["instance_id"] == "edge-01"

    finally:
        await db.aclose()


async def test_writer_survives_a_failing_flush(tmp_path: Path) -> None:
    """The writer must not die on a bad batch.

    It previously had no exception handling, so one failure stopped all
    persistence while collectors kept scraping and the queue silently filled.
    """

    class FlakyWriter(_WriterWorker):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]
            self.calls: list[int] = []

        async def _flush_batch(self, batch: list[object]) -> None:
            self.calls.append(len(batch))
            if len(self.calls) == 1:
                raise RuntimeError("disk on fire")
            await super()._flush_batch(batch)

    config = _db_config(tmp_path, batch_size=1)
    queue: asyncio.Queue[object] = asyncio.Queue(maxsize=32)
    worker = FlakyWriter(config.db_path, queue, 1)
    await worker.start()

    stop = asyncio.Event()
    task = asyncio.create_task(worker.run(stop))
    try:
        await queue.put(_caddy_metric())
        await queue.put(_caddy_metric("edge-02"))
        for _ in range(50):
            if len(worker.calls) >= 2:
                break

            await asyncio.sleep(0.05)
        assert len(worker.calls) >= 2, "writer stopped consuming after a failed flush"
        assert not task.done(), "writer task must survive a failed flush"

    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=5.0)
        await worker.close()


def test_recent_returns_newest_rows_oldest_first() -> None:
    """Rows arrive ORDER BY created_at DESC.

    The old `rows[-20:]` took the OLDEST slice, and `[-1]` on it then picked the
    stalest sample in the window while calling it "latest".
    """
    from diagnostic.nodes import _recent

    rows = [{"id": i, "cpu": float(100 - i)} for i in range(50)]

    out = _recent(rows, 20)

    assert len(out) == 20
    assert out[-1]["cpu"] == 100.0, "last element must be the NEWEST row"
    assert out[0]["cpu"] == 81.0, "first element must be the oldest of the newest 20"
    assert "id" not in out[0], "internal id column must be stripped"


async def test_rate_limit_counts_failed_calls(tmp_path: Path) -> None:
    """A failing provider must still consume budget.

    Counting only success = 1 meant an erroring provider was never rate
    limited, so the daemon retried every entity every cycle forever. Failed
    calls are still billed for input tokens.
    """
    db = DatabaseEngine(_db_config(tmp_path))
    await db.start()
    try:
        await db.insert_ai_call_log(
            anomaly_type="host:localhost",
            provider="google",
            model="gemini-1.5-flash",
            prompt_tokens=100,
            completion_tokens=0,
            total_tokens=100,
            success=False,
            error="quota exhausted",
        )
        assert await db.count_ai_calls_last_hour() == 1
    finally:
        await db.aclose()


async def test_run_diagnostics_skips_provider_without_a_breach() -> None:
    """No breach, no paid call — and no provider interaction at all."""
    from diagnostic.nodes import run_diagnostics

    class ExplodingProvider:
        provider_name = "test"
        model_name = "test"

        async def analyze_incident(self, telemetry_data: dict) -> object:
            raise AssertionError("provider must not be called without a threshold breach")

    class RecordingGuardrails:
        def __init__(self) -> None:
            self.calls = 0

        async def log_call(self, *args: object, **kwargs: object) -> None:
            self.calls += 1

        async def record_trigger(self, *args: object) -> None:
            self.calls += 1

    guardrails = RecordingGuardrails()
    state = {
        "anomaly_type": "host:localhost",
        "threshold_breaches": [],
        "telemetry_snapshot": {"host": [{"cpu": 5.0}]},
    }

    result = await run_diagnostics(state, ExplodingProvider(), guardrails)

    assert result["action_plan"] is None
    assert result["error"] == "no_breach_detected"
    assert guardrails.calls == 0, "a skipped call must not consume cooldown or quota"


def test_interpolation_cannot_inject_yaml_structure() -> None:
    """Interpolation happens after parsing, so a value stays a value.


    Substituting into raw YAML text meant an env var containing ": " or "#"
    could change the shape of the config wherever the placeholder was unquoted.


    """
    tree = {"diagnostic": {"gemini_api_key": "${EVIL}"}}

    env = {"EVIL": "key\n  enabled: false  # injected"}

    with pytest.raises(ValueError, match="line breaks"):
        interpolate_tree(tree, env)

    out = interpolate_tree({"k": "${V}"}, {"V": "a: b # c &anchor *alias"})
    assert out == {"k": "a: b # c &anchor *alias"}


def test_interpolation_fails_closed_on_missing_variable() -> None:
    with pytest.raises(ValueError, match="not set and has no default"):
        interpolate_env("${DEFINITELY_NOT_SET_ANYWHERE}", {})


def test_interpolation_uses_default_when_unset() -> None:
    assert interpolate_env("${NOPE:fallback}", {}) == "fallback"
    assert interpolate_env("${NOPE:}", {}) == ""


def test_interpolation_does_not_escape_backslashes_or_quotes() -> None:
    """Post-parse interpolation must pass secrets through byte for byte.

    The old text-substitution path escaped backslashes and quotes to survive
    YAML re-parsing, which silently corrupted any secret containing them.
    """
    secret = r'p@ss\word"with\'quotes'
    assert interpolate_env("${SECRET}", {"SECRET": secret}) == secret


async def test_prune_deletes_old_rows(tmp_path: Path) -> None:
    """`DELETE ... LIMIT` needs a compile-time option that is not universal.

    The rowid subquery form is portable; this test fails loudly if it regresses.
    """
    from database import _connect, _PruneWorker

    config = _db_config(tmp_path, retention_days=1)
    db = DatabaseEngine(config)
    await db.start()
    await db.aclose()

    old = (datetime.now(UTC) - timedelta(days=5)).isoformat()
    fresh = datetime.now(UTC).isoformat()
    async with _connect(config.db_path) as conn:
        await conn.executemany(
            "INSERT INTO caddy_metrics"
            "(instance_id,requests_per_sec,error_rate,p99_latency_ms,active_conns,created_at)"
            " VALUES (?,?,?,?,?,?)",
            [("edge-01", 1.0, 0.0, 1.0, 1, old)] * 3 + [("edge-01", 1.0, 0.0, 1.0, 1, fresh)],
        )
        await conn.commit()

    await _PruneWorker(config.db_path, 3600.0, 1)._prune()

    async with _connect(config.db_path) as conn:
        cursor = await conn.execute("SELECT COUNT(*) FROM caddy_metrics")
        remaining = (await cursor.fetchone())[0]
    assert remaining == 1, "only the fresh row should survive retention"
