from __future__ import annotations

import time
from pathlib import Path

from config import DatabaseConfig
from database import DatabaseEngine
from diagnostic.guardrails import Guardrails
from providers import TokenUsage


def _db_config(tmp_path: Path) -> DatabaseConfig:
    return DatabaseConfig(
        db_path=str(tmp_path / "test.db"),
        queue_maxsize=256,
        batch_size=16,
        prune_interval_seconds=3600.0,
        retention_days=7,
    )


async def test_cooldown_active_after_trigger(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        g = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)
        assert await g.check_cooldown("host:localhost") is False
        await g.record_trigger("host:localhost")
        assert await g.check_cooldown("host:localhost") is True


async def test_cooldown_expires_in_memory(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        g = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)
        await g.record_trigger("docker:abc")
        assert g.is_cooldown_active("docker:abc") is True

        g._cooldown_cache["docker:abc"] = time.time() - 16 * 60
        assert g.is_cooldown_active("docker:abc") is False


async def test_cooldown_keyed_per_anomaly_type(tmp_path: Path) -> None:

    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        g = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)
        await g.record_trigger("host:node-01")
        assert await g.check_cooldown("host:node-01") is True
        assert await g.check_cooldown("host:node-02") is False


async def test_rate_limit_exceeded_after_max_calls(tmp_path: Path) -> None:
    config = _db_config(tmp_path)

    async with DatabaseEngine(config) as db:
        g = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=3)
        usage = TokenUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2)
        for i in range(3):
            await g.log_call(f"a{i}", "google", "model", usage, success=True)

        assert await g.check_rate_limit() is True


async def test_rate_limit_allows_within_cap(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        g = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=5)

        usage = TokenUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2)
        for i in range(2):
            await g.log_call(f"a{i}", "google", "model", usage, success=True)
        assert await g.check_rate_limit() is False


async def test_log_call_records_usage(tmp_path: Path) -> None:

    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        g = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)

        usage = TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        await g.log_call("host:x", "google", "gemini", usage, success=True)
        rows = await db.query_recent_ai_calls(minutes=5)
        assert len(rows) == 1
        assert rows[0]["total_tokens"] == 15
        assert rows[0]["success"] == 1


async def test_warm_cache_loads_cooldown(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        g1 = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)
        await g1.record_trigger("host:warm")
    async with DatabaseEngine(config) as db:
        g2 = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)
        await g2.warm_cache()
        assert g2.is_cooldown_active("host:warm") is True
