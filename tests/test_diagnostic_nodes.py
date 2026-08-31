from __future__ import annotations

from pathlib import Path

from config import ConfigManager, DatabaseConfig, DiagnosticConfig
from database import DatabaseEngine
from diagnostic.guardrails import Guardrails
from diagnostic.nodes import evaluate_metrics, human_in_the_loop_validation, run_diagnostics, sanitize_telemetry
from models import HostMetric, utcnow
from providers import ActionPlan, AIProvider, Severity


def _db_config(tmp_path: Path) -> DatabaseConfig:
    return DatabaseConfig(
        db_path=str(tmp_path / "test.db"),
        queue_maxsize=256,
        batch_size=16,
        prune_interval_seconds=3600.0,
        retention_days=7,
    )


def _minimal_config() -> ConfigManager:
    return ConfigManager(
        polling={"interval_seconds": 5.0},
        thresholds={
            "host": {
                "cpu": {
                    "warning": 80.0,
                    "critical": 90.0,
                    "mode": "max",
                }
            }
        },
        collectors={
            "host": {"host_id": "localhost"},
            "caddy": {"instance_id": "edge-01"},
            "database": _db_config(Path("/tmp")),
        },
        diagnostic=DiagnosticConfig(),
    )


class FakeProvider(AIProvider):
    @property
    def provider_name(self) -> str:
        return "fake"

    @property
    def model_name(self) -> str:
        return "fake-model"

    async def analyze_incident(self, telemetry_data: dict) -> ActionPlan:
        return ActionPlan(
            root_cause="Simulated root cause identified by fake provider",
            severity=Severity.MEDIUM,
            suggested_commands=["echo remediation"],
        )

    def take_last_usage(self) -> dict[str, int] | None:
        return {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}


def test_sanitize_telemetry_escapes_control_chars() -> None:
    data = {"host": {"name": "node\x00\x01\r\n<script>"}, "v": 1.5, "ok": True, "none": None}
    out = sanitize_telemetry(data)
    assert "\\u003cscript\\u003e" in out["host"]["name"]
    assert "\r" not in out["host"]["name"]
    assert "\n" not in out["host"]["name"]
    assert "\x00" not in out["host"]["name"]


def test_sanitize_telemetry_bounds_depth() -> None:
    data = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}}
    out = sanitize_telemetry(data, max_depth=2)
    # Beyond the depth budget, nested structures collapse to None.
    assert out["a"]["b"]["c"] is None


async def test_evaluate_metrics_returns_breaches(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        await db.write(
            HostMetric(
                host_id="localhost",
                cpu_percent=95.0,
                memory_percent=50.0,
                disk_percent=40.0,
                load_avg=1.0,
                timestamp=utcnow(),
            )
        )
        import asyncio

        await asyncio.sleep(0.1)
        state = {
            "anomaly_type": "host:localhost",
            "metric_type": "host",
            "entity_id": "localhost",
            "evaluation_window_minutes": 5,
        }
        result = await evaluate_metrics(state, db, _minimal_config())
        cpu_breach = [b for b in result["threshold_breaches"] if b["field"] == "cpu"]
        assert cpu_breach, f"expected cpu breach, got {result['threshold_breaches']}"
        assert cpu_breach[0]["level"] == "critical"


async def test_human_in_the_loop_writes_proposed_rule(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        plan = ActionPlan(
            root_cause="A simulated root cause that is long enough",
            severity=Severity.HIGH,
            suggested_commands=["echo proposed"],
        )
        state = {
            "anomaly_type": "host:localhost",
            "metric_type": "host",
            "entity_id": "localhost",
            "action_plan": plan,
        }
        result = await human_in_the_loop_validation(state, db)
        assert result["proposed_rule_id"] is not None
        rows = await db.query_proposed_rules(status="pending")
        assert len(rows) == 1
        assert rows[0]["severity"] == "high"


async def test_human_in_the_loop_rejects_no_plan(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        state = {"anomaly_type": "host:x", "metric_type": "host", "entity_id": "x"}
        result = await human_in_the_loop_validation(state, db)
        assert result["proposed_rule_id"] is None
        assert "no_action_plan" in result["error"]


async def test_run_diagnostics_invokes_provider_and_logs_call(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        guardrails = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)
        provider = FakeProvider()
        state = {
            "anomaly_type": "host:x",
            "telemetry_snapshot": {"cpu": 95.0},
            "threshold_breaches": [{"field": "cpu", "level": "critical"}],
            "cooldown_active": False,
            "rate_limit_exceeded": False,
        }
        result = await run_diagnostics(state, provider, guardrails)
        assert result["action_plan"] is not None
        assert result["action_plan"].requires_human_approval is True
        assert result["token_usage"].total_tokens == 15
        rows = await db.query_recent_ai_calls(minutes=5)
        assert len(rows) == 1
        assert rows[0]["success"] == 1


async def test_run_diagnostics_guardrail_block(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        guardrails = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)
        provider = FakeProvider()
        state = {
            "anomaly_type": "host:x",
            "telemetry_snapshot": {},
            "threshold_breaches": [],
            "cooldown_active": True,
            "rate_limit_exceeded": False,
        }
        result = await run_diagnostics(state, provider, guardrails)
        assert result["action_plan"] is None
        assert result["error"] == "guardrail_blocked"
