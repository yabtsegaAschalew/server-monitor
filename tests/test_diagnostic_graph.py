from __future__ import annotations

from pathlib import Path

from config import ConfigManager, DatabaseConfig, DiagnosticConfig
from database import DatabaseEngine
from diagnostic.agent import DiagnosticAgent, compile_graph
from diagnostic.guardrails import Guardrails
from models import HostMetric, MetricType, utcnow
from providers import ActionPlan, AIProvider, Severity


def _db_config(tmp_path: Path) -> DatabaseConfig:
    return DatabaseConfig(
        db_path=str(tmp_path / "test.db"),
        queue_maxsize=256,
        batch_size=16,
        prune_interval_seconds=3600.0,
        retention_days=7,
    )


def _config(tmp_path: Path) -> ConfigManager:
    return ConfigManager(
        polling={"interval_seconds": 5.0},
        thresholds={
            "host": {
                "cpu": {"warning": 80.0, "critical": 90.0, "mode": "max"},
                "memory": {"warning": 90.0, "critical": 95.0, "mode": "max"},
            }
        },
        collectors={
            "host": {"host_id": "localhost"},
            "caddy": {"instance_id": "edge-01"},
            "database": _db_config(tmp_path),
        },
        diagnostic=DiagnosticConfig(
            gemini_api_key="test-key",
            enabled_metric_sources=["host"],
        ),
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
            root_cause="CPU utilization breached critical threshold for several minutes",
            severity=Severity.CRITICAL,
            suggested_commands=["systemctl restart nginx"],
        )

    def take_last_usage(self) -> dict[str, int] | None:
        return {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}


async def test_full_graph_writes_proposed_rule(tmp_path: Path) -> None:
    config = _config(tmp_path)
    async with DatabaseEngine(config.collectors.database) as db:
        await db.write(
            HostMetric(
                host_id="localhost",
                cpu_percent=97.0,
                memory_percent=50.0,
                disk_percent=40.0,
                load_avg=1.0,
                timestamp=utcnow(),
            )
        )
        import asyncio

        await asyncio.sleep(0.1)

        provider = FakeProvider()
        guardrails = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)
        app = compile_graph(provider, db, config, guardrails)

        initial = {
            "anomaly_type": "host:localhost",
            "metric_type": MetricType.HOST,
            "entity_id": "localhost",
            "evaluation_window_minutes": 5,
            "cooldown_active": False,
            "rate_limit_exceeded": False,
            "threshold_breaches": [],
            "telemetry_snapshot": {},
            "sanitized_telemetry": {},
            "action_plan": None,
            "token_usage": None,
            "proposed_rule_id": None,
            "error": None,
        }

        result = await app.ainvoke(initial)

        assert result["action_plan"] is not None
        assert result["proposed_rule_id"] is not None
        assert result["threshold_breaches"], "expected at least one breach"

        rules = await db.query_proposed_rules(status="pending")
        assert len(rules) == 1
        assert rules[0]["severity"] == "critical"
        assert "nginx" in rules[0]["action_plan_json"]


async def test_agent_analyze_anomaly_via_graph(tmp_path: Path) -> None:
    config = _config(tmp_path)
    async with DatabaseEngine(config.collectors.database) as db:
        await db.write(
            HostMetric(
                host_id="localhost",
                cpu_percent=96.0,
                memory_percent=50.0,
                disk_percent=40.0,
                load_avg=1.0,
                timestamp=utcnow(),
            )
        )
        import asyncio

        await asyncio.sleep(0.1)

        agent = DiagnosticAgent.__new__(DiagnosticAgent)
        agent._config = config
        agent._db = db
        agent._enabled_sources = frozenset({MetricType.HOST})
        agent._interval = 60.0
        agent._provider = FakeProvider()
        agent._guardrails = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)
        agent._graph = compile_graph(agent._provider, db, config, agent._guardrails)
        agent._stop_event = None

        plan = await agent.analyze_anomaly(MetricType.HOST, "localhost")
        assert plan is not None
        assert plan.requires_human_approval is True
        assert plan.severity == Severity.CRITICAL


async def test_agent_cooldown_blocks_second_analyze(tmp_path: Path) -> None:
    config = _config(tmp_path)
    async with DatabaseEngine(config.collectors.database) as db:
        await db.write(
            HostMetric(
                host_id="localhost",
                cpu_percent=96.0,
                memory_percent=50.0,
                disk_percent=40.0,
                load_avg=1.0,
                timestamp=utcnow(),
            )
        )
        import asyncio

        await asyncio.sleep(0.1)

        agent = DiagnosticAgent.__new__(DiagnosticAgent)
        agent._config = config
        agent._db = db
        agent._enabled_sources = frozenset({MetricType.HOST})
        agent._interval = 60.0
        agent._provider = FakeProvider()
        agent._guardrails = Guardrails(db, cooldown_minutes=15, max_calls_per_hour=10)
        agent._graph = compile_graph(agent._provider, db, config, agent._guardrails)
        agent._stop_event = None

        first = await agent.analyze_anomaly(MetricType.HOST, "localhost")
        assert first is not None
        second = await agent.analyze_anomaly(MetricType.HOST, "localhost")
        assert second is None  # blocked by cooldown
