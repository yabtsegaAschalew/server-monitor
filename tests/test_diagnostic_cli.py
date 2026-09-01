"""Tests for the shared diagnostic CLI implementation.

NOT RUN in the session that wrote them.

The point of `diagnostic/cli.py` is that `python -m main diagnostic ...` and
`python -m diagnostic ...` cannot drift apart, and that `approve` moves a status
column and nothing else.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from config import ConfigManager, DatabaseConfig, DiagnosticConfig
from database import DatabaseEngine
from diagnostic import cli
from models import MetricType


def _db_config(tmp_path: Path) -> DatabaseConfig:
    return DatabaseConfig(
        db_path=str(tmp_path / "cli.db"),
        queue_maxsize=256,
        batch_size=16,
        prune_interval_seconds=3600.0,
        retention_days=7,
    )


def _config(tmp_path: Path, *, enabled: bool = True) -> ConfigManager:
    return ConfigManager(
        polling={"interval_seconds": 5.0},
        thresholds={},
        collectors={
            "host": {"host_id": "localhost"},
            "caddy": {"instance_id": "edge-01"},
            "database": _db_config(tmp_path),
        },
        diagnostic=DiagnosticConfig(enabled=enabled),
    )


class TestAnomalyKeyParsing:
    def test_splits_type_and_entity(self) -> None:
        assert cli.split_anomaly_type("host:localhost") == ("host", "localhost")

    def test_splits_once_so_ipv6_entities_survive(self) -> None:
        """An ICMP target can contain colons; only the first one is a separator."""
        assert cli.split_anomaly_type("network:2001:db8::1") == ("network", "2001:db8::1")

    @pytest.mark.parametrize("bad", ["host", "host:", ":localhost", ""])
    def test_rejects_malformed_keys(self, bad: str) -> None:

        with pytest.raises(ValueError, match="expected"):
            cli.split_anomaly_type(bad)


class TestAnalyzeTargetResolution:
    def test_prefers_anomaly_key(self) -> None:
        args = argparse.Namespace(anomaly="caddy:edge-01", metric_type=None, entity=None)
        assert cli.resolve_analyze_target(args) == ("caddy", "edge-01")

    def test_accepts_explicit_pair(self) -> None:
        args = argparse.Namespace(anomaly=None, metric_type="host", entity="node-01")
        assert cli.resolve_analyze_target(args) == ("host", "node-01")

    def test_requires_one_form_or_the_other(self) -> None:
        args = argparse.Namespace(anomaly=None, metric_type=None, entity=None)
        with pytest.raises(SystemExit, match="analyze requires"):
            cli.resolve_analyze_target(args)


class TestParserWiring:
    def test_every_documented_subcommand_parses(self) -> None:
        parser = argparse.ArgumentParser()
        cli.add_arguments(parser)
        assert parser.parse_args(["list-rules", "--status", "pending"]).diag_command == "list-rules"
        assert parser.parse_args(["approve", "7"]).rule_id == 7
        assert parser.parse_args(["reject", "9"]).rule_id == 9
        assert parser.parse_args(["analyze", "--anomaly", "host:localhost"]).anomaly == "host:localhost"
        assert parser.parse_args(["daemon"]).diag_command == "daemon"

    def test_subcommand_is_required(self) -> None:
        parser = argparse.ArgumentParser()
        cli.add_arguments(parser)

        with pytest.raises(SystemExit):
            parser.parse_args([])


class TestReviewIsStatusOnly:
    async def test_approve_updates_status_and_nothing_else(self, tmp_path: Path, capsys) -> None:
        config = _config(tmp_path)
        async with DatabaseEngine(config.collectors.database) as db:
            rule_id = await db.insert_proposed_rule(
                anomaly_type="host:localhost",
                metric_type=MetricType.HOST,
                entity_id="localhost",
                action_plan_json='{"suggested_commands": ["rm -rf /tmp/nothing"]}',
                severity="high",
            )

        await cli.run_review(config, rule_id, "approved", user="tester")

        out = capsys.readouterr().out
        assert "nothing executed" in out, "the operator must be told approval does not run anything"

        async with DatabaseEngine(config.collectors.database) as db:
            rows = await db.query_proposed_rules(status="approved")
            assert len(rows) == 1
            assert rows[0]["id"] == rule_id
            assert rows[0]["reviewed_by"] == "tester"
            assert "rm -rf /tmp/nothing" in rows[0]["action_plan_json"]

    async def test_reject_sets_rejected(self, tmp_path: Path) -> None:
        config = _config(tmp_path)
        async with DatabaseEngine(config.collectors.database) as db:
            rule_id = await db.insert_proposed_rule(
                anomaly_type="host:localhost",
                metric_type=MetricType.HOST,
                entity_id="localhost",
                action_plan_json="{}",
                severity="low",
            )
        await cli.run_review(config, rule_id, "rejected")
        async with DatabaseEngine(config.collectors.database) as db:
            assert len(await db.query_proposed_rules(status="rejected")) == 1

    async def test_missing_rule_reports_cleanly(self, tmp_path: Path, capsys) -> None:
        config = _config(tmp_path)

        async with DatabaseEngine(config.collectors.database) as db:
            assert db is not None
        await cli.run_review(config, 4242, "approved")
        assert "not found" in capsys.readouterr().out


class TestListRules:
    async def test_warns_that_commands_are_untrusted(self, tmp_path: Path, capsys) -> None:
        config = _config(tmp_path)
        async with DatabaseEngine(config.collectors.database) as db:
            await db.insert_proposed_rule(
                anomaly_type="docker:a1b2c3d4e5f6",
                metric_type=MetricType.DOCKER,
                entity_id="a1b2c3d4e5f6",
                action_plan_json='{"suggested_commands": ["docker restart web"]}',
                severity="medium",
            )
        await cli.run_list_rules(config)
        out = capsys.readouterr().out
        assert "attacker-controllable" in out
        assert "docker restart web" in out

    async def test_empty_listing_says_so(self, tmp_path: Path, capsys) -> None:
        config = _config(tmp_path)

        async with DatabaseEngine(config.collectors.database) as db:
            assert db is not None
        await cli.run_list_rules(config, status="pending")
        assert "no proposed rules" in capsys.readouterr().out


class TestDisabledModule:
    async def test_dispatch_refuses_when_disabled(self, tmp_path: Path, capsys) -> None:
        config = _config(tmp_path, enabled=False)
        args = argparse.Namespace(diag_command="list-rules", status=None, config="unused")
        await cli.dispatch(args, config=config)
        assert "disabled in config" in capsys.readouterr().out


class TestDatabaseLifecycle:
    async def test_open_database_closes_what_it_opened(self, tmp_path: Path) -> None:
        """Each CLI invocation used to leak a running writer and pruner task."""
        config = _config(tmp_path)
        async with cli.open_database(config) as db:
            engine = db
            assert engine._tasks, "writer and pruner should be running inside the block"
        assert engine._tasks == [], "background tasks must be stopped on exit"
