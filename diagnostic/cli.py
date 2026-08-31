"""Shared implementations for the diagnostic inspection commands.

These are reachable two ways — `python -m main diagnostic <cmd>` and
`python -m diagnostic <cmd>` — and both call in here so the behaviour cannot
drift between entry points.

EXECUTION BOUNDARY: `approve` and `reject` update a status column and nothing
else. No command in this module executes, schedules, or hands off a proposed
remediation command. The `approve` output says so explicitly, because the word
"approve" invites the opposite assumption.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from config import ConfigManager
from database import DatabaseEngine
from models import MetricType

logger = logging.getLogger(__name__)

_RULE_STATUSES = ("pending", "approved", "rejected", "expired")

_UNTRUSTED_BANNER = (
    "WARNING: suggested commands below are model-generated from telemetry that\n"
    "         includes attacker-controllable fields (container names, image tags,\n"
    "         labels). Read every command before running it. Nothing here has\n"
    "         been executed.\n"
)


@asynccontextmanager
async def open_database(config: ConfigManager) -> AsyncIterator[DatabaseEngine]:
    """Start a DatabaseEngine and guarantee it is closed.

    The previous inline version started an engine per command and never closed
    it, leaving the writer and pruner tasks running until interpreter exit.
    """
    db = DatabaseEngine(config.collectors.database)
    await db.start()
    try:
        yield db
    finally:
        await db.aclose()


@asynccontextmanager
async def open_agent(config: ConfigManager) -> AsyncIterator[object]:
    """Start a DiagnosticAgent over its own database, closing both in order."""
    from diagnostic.agent import DiagnosticAgent

    async with open_database(config) as db:
        agent = DiagnosticAgent(config, db)
        await agent.start()
        try:
            yield agent
        finally:
            # Agent first (releases the provider's HTTP pool), database second,
            # so a late write still lands.
            await agent.aclose()


def _require_api_key(config: ConfigManager) -> bool:
    from diagnostic.agent import resolve_api_key

    if resolve_api_key(config.diagnostic) is None:
        logger.warning(
            "diagnostic command unavailable: no API key configured for provider %r",
            config.diagnostic.provider,
        )
        return False
    return True


def split_anomaly_type(anomaly: str) -> tuple[str, str]:
    """Split the agent's own ``"<metric_type>:<entity_id>"`` key.

    An entity id may itself contain a colon (an IPv6 ICMP target, say), so split
    once from the left only.
    """
    metric_type, sep, entity_id = anomaly.partition(":")
    if not sep or not metric_type or not entity_id:
        raise ValueError(f"expected '<type>:<entity>', got {anomaly!r}")
    return metric_type, entity_id


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


async def run_daemon(config: ConfigManager, interval: float | None = None) -> None:
    if not _require_api_key(config):
        return
    async with open_agent(config) as agent:
        await agent.run_daemon(interval_seconds=interval)


async def run_analyze(
    config: ConfigManager,
    *,
    metric_type: str,
    entity: str,
    window: int | None = None,
) -> None:
    if not _require_api_key(config):
        return
    window_minutes = window or config.diagnostic.evaluation_window_minutes
    async with open_agent(config) as agent:
        plan = await agent.analyze_anomaly(
            MetricType(metric_type),
            entity,
            window_minutes=window_minutes,
        )

    if plan is None:
        print("no action plan produced (guardrail blocked or no breach detected)")
        return
    print(f"severity={plan.severity.value} root_cause={plan.root_cause}")
    print("proposed commands (model-generated, NOT executed — review before running):")
    for cmd in plan.suggested_commands:
        print(f"  proposed: {cmd}")


async def run_list_rules(config: ConfigManager, status: str | None = None) -> None:
    async with open_database(config) as db:
        rows = await db.query_proposed_rules(status=status)
    if rows:
        print(_UNTRUSTED_BANNER)
    for row in rows:
        print(f"[{row['id']}] {row['status']} {row['severity']} {row['anomaly_type']} created={row['created_at']}")
        print(f"    {row['action_plan_json']}")
    if not rows:
        print("no proposed rules" + (f" with status={status}" if status else ""))


async def run_review(
    config: ConfigManager,
    rule_id: int,
    status: str,
    user: str | None = None,
) -> None:
    """Mark a rule approved or rejected. Updates a column; runs nothing."""
    reviewer = user or "cli"
    async with open_database(config) as db:
        updated = await db.update_rule_status(rule_id, status, reviewed_by=reviewer)
        if updated:
            await db.insert_diagnostic_log(
                "diagnostic",
                "info",
                f"rule {rule_id} {status} by {reviewer}",
                None,
            )
    if not updated:
        print(f"rule {rule_id} not found")
    elif status == "approved":
        print(f"rule {rule_id} approved (status only, nothing executed)")
    else:
        print(f"rule {rule_id} {status}")


# ---------------------------------------------------------------------------
# Argument parsing, shared by both entry points
# ---------------------------------------------------------------------------


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach the diagnostic subcommands to an existing parser."""
    sub = parser.add_subparsers(dest="diag_command", required=True)

    daemon = sub.add_parser("daemon", help="Run the diagnostic agent as a continuous daemon")
    daemon.add_argument("--interval", type=float, default=None, help="Override evaluation interval (seconds)")
    daemon.add_argument("--config", default="config.yaml", help="Path to YAML config")

    analyze = sub.add_parser("analyze", help="Run a single ad-hoc anomaly analysis")
    # Either --anomaly "host:localhost" (the agent's own key format) or the
    # explicit pair. One of the two is required.
    analyze.add_argument("--anomaly", default=None, help="Anomaly key, e.g. host:localhost")
    analyze.add_argument("--type", choices=[m.value for m in MetricType], dest="metric_type", default=None)
    analyze.add_argument("--entity", default=None)
    analyze.add_argument("--window", type=int, default=None, help="Evaluation window in minutes")
    analyze.add_argument("--config", default="config.yaml", help="Path to YAML config")

    list_rules = sub.add_parser("list-rules", help="List proposed remediation rules")
    list_rules.add_argument("--status", choices=list(_RULE_STATUSES), default=None)
    list_rules.add_argument("--config", default="config.yaml", help="Path to YAML config")

    approve = sub.add_parser("approve", help="Mark a rule approved (never executes commands)")
    approve.add_argument("rule_id", type=int)
    approve.add_argument("--user", default=None)
    approve.add_argument("--config", default="config.yaml", help="Path to YAML config")

    reject = sub.add_parser("reject", help="Mark a rule as rejected")
    reject.add_argument("rule_id", type=int)
    reject.add_argument("--user", default=None)
    reject.add_argument("--config", default="config.yaml", help="Path to YAML config")


def resolve_analyze_target(args: argparse.Namespace) -> tuple[str, str]:
    """Work out the (metric_type, entity_id) pair from either argument form."""
    if args.anomaly:
        return split_anomaly_type(args.anomaly)
    if args.metric_type and args.entity:
        return args.metric_type, args.entity
    raise SystemExit("analyze requires either --anomaly <type>:<entity>, or both --type and --entity")


async def dispatch(args: argparse.Namespace, config: ConfigManager | None = None) -> None:
    """Route a parsed namespace to the matching command."""
    cfg = config if config is not None else ConfigManager.from_file(args.config)

    # Read the flag directly rather than importing diagnostic.agent for it:
    # that module pulls in langgraph and the Gemini SDK, which `list-rules` and
    # `approve` have no use for.
    if not cfg.diagnostic.enabled:
        print("diagnostic module is disabled in config; cannot run diagnostic commands")
        return

    command = args.diag_command
    if command == "daemon":
        await run_daemon(cfg, args.interval)
    elif command == "analyze":
        metric_type, entity = resolve_analyze_target(args)
        await run_analyze(cfg, metric_type=metric_type, entity=entity, window=args.window)
    elif command == "list-rules":
        await run_list_rules(cfg, args.status)
    elif command == "approve":
        await run_review(cfg, args.rule_id, "approved", args.user)
    elif command == "reject":
        await run_review(cfg, args.rule_id, "rejected", args.user)
    else:
        raise SystemExit(f"unknown diagnostic subcommand: {command}")


def main(argv: list[str] | None = None) -> None:
    """Entry point for `python -m diagnostic`."""
    from dotenv import load_dotenv

    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(
        prog="python -m diagnostic",
        description="Inspect and review the AI diagnostic agent's proposals.",
    )
    add_arguments(parser)
    args = parser.parse_args(argv)
    asyncio.run(dispatch(args))
