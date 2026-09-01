from __future__ import annotations

import json
import logging
from typing import Any

from config import ConfigManager
from database import DatabaseEngine
from models import MetricType
from providers.base import AIProvider
from providers.models import TokenUsage

from .guardrails import Guardrails
from .state import DiagnosticState

logger = logging.getLogger(__name__)

_PRIMARY_LIMIT = 20
_CONTEXT_LIMIT = 10


def _recent(rows: list[dict], limit: int) -> list[dict]:
    """Take the newest `limit` rows and return them oldest-first.

    Queries come back ORDER BY created_at DESC, so rows[0] is the NEWEST. The
    previous `rows[-limit:]` took the *oldest* slice of the window and then
    treated its last element as "latest" — every threshold decision was made
    against the stalest sample available rather than the freshest.
    """
    return [{k: v for k, v in r.items() if k != "id"} for r in rows[:limit]][::-1]


async def _cross_layer_query(
    db: DatabaseEngine,
    metric_type: MetricType,
    entity_id: str,
    minutes: int,
    cfg: ConfigManager,
) -> dict:
    """Gather metrics from this entity plus cross-layer context for root-cause analysis."""
    snapshot: dict = {}
    if metric_type == MetricType.HOST:
        snapshot["host"] = _recent(await db.query_recent_host_metrics(entity_id, minutes=minutes), _PRIMARY_LIMIT)
    elif metric_type == MetricType.CADDY:
        snapshot["caddy"] = _recent(await db.query_recent_caddy_metrics(entity_id, minutes=minutes), _PRIMARY_LIMIT)
    elif metric_type == MetricType.DOCKER:
        snapshot["docker"] = _recent(await db.query_recent_docker_events(entity_id, minutes=minutes), _PRIMARY_LIMIT)
    elif metric_type == MetricType.NETWORK:
        snapshot["network"] = _recent(await db.query_recent_icmp_probes(entity_id, minutes=minutes), _PRIMARY_LIMIT)

    if metric_type != MetricType.HOST:
        snapshot["host_context"] = _recent(
            await db.query_recent_host_metrics(cfg.collectors.host.host_id, minutes=minutes),
            _CONTEXT_LIMIT,
        )
    if metric_type != MetricType.CADDY:
        snapshot["caddy_context"] = _recent(
            await db.query_recent_caddy_metrics(cfg.collectors.caddy.instance_id, minutes=minutes),
            _CONTEXT_LIMIT,
        )
    if metric_type != MetricType.DOCKER:
        snapshot["docker_context"] = _recent(await db.query_recent_docker_events_any(minutes=minutes), _CONTEXT_LIMIT)
    return snapshot


def sanitize_telemetry(data: Any, *, max_depth: int = 8) -> Any:
    """Recursively sanitize telemetry for safe LLM consumption.

    Escapes control characters in strings, truncates overly long values,
    and enforces a maximum nesting depth to bound payload size.
    """
    if max_depth < 0:
        return None
    if isinstance(data, dict):
        return {_sanitize_key(k): sanitize_telemetry(v, max_depth=max_depth - 1) for k, v in data.items()}
    if isinstance(data, list):
        return [sanitize_telemetry(v, max_depth=max_depth - 1) for v in data]
    if isinstance(data, str):
        return _escape_string(data)[:1000]

    if isinstance(data, (int, float, bool)) or data is None:
        return data
    return str(data)[:1000]


def _sanitize_key(key: str) -> str:
    return _escape_string(key)[:200]


def _escape_string(s: str) -> str:
    """Neutralise characters that could break out of the prompt's data block.

    Container names, image tags and Caddy labels are attacker-controllable: a
    container anyone can start on the monitored host lands its name in
    docker_metrics, and from there into the model's context. Stripping NUL and
    escaping CR/LF stops newline-based breakout; backticks and angle brackets
    stop the payload from closing the delimiter that marks it as data.

    This is defence in depth, not the whole defence — the system prompt also
    declares the block untrusted. See providers/gemini.py.
    """

    return (
        s.replace("\x00", "")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("`", "'")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def thresholds_for_metric_type(config: ConfigManager) -> dict[str, Any]:
    return config.thresholds


async def evaluate_metrics(
    state: DiagnosticState,
    db: DatabaseEngine,
    cfg: ConfigManager,
) -> dict:
    """Node 1: read metrics from SQLite and detect threshold breaches."""
    metric_type = _coerce_metric_type(state["metric_type"])
    entity_id = state["entity_id"]
    minutes = state.get("evaluation_window_minutes", 10)

    try:
        snapshot = await _cross_layer_query(db, metric_type, entity_id, minutes, cfg)
    except Exception as exc:
        logger.exception("failed to query metrics for %s %s", metric_type, entity_id)
        return {"telemetry_snapshot": {}, "threshold_breaches": [], "error": str(exc)}

    breaches: list[dict] = []
    thresholds: dict = {}
    if isinstance(cfg.thresholds, dict):
        thresholds = cfg.thresholds.get(metric_type, {})

    primary = _primary_rows(snapshot, metric_type)
    if primary:
        latest = primary[-1]
        for field, bounds in thresholds.items() if isinstance(thresholds, dict) else []:
            if field not in latest:
                continue
            try:
                value = float(latest[field])
            except (TypeError, ValueError):
                continue
            if bounds.is_critical(value):
                breaches.append(
                    {
                        "field": field,
                        "value": value,
                        "threshold": bounds.critical,
                        "level": "critical",
                        "mode": bounds.mode,
                    }
                )
            elif bounds.is_warning(value):
                breaches.append(
                    {
                        "field": field,
                        "value": value,
                        "threshold": bounds.warning,
                        "level": "warning",
                        "mode": bounds.mode,
                    }
                )

    return {
        "telemetry_snapshot": snapshot,
        "threshold_breaches": breaches,
    }


def _coerce_metric_type(value: object) -> MetricType:
    if isinstance(value, MetricType):
        return value

    return MetricType(str(value))


def _primary_rows(snapshot: dict, metric_type: MetricType) -> list[dict]:
    for key in (metric_type.value, f"{metric_type.value}_context", "host"):
        rows = snapshot.get(key)
        if isinstance(rows, list) and rows:
            return rows
    return []


async def run_diagnostics(
    state: DiagnosticState,
    provider: AIProvider,
    guardrails: Guardrails,
) -> dict:
    """Node 2: sanitize telemetry and invoke the configured AI provider."""
    anomaly_type = state["anomaly_type"]

    if state.get("cooldown_active") or state.get("rate_limit_exceeded"):
        return {"action_plan": None, "error": "guardrail_blocked"}

    breaches = state.get("threshold_breaches", [])
    if not breaches:
        logger.info("diagnostic: no threshold breach for %s; skipping provider call", anomaly_type)
        return {"action_plan": None, "error": "no_breach_detected"}

    breach_summary = ", ".join(f"{b.get('field')}={b.get('value')} {b.get('level')}" for b in breaches)
    logger.info(
        "diagnostic: analyzing anomaly %s (breaches: %s) over %s window",
        anomaly_type,
        breach_summary or "none",
        state.get("evaluation_window_minutes", "?"),
    )

    sanitized = sanitize_telemetry(state.get("telemetry_snapshot", {}))
    telemetry = {
        "anomaly_type": anomaly_type,
        "threshold_breaches": breaches,
        "metrics": sanitized,
    }

    try:
        plan = await provider.analyze_incident(telemetry)
    except Exception as exc:
        logger.exception("AI provider analysis failed for %s", anomaly_type)
        await guardrails.log_call(
            anomaly_type,
            provider.provider_name,
            provider.model_name,
            TokenUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
            success=False,
            error=str(exc)[:500],
        )
        await guardrails.record_trigger(anomaly_type)
        return {"action_plan": None, "error": str(exc)}

    usage_raw = getattr(provider, "take_last_usage", None)
    usage = None
    if callable(usage_raw):
        data = usage_raw()
        if data:
            usage = TokenUsage(
                prompt_tokens=data.get("prompt_tokens", 0),
                completion_tokens=data.get("completion_tokens", 0),
                total_tokens=data.get("total_tokens", 0),
            )

    await guardrails.log_call(
        anomaly_type,
        provider.provider_name,
        provider.model_name,
        usage or TokenUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0),
        success=True,
    )
    await guardrails.record_trigger(anomaly_type)

    logger.info(
        "diagnostic: %s => severity=%s root_cause=%r (%d suggested command(s))",
        anomaly_type,
        plan.severity.value,
        plan.root_cause,
        len(plan.suggested_commands),
    )

    return {
        "sanitized_telemetry": telemetry,
        "action_plan": plan,
        "token_usage": usage,
    }


async def human_in_the_loop_validation(
    state: DiagnosticState,
    db: DatabaseEngine,
) -> dict:
    """Node 3: validate the ActionPlan and write the *proposed* rule to SQLite.

    This node strictly writes a proposed remediation rule to the database for
    human review. It NEVER executes any commands directly.
    """
    plan = state.get("action_plan")
    if plan is None:
        return {"proposed_rule_id": None, "error": state.get("error") or "no_action_plan"}

    if not plan.requires_human_approval:
        raise ValueError("ActionPlan.requires_human_approval must be True; refusing to proceed without human review")

    rule_id = await db.insert_proposed_rule(
        anomaly_type=state["anomaly_type"],
        metric_type=state["metric_type"],
        entity_id=state["entity_id"],
        action_plan_json=json.dumps(_action_plan_to_dict(plan)),
        severity=plan.severity.value,
    )
    return {"proposed_rule_id": rule_id}


def _action_plan_to_dict(plan: object) -> dict:
    return {
        "root_cause": plan.root_cause,
        "severity": plan.severity.value,
        "suggested_commands": list(plan.suggested_commands),
        "requires_human_approval": plan.requires_human_approval,
    }
