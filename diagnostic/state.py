from __future__ import annotations

from typing import TypedDict

from models import MetricType
from providers.models import ActionPlan, TokenUsage


class DiagnosticState(TypedDict, total=False):
    """LangGraph state shared across the three diagnostic nodes."""

    # --- Input (set by daemon or CLI) ---
    anomaly_type: str
    metric_type: MetricType
    entity_id: str
    evaluation_window_minutes: int

    # --- Node 1 (evaluate_metrics) output ---
    threshold_breaches: list[dict]
    telemetry_snapshot: dict

    # --- Node 2 (run_diagnostics) output ---
    sanitized_telemetry: dict
    action_plan: ActionPlan | None
    token_usage: TokenUsage | None

    # --- Guardrails ---
    cooldown_active: bool
    rate_limit_exceeded: bool

    # --- Node 3 (human_in_the_loop) output ---
    proposed_rule_id: int | None
    error: str | None
