from __future__ import annotations

from typing import TypedDict

from models import MetricType
from providers.models import ActionPlan, TokenUsage


class DiagnosticState(TypedDict, total=False):
    """LangGraph state shared across the three diagnostic nodes."""

    anomaly_type: str
    metric_type: MetricType
    entity_id: str
    evaluation_window_minutes: int

    threshold_breaches: list[dict]
    telemetry_snapshot: dict

    sanitized_telemetry: dict
    action_plan: ActionPlan | None
    token_usage: TokenUsage | None

    cooldown_active: bool
    rate_limit_exceeded: bool

    proposed_rule_id: int | None
    error: str | None
