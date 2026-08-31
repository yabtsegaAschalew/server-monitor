from __future__ import annotations

import asyncio
import logging
from functools import partial

from langgraph.graph import END, StateGraph

from config import ConfigManager, DiagnosticConfig
from database import DatabaseEngine
from models import MetricType
from providers.base import AIProvider
from providers.gemini import GeminiProvider
from providers.models import ActionPlan

from .guardrails import Guardrails
from .nodes import evaluate_metrics, human_in_the_loop_validation, run_diagnostics
from .state import DiagnosticState

logger = logging.getLogger(__name__)

# Outer bound on one graph invocation: the provider's own LLM timeout plus
# headroom for the two SQLite nodes on either side of it.
_GRAPH_TIMEOUT_SECONDS = 60.0


def is_diagnostic_enabled(config: ConfigManager) -> bool:
    return config.diagnostic.enabled


def resolve_api_key(config: DiagnosticConfig) -> str | None:
    """Return the configured API key, or None when none is set.

    ConfigManager.from_file already expanded ${VAR} placeholders, so the value
    here is the literal key. Re-running interpolation would re-expand a literal
    ${...} that legitimately appears inside a key — or raise on an unset name
    and silently disable the diagnostic module.
    """
    if config.provider == "gemini":
        return config.gemini_api_key or None
    return None


def build_provider(config: DiagnosticConfig, api_key: str | None) -> AIProvider | None:
    if config.provider == "gemini":
        if not api_key:
            return None
        return GeminiProvider(api_key=api_key, model=config.gemini_model)
    raise ValueError(f"unknown AI provider: {config.provider!r}")


def compile_graph(
    provider: AIProvider,
    db: DatabaseEngine,
    config: ConfigManager,
    guardrails: Guardrails,
):
    graph = StateGraph(DiagnosticState)

    graph.add_node("evaluate_metrics", partial(evaluate_metrics, db=db, cfg=config))
    graph.add_node("run_diagnostics", partial(run_diagnostics, provider=provider, guardrails=guardrails))
    graph.add_node("human_in_the_loop", partial(human_in_the_loop_validation, db=db))

    graph.set_entry_point("evaluate_metrics")
    graph.add_edge("evaluate_metrics", "run_diagnostics")
    graph.add_edge("run_diagnostics", "human_in_the_loop")
    graph.add_edge("human_in_the_loop", END)

    return graph.compile()


class DiagnosticAgent:
    """Central diagnostic agent — both continuous daemon and on-demand CLI.

    Wraps the compiled LangGraph and enforces guardrails (cooldown + rate
    limit) before invoking the model. It never executes remediation commands.
    """

    __slots__ = (
        "_config",
        "_db",
        "_enabled_sources",
        "_graph",
        "_guardrails",
        "_interval",
        "_provider",
        "_stop_event",
    )

    def __init__(self, config: ConfigManager, db: DatabaseEngine) -> None:
        self._config = config
        self._db = db
        diag = config.diagnostic
        self._enabled_sources = frozenset(diag.enabled_metric_sources)
        self._interval = diag.evaluation_interval_seconds

        api_key = resolve_api_key(diag)
        self._provider = build_provider(diag, api_key)
        if self._provider is None:
            raise RuntimeError(
                "diagnostic module is enabled but no API key is configured "
                "(set GEMINI_API_KEY or diagnostic.gemini_api_key)"
            )

        self._guardrails = Guardrails(
            db,
            cooldown_minutes=diag.cooldown_minutes,
            max_calls_per_hour=diag.max_calls_per_hour,
        )
        self._graph = compile_graph(self._provider, db, config, self._guardrails)
        self._stop_event: asyncio.Event | None = None

    @property
    def provider(self) -> AIProvider:
        return self._provider

    async def start(self) -> None:
        await self._guardrails.warm_cache()

    async def run_daemon(self, interval_seconds: float | None = None) -> None:
        self._stop_event = asyncio.Event()
        interval = interval_seconds or self._interval
        logger.info("diagnostic daemon starting (interval=%.0fs, sources=%s)", interval, sorted(self._enabled_sources))
        while not self._stop_event.is_set():
            try:
                await self._scan_all_entities()
            except Exception:
                logger.exception("diagnostic scan failed")
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
            except TimeoutError:
                pass

    async def _scan_all_entities(self) -> None:
        for source in self._enabled_sources:
            metric_type = source if isinstance(source, MetricType) else MetricType(str(source))
            entity_ids: list[str] = []
            if metric_type == MetricType.HOST:
                entity_ids = [self._config.collectors.host.host_id]
            elif metric_type == MetricType.CADDY:
                entity_ids = [self._config.collectors.caddy.instance_id]
            elif metric_type == MetricType.DOCKER:
                entity_ids = await self._db.list_known_container_ids()
            elif metric_type == MetricType.ENDPOINT:
                entity_ids = [e.endpoint_id for e in self._config.collectors.endpoints]
            elif metric_type == MetricType.NETWORK:
                entity_ids = [t.host for t in self._config.collectors.network.icmp_targets]

            for entity_id in entity_ids:
                anomaly_type = f"{metric_type.value}:{entity_id}"
                if self._guardrails.is_cooldown_active(anomaly_type):
                    continue
                await self.analyze_anomaly(metric_type, entity_id)

    async def analyze_anomaly(
        self,
        metric_type: MetricType,
        entity_id: str,
        *,
        window_minutes: int | None = None,
    ) -> ActionPlan | None:
        anomaly_type = f"{metric_type.value}:{entity_id}"

        cooldown_active = await self._guardrails.check_cooldown(anomaly_type)
        rate_limit_exceeded = await self._guardrails.check_rate_limit()
        if cooldown_active:
            logger.info("cooldown active for %s, skipping", anomaly_type)
            return None
        if rate_limit_exceeded:
            logger.warning("rate limit exceeded, skipping %s", anomaly_type)
            return None

        initial: DiagnosticState = {
            "anomaly_type": anomaly_type,
            "metric_type": metric_type,
            "entity_id": entity_id,
            "evaluation_window_minutes": window_minutes or self._config.diagnostic.evaluation_window_minutes,
            "cooldown_active": cooldown_active,
            "rate_limit_exceeded": rate_limit_exceeded,
            "threshold_breaches": [],
            "telemetry_snapshot": {},
            "sanitized_telemetry": {},
            "action_plan": None,
            "token_usage": None,
            "proposed_rule_id": None,
            "error": None,
        }

        # The provider bounds its own call, but the graph also touches SQLite in
        # two nodes; an outer deadline keeps one wedged entity from stalling the
        # daemon's whole scan.
        try:
            result = await asyncio.wait_for(self._graph.ainvoke(initial), timeout=_GRAPH_TIMEOUT_SECONDS)
        except TimeoutError:
            logger.error("diagnostic graph timed out for %s", anomaly_type)
            return None
        return result.get("action_plan")

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()

    async def aclose(self) -> None:
        await self.stop()
        # Release the provider's HTTP connection pool.
        if self._provider is not None:
            try:
                await self._provider.aclose()
            except Exception:  # noqa: BLE001 - shutdown must not raise
                logger.debug("error closing AI provider", exc_info=True)

    async def __aenter__(self) -> DiagnosticAgent:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
