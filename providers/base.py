from __future__ import annotations

from abc import ABC, abstractmethod

from providers.models import ActionPlan


class AIProvider(ABC):
    """Abstract base class for AI diagnostic providers.

    To add a new provider (e.g., AnthropicProvider), subclass AIProvider
    and implement analyze_incident(). The LangGraph orchestration layer
    remains unchanged.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider identifier (e.g., 'google', 'anthropic')."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model identifier (e.g., 'gemini-1.5-flash', 'claude-3-haiku')."""

    @abstractmethod
    async def analyze_incident(self, telemetry_data: dict) -> ActionPlan:
        """Analyze telemetry data and return a structured ActionPlan.

        Args:
            telemetry_data: Sanitized JSON-serializable dict containing
                metric snapshots and threshold breach details.

        Returns:
            ActionPlan with root cause, severity, and suggested remediation.
            The caller is responsible for logging token usage and validating
            the response structure.

        Implementations MUST bound the call with an explicit timeout — an
        unbounded provider call stalls the whole diagnostic daemon.
        """

    async def aclose(self) -> None:
        """Release any connection pool the provider holds.

        Default is a no-op so providers without pooled transports need not
        implement it. Called during daemon shutdown.
        """
        return None
