from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_COMMAND_LENGTH = 500


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TokenUsage(BaseModel):
    """Token usage metadata returned by AI providers."""

    model_config = ConfigDict(slots=True, frozen=True)

    prompt_tokens: int = Field(ge=0)

    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)


class ActionPlan(BaseModel):
    """Structured output from AI diagnostic analysis.

    The requires_human_approval field is always True — the system never
    auto-executes remediation commands. Human review is mandatory.
    """

    model_config = ConfigDict(slots=True, frozen=True, extra="forbid")

    root_cause: str = Field(
        min_length=10,
        max_length=2000,
        description="Concise explanation of the detected anomaly root cause",
    )
    severity: Severity = Field(description="Classified severity level")
    suggested_commands: list[str] = Field(
        min_length=1,
        max_length=20,
        description="List of shell commands to remediate the issue (proposed only, never auto-executed)",
    )
    requires_human_approval: bool = Field(
        default=True,
        frozen=True,
        description="Always True — human review is mandatory before any action",
    )

    @model_validator(mode="before")
    @classmethod
    def _force_human_approval(cls, data: object) -> object:
        if isinstance(data, dict) and data.get("requires_human_approval") is False:
            raise ValueError("requires_human_approval must always be True")
        return data

    @field_validator("suggested_commands")
    @classmethod
    def _bound_commands(cls, value: list[str]) -> list[str]:
        """Bound each command and reject control characters.

        These strings are shown to an operator who may paste them into a root
        shell, and the telemetry that shaped them includes attacker-controllable
        fields such as container names. An embedded newline would let one entry
        render as two commands.
        """
        for cmd in value:
            if len(cmd) > MAX_COMMAND_LENGTH:
                raise ValueError(f"suggested command exceeds {MAX_COMMAND_LENGTH} characters")
            if "\n" in cmd or "\r" in cmd or "\x00" in cmd:
                raise ValueError("suggested command must be a single line with no control characters")
        return value
