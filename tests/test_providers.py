from __future__ import annotations

import pytest
from pydantic import ValidationError

from providers import ActionPlan, Severity, TokenUsage


class TestActionPlan:
    def test_valid_plan(self) -> None:
        plan = ActionPlan(
            root_cause="CPU utilization exceeded critical threshold for 10 continuous minutes",
            severity=Severity.HIGH,
            suggested_commands=["systemctl restart nginx", "docker restart web-01"],
        )
        assert plan.severity == Severity.HIGH
        assert plan.requires_human_approval is True
        assert len(plan.suggested_commands) == 2

    def test_requires_human_approval_is_frozen_true(self) -> None:
        plan = ActionPlan(
            root_cause="Memory usage exceeded warning threshold",
            severity=Severity.MEDIUM,
            suggested_commands=["echo test"],
        )
        assert plan.requires_human_approval is True
        with pytest.raises(ValidationError):
            ActionPlan(
                root_cause="Memory usage exceeded warning threshold",
                severity=Severity.MEDIUM,
                suggested_commands=["echo test"],
                requires_human_approval=False,
            )

    def test_plan_is_frozen(self) -> None:
        plan = ActionPlan(
            root_cause="Disk usage approaching capacity limits on primary volume",
            severity=Severity.LOW,
            suggested_commands=["echo test"],
        )
        with pytest.raises(ValidationError):
            plan.root_cause = "mutated"  # type: ignore[misc]

    def test_rejects_short_root_cause(self) -> None:
        with pytest.raises(ValidationError):
            ActionPlan(root_cause="short", severity=Severity.LOW, suggested_commands=["echo"])

    def test_rejects_empty_suggested_commands(self) -> None:
        with pytest.raises(ValidationError):
            ActionPlan(
                root_cause="A sufficiently long root cause description here",
                severity=Severity.LOW,
                suggested_commands=[],
            )

    def test_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            ActionPlan(
                root_cause="A sufficiently long root cause description here",
                severity=Severity.LOW,
                suggested_commands=["echo"],
                unexpected=123,
            )

    def test_rejects_overlong_command(self) -> None:
        """Bounds a payload smuggled through attacker-controllable telemetry."""
        with pytest.raises(ValidationError):
            ActionPlan(
                root_cause="A sufficiently long root cause description here",
                severity=Severity.LOW,
                suggested_commands=["echo " + "A" * 600],
            )

    @pytest.mark.parametrize("bad", ["echo one\necho two", "echo one\rrm -rf /", "echo\x00rm"])
    def test_rejects_multiline_or_control_chars_in_command(self, bad: str) -> None:
        """One entry must render as exactly one command.

        These strings are shown to an operator who may paste them into a root
        shell; an embedded newline would smuggle in a second command.
        """
        with pytest.raises(ValidationError):
            ActionPlan(
                root_cause="A sufficiently long root cause description here",
                severity=Severity.LOW,
                suggested_commands=[bad],
            )


class TestSeverity:
    def test_members(self) -> None:
        assert list(Severity) == [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class TestTokenUsage:
    def test_usage(self) -> None:
        usage = TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150)
        assert usage.total_tokens == 150

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValidationError):
            TokenUsage(prompt_tokens=-1, completion_tokens=0, total_tokens=-1)
