"""Configuration management: polling parameters and per-field thresholds.

``ConfigManager`` loads ``config.yaml`` into validated Pydantic models. Each
metric field maps to a ``ThresholdBounds`` describing the WARNING/CRITICAL
cut-offs and whether the metric breaches on values above ("max") or below
("min") the bound.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from models import MetricType

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}")


def _escape_interpolated(value: str) -> str:
    """Escape a substituted value so it cannot break out of a YAML scalar.

    Line breaks would let an injected value restructure the document, so they
    are rejected outright; backslashes and double quotes are escaped for use
    inside double-quoted YAML scalars (the recommended placeholder style).
    """
    if "\r" in value or "\n" in value:
        raise ValueError("interpolated config values must not contain line breaks")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def interpolate_env(text: str, env: Mapping[str, str] | None = None) -> str:
    """Substitute ``${VAR}`` / ``${VAR:default}`` placeholders from ``env``.

    A variable without a default that is missing from the environment raises
    a ``ValueError`` so deployment mistakes fail fast instead of silently
    producing an empty value.
    """
    if env is None:
        env = os.environ

    def _replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        value = env.get(name)
        if value is None:
            if default is None:
                raise ValueError(f"config references ${name} but it is not set and has no default")
            return default
        return _escape_interpolated(value)

    return _ENV_PATTERN.sub(_replace, text)


class ThresholdBounds(BaseModel):
    """A WARNING/CRITICAL threshold pair for a single numeric metric field."""

    warning: float
    critical: float
    mode: Literal["max", "min"] = "max"

    @model_validator(mode="after")
    def _validate_ordering(self) -> ThresholdBounds:
        if self.mode == "max" and self.critical < self.warning:
            raise ValueError(f"critical ({self.critical}) must be >= warning ({self.warning}) for 'max' mode")
        if self.mode == "min" and self.critical > self.warning:
            raise ValueError(f"critical ({self.critical}) must be <= warning ({self.warning}) for 'min' mode")
        return self

    def is_warning(self, value: float) -> bool:
        if self.mode == "max":
            return value >= self.warning
        return value <= self.warning

    def is_critical(self, value: float) -> bool:
        if self.mode == "max":
            return value >= self.critical
        return value <= self.critical

    def describe(self, field: str, value: float, level: Literal["warning", "critical"]) -> str:
        """Human-readable breach description used in transition reasons."""
        bound = getattr(self, level)
        op = ">=" if self.mode == "max" else "<="
        return f"{field}={value:.2f} {op} {level}({bound:g})"


class PollingConfig(BaseModel):
    """Sampling cadence and state-machine tuning knobs."""

    interval_seconds: float = Field(gt=0.0)
    sliding_window_size: int = Field(default=3, ge=1)
    hysteresis_resolve_seconds: float = Field(default=300.0, ge=0.0)


class HostConfig(BaseModel):
    """Identity for the local host sampled by ``HostCollector``."""

    host_id: str = "localhost"


class CaddyConfig(BaseModel):
    """Where and how to scrape Caddy's Prometheus endpoint."""

    instance_id: str = "caddy"
    metrics_url: str = "http://localhost:2019/metrics"


class EndpointTarget(BaseModel):
    """A single URL probed by ``EndpointPoller``."""

    endpoint_id: str
    url: str
    timeout_ms: float = Field(default=2000.0, gt=0.0)
    check_ssl: bool = True

    @property
    def timeout_seconds(self) -> float:
        return self.timeout_ms / 1000.0


class DockerConfig(BaseModel):
    """Docker socket streaming, crash-loop window and reconnect backoff."""

    socket_path: str = "/var/run/docker.sock"
    events_url: str = "http://localhost/events"  # host is ignored under UnixConnector
    filtered_actions: set[str] = Field(default_factory=lambda: {"die", "kill", "oom", "restart"})
    crash_loop_window_seconds: float = Field(default=900.0, gt=0.0)
    max_restarts: int = Field(default=3, ge=1)
    backoff_initial_seconds: float = Field(default=1.0, gt=0.0)
    backoff_max_seconds: float = Field(default=60.0, gt=0.0)
    max_attempts: int | None = Field(default=None, ge=1)


class CollectorsConfig(BaseModel):
    """Tuning for the Phase 2 metric collection daemons."""

    host: HostConfig = Field(default_factory=HostConfig)
    caddy: CaddyConfig = Field(default_factory=CaddyConfig)
    endpoints: list[EndpointTarget] = Field(default_factory=list)
    docker: DockerConfig = Field(default_factory=DockerConfig)


class ConfigManager(BaseModel):
    """Validated, queryable view of ``config.yaml``."""

    polling: PollingConfig
    thresholds: dict[MetricType, dict[str, ThresholdBounds]]
    collectors: CollectorsConfig = Field(default_factory=CollectorsConfig)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        env: Mapping[str, str] | None = None,
    ) -> ConfigManager:
        """Load and validate a YAML configuration file.

        ``${VAR}`` and ``${VAR:default}`` placeholders in the raw text are
        interpolated from ``env`` (defaults to the process environment) before
        parsing, so deployment can inject values such as service URLs without
        editing the file.
        """
        raw_text = Path(path).read_text(encoding="utf-8")
        raw = yaml.safe_load(interpolate_env(raw_text, env))
        if not isinstance(raw, dict):
            raise TypeError(f"{path}: expected a mapping at the top level")
        return cls.model_validate(raw)

    def get_threshold(self, metric_type: MetricType, field: str) -> ThresholdBounds | None:
        """Return bounds for a field, or ``None`` if not configured."""
        return self.thresholds.get(metric_type, {}).get(field)
