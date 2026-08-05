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
    if "\r" in value or "\n" in value:
        raise ValueError("interpolated config values must not contain line breaks")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def interpolate_env(text: str, env: Mapping[str, str] | None = None) -> str:
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
        bound = getattr(self, level)
        op = ">=" if self.mode == "max" else "<="
        return f"{field}={value:.2f} {op} {level}({bound:g})"


class PollingConfig(BaseModel):
    interval_seconds: float = Field(gt=0.0)
    sliding_window_size: int = Field(default=3, ge=1)
    hysteresis_resolve_seconds: float = Field(default=300.0, ge=0.0)


class HostConfig(BaseModel):
    host_id: str = "localhost"


class CaddyConfig(BaseModel):
    instance_id: str = "caddy"
    metrics_url: str = "http://localhost:2019/metrics"


class EndpointTarget(BaseModel):
    endpoint_id: str
    url: str
    timeout_ms: float = Field(default=2000.0, gt=0.0)
    check_ssl: bool = True

    @property
    def timeout_seconds(self) -> float:
        return self.timeout_ms / 1000.0


class DockerConfig(BaseModel):
    socket_path: str = "/var/run/docker.sock"
    events_url: str = "http://localhost/events"
    filtered_actions: set[str] = Field(default_factory=lambda: {"die", "kill", "oom", "restart"})
    crash_loop_window_seconds: float = Field(default=900.0, gt=0.0)
    max_restarts: int = Field(default=3, ge=1)
    backoff_initial_seconds: float = Field(default=1.0, gt=0.0)
    backoff_max_seconds: float = Field(default=60.0, gt=0.0)
    max_attempts: int | None = Field(default=None, ge=1)


class CollectorsConfig(BaseModel):
    host: HostConfig = Field(default_factory=HostConfig)
    caddy: CaddyConfig = Field(default_factory=CaddyConfig)
    endpoints: list[EndpointTarget] = Field(default_factory=list)
    docker: DockerConfig = Field(default_factory=DockerConfig)


class ConfigManager(BaseModel):
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
        raw_text = Path(path).read_text(encoding="utf-8")
        raw = yaml.safe_load(interpolate_env(raw_text, env))
        if not isinstance(raw, dict):
            raise TypeError(f"{path}: expected a mapping at the top level")
        return cls.model_validate(raw)

    def get_threshold(self, metric_type: MetricType, field: str) -> ThresholdBounds | None:
        return self.thresholds.get(metric_type, {}).get(field)
