from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Literal

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class MetricType(StrEnum):
    HOST = "host"
    CADDY = "caddy"
    DOCKER = "docker"
    ENDPOINT = "endpoint"


class State(StrEnum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def severity(self) -> int:
        return {State.OK: 0, State.WARNING: 1, State.CRITICAL: 2}[self]


class HostMetric(BaseModel):
    metric_type: ClassVar[MetricType] = MetricType.HOST
    ENTITY_ID_FIELD: ClassVar[str] = "host_id"

    host_id: str
    cpu_percent: float = Field(ge=0.0)
    memory_percent: float = Field(ge=0.0)
    disk_percent: float = Field(ge=0.0)
    load_avg: float = Field(ge=0.0)
    disk_read_bps: float = Field(default=0.0, ge=0.0)
    disk_write_bps: float = Field(default=0.0, ge=0.0)
    net_bytes_sent_per_sec: float = Field(default=0.0, ge=0.0)
    net_bytes_recv_per_sec: float = Field(default=0.0, ge=0.0)
    timestamp: datetime = Field(default_factory=utcnow)


class CaddyMetric(BaseModel):
    metric_type: ClassVar[MetricType] = MetricType.CADDY
    ENTITY_ID_FIELD: ClassVar[str] = "instance_id"

    instance_id: str
    requests_per_second: float = Field(ge=0.0)
    error_rate: float = Field(ge=0.0)
    p99_latency_ms: float = Field(ge=0.0)
    active_conns: int = Field(ge=0)
    timestamp: datetime = Field(default_factory=utcnow)


class DockerEvent(BaseModel):
    metric_type: ClassVar[MetricType] = MetricType.DOCKER
    ENTITY_ID_FIELD: ClassVar[str] = "container_id"

    container_id: str
    container_name: str
    status: Literal["created", "start", "stop", "die", "restart", "health_status", "kill", "oom"]
    health: str | None = None
    image: str | None = None
    exit_code: int | None = None
    failure_reason: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)


class EndpointMetric(BaseModel):
    metric_type: ClassVar[MetricType] = MetricType.ENDPOINT
    ENTITY_ID_FIELD: ClassVar[str] = "endpoint_id"

    endpoint_id: str
    url: str
    status_code: int
    response_time_ms: float = Field(ge=0.0)
    is_up: bool
    ssl_expiry_days: float | None = None
    timeout_detected: bool = False
    timestamp: datetime = Field(default_factory=utcnow)


class StateTransition(BaseModel):
    metric_type: MetricType
    entity_id: str
    previous_state: State
    new_state: State
    reason: str
    timestamp: datetime = Field(default_factory=utcnow)
