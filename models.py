"""Pydantic v2 schemas for metric payloads and shared state primitives.

All metric models are intentionally frozen-free (default Pydantic behaviour)
but validated: numeric fields are constrained to non-negative values so a
malformed collector payload fails fast at the ingestion boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Literal

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    """Timezone-aware ``datetime.now`` used as the default timestamp."""
    return datetime.now(UTC)


class MetricType(StrEnum):
    """Discriminates which collector produced a payload."""

    HOST = "host"
    CADDY = "caddy"
    DOCKER = "docker"
    ENDPOINT = "endpoint"


class State(StrEnum):
    """The three evaluated health levels for an entity."""

    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def severity(self) -> int:
        """Numerical rank used to pick the worst field verdict in a sample."""
        return {State.OK: 0, State.WARNING: 1, State.CRITICAL: 2}[self]


class HostMetric(BaseModel):
    """System-level metrics for a single host."""

    metric_type: ClassVar[MetricType] = MetricType.HOST
    ENTITY_ID_FIELD: ClassVar[str] = "host_id"

    host_id: str
    cpu_percent: float = Field(ge=0.0)
    memory_percent: float = Field(ge=0.0)
    disk_percent: float = Field(ge=0.0)
    load_avg: float = Field(ge=0.0)
    # I/O throughput (bytes/second) computed from psutil counter deltas.
    disk_read_bps: float = Field(default=0.0, ge=0.0)
    disk_write_bps: float = Field(default=0.0, ge=0.0)
    net_bytes_sent_per_sec: float = Field(default=0.0, ge=0.0)
    net_bytes_recv_per_sec: float = Field(default=0.0, ge=0.0)
    timestamp: datetime = Field(default_factory=utcnow)


class CaddyMetric(BaseModel):
    """Traffic / latency metrics for a Caddy reverse-proxy instance."""

    metric_type: ClassVar[MetricType] = MetricType.CADDY
    ENTITY_ID_FIELD: ClassVar[str] = "instance_id"

    instance_id: str
    requests_per_second: float = Field(ge=0.0)
    error_rate: float = Field(ge=0.0)
    p99_latency_ms: float = Field(ge=0.0)
    active_conns: int = Field(ge=0)
    timestamp: datetime = Field(default_factory=utcnow)


class DockerEvent(BaseModel):
    """Discrete lifecycle/health event emitted by a Docker container.

    ``status`` covers the events the Docker monitor intercepts (``die``,
    ``kill``, ``oom``, ``restart``) plus the full lifecycle values that arrive
    on the socket but are not persisted by the monitor.
    """

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
    """Single HTTP probe result for an external endpoint."""

    metric_type: ClassVar[MetricType] = MetricType.ENDPOINT
    ENTITY_ID_FIELD: ClassVar[str] = "endpoint_id"

    endpoint_id: str
    url: str
    status_code: int
    response_time_ms: float = Field(ge=0.0)
    is_up: bool
    # Days until the TLS certificate expires (``None`` when not checkable).
    ssl_expiry_days: float | None = None
    # True when the probe hit the per-target timeout rather than a real reply.
    timeout_detected: bool = False
    timestamp: datetime = Field(default_factory=utcnow)


class StateTransition(BaseModel):
    """Record of an evaluated state change, persisted by the repository."""

    metric_type: MetricType
    entity_id: str
    previous_state: State
    new_state: State
    reason: str
    timestamp: datetime = Field(default_factory=utcnow)
