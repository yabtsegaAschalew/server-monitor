from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class MetricType(StrEnum):
    HOST = "host"
    CADDY = "caddy"
    DOCKER = "docker"
    ENDPOINT = "endpoint"
    NETWORK = "network"


class State(StrEnum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def severity(self) -> int:
        return {State.OK: 0, State.WARNING: 1, State.CRITICAL: 2}[self]


class HostMetric(BaseModel):
    model_config = ConfigDict(slots=True)

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
    psi_cpu_some_avg10: float | None = Field(default=None)
    psi_memory_some_avg10: float | None = Field(default=None)
    psi_io_some_avg10: float | None = Field(default=None)
    timestamp: datetime = Field(default_factory=utcnow)


class CaddyMetric(BaseModel):
    model_config = ConfigDict(slots=True)

    metric_type: ClassVar[MetricType] = MetricType.CADDY
    ENTITY_ID_FIELD: ClassVar[str] = "instance_id"

    instance_id: str
    requests_per_second: float = Field(ge=0.0)
    error_rate: float = Field(ge=0.0)
    p99_latency_ms: float = Field(ge=0.0)
    active_conns: int = Field(ge=0)
    timestamp: datetime = Field(default_factory=utcnow)


class DockerEvent(BaseModel):
    model_config = ConfigDict(slots=True)

    metric_type: ClassVar[MetricType] = MetricType.DOCKER
    ENTITY_ID_FIELD: ClassVar[str] = "container_id"

    container_id: str
    container_name: str
    status: Literal["created", "start", "stop", "die", "restart", "health_status", "kill", "oom", "pause"]
    health: str | None = None
    image: str | None = None
    exit_code: int | None = None
    failure_reason: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)


class EndpointMetric(BaseModel):
    model_config = ConfigDict(slots=True)

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


class IcmpProbeMetric(BaseModel):
    model_config = ConfigDict(slots=True)

    """ICMP echo probe result for a single target host."""

    metric_type: ClassVar[MetricType] = MetricType.NETWORK
    ENTITY_ID_FIELD: ClassVar[str] = "target_host"

    target_host: str
    target_ip: str
    rtt_ms: float = Field(ge=0.0, description="Last probe round-trip time in milliseconds")
    avg_rtt_ms: float = Field(ge=0.0, description="Rolling average RTT")
    min_rtt_ms: float = Field(ge=0.0, description="Minimum RTT in window")
    max_rtt_ms: float = Field(ge=0.0, description="Maximum RTT in window")
    packet_loss_pct: float = Field(ge=0.0, le=100.0, description="Packet loss percentage")
    probes_sent: int = Field(ge=0)
    probes_received: int = Field(ge=0)
    timestamp: datetime = Field(default_factory=utcnow)


class SnmpInterfaceMetric(BaseModel):
    model_config = ConfigDict(slots=True)

    """Per-interface metrics from IF-MIB via SNMPv3."""

    metric_type: ClassVar[MetricType] = MetricType.NETWORK
    ENTITY_ID_FIELD: ClassVar[str] = "device_id"

    device_id: str
    device_host: str
    if_index: int
    if_name: str
    if_oper_status: int = Field(description="1=up, 2=down, 3=testing")
    if_admin_status: int = Field(description="1=up, 2=down, 3=testing")
    if_speed_bps: int = Field(ge=0, description="Interface speed in bits/sec")
    if_in_octets: int = Field(ge=0, description="Total input octets")
    if_out_octets: int = Field(ge=0, description="Total output octets")
    if_in_errors: int = Field(ge=0, description="Total input errors")
    if_out_errors: int = Field(ge=0, description="Total output errors")
    in_bps: float = Field(ge=0.0, description="Computed input rate in bytes/sec")
    out_bps: float = Field(ge=0.0, description="Computed output rate in bytes/sec")
    timestamp: datetime = Field(default_factory=utcnow)


class SnmpHostMetric(BaseModel):
    model_config = ConfigDict(slots=True)

    """Host-level metrics from HOST-RESOURCES-MIB via SNMPv3."""

    metric_type: ClassVar[MetricType] = MetricType.NETWORK
    ENTITY_ID_FIELD: ClassVar[str] = "device_id"

    device_id: str
    device_host: str
    hr_system_descr: str = ""
    hr_cpu_load: float | None = Field(default=None, description="1-minute CPU load average")
    hr_memory_total: int | None = Field(default=None, ge=0, description="Total memory in bytes")
    hr_memory_used: int | None = Field(default=None, ge=0, description="Used memory in bytes")
    timestamp: datetime = Field(default_factory=utcnow)


class StateTransition(BaseModel):
    model_config = ConfigDict(slots=True)

    metric_type: MetricType
    entity_id: str
    previous_state: State
    new_state: State
    reason: str
    timestamp: datetime = Field(default_factory=utcnow)
