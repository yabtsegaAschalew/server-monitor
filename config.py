from __future__ import annotations

import os
import re
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

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


class DockerTransportMode(StrEnum):
    """Transport mode for Docker daemon communication.

    SECURITY: 'tcp_proxy' routes through a docker-socket-proxy container that
    enforces read-only restrictions (POST=0, EXEC=0), preventing the monitor
    from issuing privileged Docker API calls like exec, container creation,
    or volume deletion.

    SECURITY: 'unix_socket' connects directly to the Docker daemon socket,
    granting full read/write API access. Use only in development or when the
    socket is locked down via OS-level permissions (e.g., docker group membership).
    """

    TCP_PROXY = "tcp_proxy"
    UNIX_SOCKET = "unix_socket"


class DockerConfig(BaseModel):
    """Configuration for the Docker event monitor.

    Supports two transport modes:
    - tcp_proxy (default): Routes through docker-socket-proxy for read-only
      API access. The proxy blocks write/exec endpoints, limiting blast radius
      if the monitor process is compromised.
    - unix_socket: Connects directly to the Docker daemon socket via
      httpx.AsyncHTTPTransport(uds=...). No socat or subprocess wrappers.
      The socket's OS permissions are the only access control boundary.
    """

    model_config = ConfigDict(validate_default=True)

    # --- Transport selection ---
    # SECURITY: tcp_proxy (default) routes through docker-socket-proxy which
    # blocks write/exec Docker API endpoints, limiting blast radius.
    transport_mode: DockerTransportMode = DockerTransportMode.TCP_PROXY

    # TCP proxy mode: base URL of the docker-socket-proxy container.
    # The events endpoint is derived as {base_url}/events.
    # In compose: "http://docker-socket-proxy:2375"
    # Local dev:  "http://localhost:2375"
    base_url: str = "http://localhost:2375"

    # Unix socket mode: filesystem path to the Docker daemon socket.
    # SECURITY: Direct socket access bypasses all proxy-level restrictions.
    # Only set this in development or when OS-level permissions are sufficient.
    socket_path: str | None = None

    # --- Event stream filtering ---
    filtered_actions: set[str] = Field(default_factory=lambda: {"die", "kill", "oom", "restart"})

    # --- Crash loop detection ---
    crash_loop_window_seconds: float = Field(default=900.0, gt=0.0)
    max_restarts: int = Field(default=3, ge=1)

    # --- Reconnection / backoff ---
    backoff_initial_seconds: float = Field(default=1.0, gt=0.0)
    backoff_max_seconds: float = Field(default=30.0, gt=0.0)
    backoff_jitter_ratio: float = Field(default=0.25, ge=0.0, le=1.0)
    max_attempts: int | None = Field(default=None, ge=1)

    # --- Memory budget ---
    event_buffer_maxlen: int = Field(default=100, ge=1)

    @model_validator(mode="after")
    def _validate_transport(self) -> DockerConfig:
        if self.transport_mode == DockerTransportMode.UNIX_SOCKET and not self.socket_path:
            raise ValueError("socket_path is required when transport_mode is 'unix_socket'")
        return self


class DatabaseConfig(BaseModel):
    db_path: str = Field(default="monitoring.db")
    queue_maxsize: int = Field(default=10_000, ge=100)
    batch_size: int = Field(default=256, ge=1, le=10_000)
    prune_interval_seconds: float = Field(default=3600.0, gt=0.0)
    retention_days: int = Field(default=7, ge=1)


# ---------------------------------------------------------------------------
# Network collector configuration
# ---------------------------------------------------------------------------


class IcmpTarget(BaseModel):
    """Single ICMP echo probe target.

    Uses unprivileged SOCK_DGRAM IPPROTO_ICMP sockets — no root required.
    Cannot control TTL or receive TTL in replies (OS limitation of DGRAM mode).
    """

    host: str
    count: int = Field(default=4, ge=1, le=50, description="Probes per poll cycle")
    interval_seconds: float = Field(default=1.0, gt=0.0, description="Delay between probes")
    timeout_seconds: float = Field(default=5.0, gt=0.0, description="Per-probe timeout")
    payload_size: int = Field(default=64, ge=8, le=1024, description="ICMP payload bytes")


class SnmpAuthProtocol(StrEnum):
    NONE = "none"
    MD5 = "md5"
    SHA = "sha"
    SHA256 = "sha256"


class SnmpPrivProtocol(StrEnum):
    NONE = "none"
    DES = "des"
    AES128 = "aes128"
    AES256 = "aes256"


class SnmpTarget(BaseModel):
    """SNMPv3 polling target.

    SECURITY: Auth/priv passwords should be provided via environment variables
    in production (e.g., SNMP_AUTH_PASSWORD), not hardcoded in config files.
    """

    device_id: str
    host: str
    port: int = Field(default=161, gt=0)
    timeout_seconds: float = Field(default=10.0, gt=0.0)

    # SNMPv3 USM authentication
    username: str = ""
    auth_protocol: SnmpAuthProtocol = SnmpAuthProtocol.NONE
    auth_password: str = Field(default="", description="Supports ${ENV_VAR} interpolation")
    priv_protocol: SnmpPrivProtocol = SnmpPrivProtocol.NONE
    priv_password: str = Field(default="", description="Supports ${ENV_VAR} interpolation")

    # What to poll
    poll_interfaces: bool = True
    poll_host_resources: bool = True

    @model_validator(mode="after")
    def _validate_auth(self) -> SnmpTarget:
        if self.auth_protocol != SnmpAuthProtocol.NONE and not self.auth_password:
            raise ValueError("auth_password required when auth_protocol is set")
        if self.priv_protocol != SnmpPrivProtocol.NONE and not self.priv_password:
            raise ValueError("priv_password required when priv_protocol is set")
        return self

    def resolved_auth_password(self, env: Mapping[str, str] | None = None) -> str:
        return interpolate_env(self.auth_password, env) if self.auth_password else ""

    def resolved_priv_password(self, env: Mapping[str, str] | None = None) -> str:
        return interpolate_env(self.priv_password, env) if self.priv_password else ""


class NetworkConfig(BaseModel):
    """Configuration for the network collector daemon.

    Encompasses both ICMP ping probes (unprivileged DGRAM sockets) and
    SNMPv3 polling (IF-MIB, HOST-RESOURCES-MIB).
    """

    icmp_targets: list[IcmpTarget] = Field(default_factory=list)
    snmp_targets: list[SnmpTarget] = Field(default_factory=list)
    icmp_interval_seconds: float = Field(default=5.0, gt=0.0)
    snmp_interval_seconds: float = Field(default=60.0, gt=0.0)


class CollectorsConfig(BaseModel):
    host: HostConfig = Field(default_factory=HostConfig)
    caddy: CaddyConfig = Field(default_factory=CaddyConfig)
    endpoints: list[EndpointTarget] = Field(default_factory=list)
    docker: DockerConfig = Field(default_factory=DockerConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)


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
