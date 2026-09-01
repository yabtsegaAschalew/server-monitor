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


def interpolate_env(text: str, env: Mapping[str, str] | None = None) -> str:
    """Expand ``${VAR}`` / ``${VAR:default}`` inside a single parsed scalar.

    SECURITY: this runs *after* ``yaml.safe_load``, never on the raw document.
    Substituting into YAML source text meant the result had to be escaped for
    whatever quoting style happened to surround the placeholder — and an
    unquoted placeholder let an environment variable containing ``: ``, ``#``,
    ``&`` or ``*`` inject arbitrary config structure. Interpolating parsed
    scalars removes that coupling entirely: the value is already a string and
    cannot change the shape of the configuration.

    The only remaining guard is on line breaks, which would otherwise let a
    malformed secret smuggle a newline into an HTTP header or SNMP credential.
    """
    if env is None:
        env = os.environ

    def _replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        value = env.get(name)
        if value is None:
            if default is None:
                raise ValueError(f"config references ${name} but it is not set and has no default")
            value = default
        if "\r" in value or "\n" in value:
            raise ValueError(f"interpolated value for {name} must not contain line breaks")
        return value

    return _ENV_PATTERN.sub(_replace, text)


def interpolate_tree(node: object, env: Mapping[str, str] | None = None) -> object:
    """Recursively expand ``${VAR}`` placeholders across a parsed YAML tree."""
    if isinstance(node, dict):
        return {key: interpolate_tree(value, env) for key, value in node.items()}
    if isinstance(node, list):
        return [interpolate_tree(value, env) for value in node]
    if isinstance(node, str):
        return interpolate_env(node, env)
    return node


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
    disk_path: str | None = None


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

    # SECURITY: tcp_proxy (default) routes through docker-socket-proxy which
    # blocks write/exec Docker API endpoints, limiting blast radius.
    transport_mode: DockerTransportMode = DockerTransportMode.TCP_PROXY

    base_url: str = "http://localhost:2375"

    # SECURITY: Direct socket access bypasses all proxy-level restrictions.
    socket_path: str | None = None

    filtered_actions: set[str] = Field(default_factory=lambda: {"die", "kill", "oom", "restart"})

    crash_loop_window_seconds: float = Field(default=900.0, gt=0.0)
    max_restarts: int = Field(default=3, ge=1)

    backoff_initial_seconds: float = Field(default=1.0, gt=0.0)
    backoff_max_seconds: float = Field(default=30.0, gt=0.0)
    backoff_jitter_ratio: float = Field(default=0.25, ge=0.0, le=1.0)

    max_attempts: int | None = Field(default=None, ge=1)

    event_buffer_maxlen: int = Field(default=100, ge=1)

    @model_validator(mode="after")
    def _validate_transport(self) -> DockerConfig:
        if self.transport_mode == DockerTransportMode.UNIX_SOCKET and not self.socket_path:
            raise ValueError("socket_path is required when transport_mode is 'unix_socket'")
        return self


class DatabaseConfig(BaseModel):
    db_path: str = Field(default="monitoring.db")
    queue_maxsize: int = Field(default=1_000, ge=100)
    batch_size: int = Field(default=256, ge=1, le=10_000)
    prune_interval_seconds: float = Field(default=3600.0, gt=0.0)

    retention_days: int = Field(default=7, ge=1)


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

    username: str = ""
    auth_protocol: SnmpAuthProtocol = SnmpAuthProtocol.NONE
    auth_password: str = Field(default="", description="Supports ${ENV_VAR} interpolation")
    priv_protocol: SnmpPrivProtocol = SnmpPrivProtocol.NONE
    priv_password: str = Field(default="", description="Supports ${ENV_VAR} interpolation")

    poll_interfaces: bool = True

    poll_host_resources: bool = True

    @model_validator(mode="after")
    def _validate_auth(self) -> SnmpTarget:
        # an SNMPv3 target configured for sha256/aes256 must never fall back to
        if self.auth_protocol != SnmpAuthProtocol.NONE and not self.auth_password:
            raise ValueError(
                f"snmp target {self.device_id!r} sets auth_protocol={self.auth_protocol.value} "
                "but auth_password is empty — set SNMP_AUTH_PASSWORD in .env, or remove the "
                "target from config.yaml if you are not polling SNMP"
            )
        if self.priv_protocol != SnmpPrivProtocol.NONE and not self.priv_password:
            raise ValueError(
                f"snmp target {self.device_id!r} sets priv_protocol={self.priv_protocol.value} "
                "but priv_password is empty — set SNMP_PRIV_PASSWORD in .env, or remove the "
                "target from config.yaml if you are not polling SNMP"
            )
        return self

    def resolved_auth_password(self, env: Mapping[str, str] | None = None) -> str:
        return self.auth_password

    def resolved_priv_password(self, env: Mapping[str, str] | None = None) -> str:
        return self.priv_password


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


class DiagnosticConfig(BaseModel):
    """Configuration for the Phase 3 central diagnostic agent (AI-driven)."""

    model_config = ConfigDict(validate_default=True)

    enabled: bool = True
    provider: Literal["gemini"] = "gemini"
    gemini_model: str = "gemini-1.5-flash"
    gemini_api_key: str = Field(default="", description="Supports ${GEMINI_API_KEY} interpolation")

    cooldown_minutes: int = Field(default=15, ge=1)
    max_calls_per_hour: int = Field(default=10, ge=1)

    evaluation_window_minutes: int = Field(default=10, ge=1)
    evaluation_interval_seconds: float = Field(default=60.0, ge=10.0)
    enabled_metric_sources: list[Literal["host", "caddy", "docker", "endpoint", "network"]] = Field(
        default_factory=lambda: ["host", "caddy", "docker", "network"]
    )


class SloSource(StrEnum):
    """Metric sources that expose a genuine good/bad event ratio.

    Only these two are offered. An SLI must be a ratio of successful events to


    total events; host CPU percentage and Docker event counts are not, and
    dividing one by an error budget produces a burn rate that means nothing.
    Restricting the enum makes config validation reject the mistake outright
    rather than silently alerting on a meaningless number.
    """

    CADDY = "caddy"
    ICMP = "icmp"


class SloDefinition(BaseModel):
    """One service-level objective evaluated by the alert engine."""

    model_config = ConfigDict(validate_default=True)

    name: str = Field(min_length=1, description="Unique identifier, used in the alert key")
    source: SloSource

    entity_id: str = Field(
        min_length=1,
        description="caddy: the instance_id; icmp: the target host",
    )
    target: float = Field(
        gt=0.0,
        lt=1.0,
        description="Success ratio objective, e.g. 0.999 for 99.9%",
    )
    description: str = ""

    @property
    def error_budget(self) -> float:
        """Fraction of events allowed to fail before the objective is missed."""
        return 1.0 - self.target


class SmtpSecurity(StrEnum):
    NONE = "none"
    STARTTLS = "starttls"
    TLS = "tls"


class SmtpConfig(BaseModel):
    """Fallback email notification channel.

    SECURITY: the password supports ${SMTP_PASSWORD} interpolation and should
    never be written literally into config.yaml.
    """

    model_config = ConfigDict(validate_default=True)

    host: str = ""
    port: int = Field(default=587, gt=0, le=65535)
    username: str = ""
    password: str = Field(default="", description="Supports ${SMTP_PASSWORD} interpolation")
    from_addr: str = ""
    to_addrs: list[str] = Field(default_factory=list)
    security: SmtpSecurity = SmtpSecurity.STARTTLS

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.from_addr and self.to_addrs)


class AlertingConfig(BaseModel):
    """Configuration for the Phase 4 multi-burn-rate alert engine.

    Burn-rate thresholds are expressed as "consume this fraction of the error
    budget within this window" rather than as bare multipliers, so the intent
    stays readable and the multiplier is derived. The defaults are the canonical
    Google SRE pair: 2% in 1h (14.4x) and 5% in 6h (6x).
    """

    model_config = ConfigDict(validate_default=True)

    enabled: bool = True
    evaluation_interval_seconds: float = Field(default=60.0, ge=10.0)

    cooldown_minutes: int = Field(default=15, ge=1, description="Minimum gap between notifications for one alert key")
    resolve_after_seconds: float = Field(
        default=300.0,
        ge=0.0,
        description="A firing alert must stay below threshold this long before it resolves",
    )

    request_timeout_seconds: float = Field(default=10.0, gt=0.0)
    slo_window_days: int = Field(default=30, ge=1, description="Error budget period")

    fast_burn_budget_fraction: float = Field(default=0.02, gt=0.0, lt=1.0)
    fast_burn_long_window_minutes: int = Field(default=60, ge=1)
    fast_burn_short_window_minutes: int = Field(default=5, ge=1)

    slow_burn_budget_fraction: float = Field(default=0.05, gt=0.0, lt=1.0)
    slow_burn_long_window_minutes: int = Field(default=360, ge=1)
    slow_burn_short_window_minutes: int = Field(default=30, ge=1)

    discord_webhook_url: str = ""
    slack_webhook_url: str = ""
    smtp: SmtpConfig = Field(default_factory=SmtpConfig)

    slos: list[SloDefinition] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate(self) -> AlertingConfig:
        if self.fast_burn_short_window_minutes > self.fast_burn_long_window_minutes:
            raise ValueError("fast_burn_short_window_minutes must not exceed the long window")
        if self.slow_burn_short_window_minutes > self.slow_burn_long_window_minutes:
            raise ValueError("slow_burn_short_window_minutes must not exceed the long window")
        names = [slo.name for slo in self.slos]
        duplicates = {name for name in names if names.count(name) > 1}
        if duplicates:
            raise ValueError(f"duplicate SLO names: {', '.join(sorted(duplicates))}")
        return self

    @property
    def has_channel(self) -> bool:
        """True when at least one notification channel is usable."""
        return bool(self.discord_webhook_url or self.slack_webhook_url or self.smtp.is_configured)


class ConfigManager(BaseModel):
    polling: PollingConfig
    thresholds: dict[MetricType, dict[str, ThresholdBounds]]
    collectors: CollectorsConfig = Field(default_factory=CollectorsConfig)
    diagnostic: DiagnosticConfig = Field(default_factory=DiagnosticConfig)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        env: Mapping[str, str] | None = None,
    ) -> ConfigManager:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise TypeError(f"{path}: expected a mapping at the top level")
        return cls.model_validate(interpolate_tree(raw, env))

    def get_threshold(self, metric_type: MetricType, field: str) -> ThresholdBounds | None:
        return self.thresholds.get(metric_type, {}).get(field)
