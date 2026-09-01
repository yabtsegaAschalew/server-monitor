"""Phase 4 — multi-burn-rate SLO alert engine and notification dispatch.

Error-budget alerting, in the Google SRE multi-window multi-burn-rate shape:

    burn_rate = observed_failure_ratio / error_budget

A burn rate of 1.0 exhausts the budget exactly at the end of the SLO period. A
burn rate of 14.4 exhausts 2% of a 30-day budget in one hour. Rather than
hardcoding 14.4 and 6.0, the thresholds are derived from the intent — "consume
this fraction of budget within this window" — so the numbers stay auditable.

Every burn class evaluates TWO windows: a long one that establishes the trend
and a short canary that confirms the problem is still happening right now. Both
must exceed the threshold to fire. Without the canary, a brief spike keeps an
alert firing for the whole length of the long window after it has recovered.

SECURITY / EXECUTION BOUNDARY: this module dispatches notifications. It never
reads or acts on `proposed_remediation_rules`, never executes a command, and
never imports a process-spawning module. The webhook POSTs here are the only
non-GET requests in the codebase, and they carry alert metadata only.

Memory: every plain class here declares `__slots__`, in-memory state is bounded
by the number of configured SLOs, and SLI aggregation happens in SQL so a
six-hour window costs O(1) memory regardless of scrape interval.
"""

from __future__ import annotations

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from config import AlertingConfig, SloDefinition, SloSource, SmtpConfig, SmtpSecurity
from database import DatabaseEngine
from providers.models import Severity

logger = logging.getLogger(__name__)

BurnClass = Literal["fast", "slow"]
AlertStatus = Literal["firing", "resolved"]


def burn_rate_threshold(
    budget_fraction: float,
    window_hours: float,
    slo_window_days: int = 30,
) -> float:
    """Burn rate that consumes `budget_fraction` of the budget in `window_hours`.

    A burn rate of 1.0 spends the entire budget evenly across the SLO period, so
    consuming a fraction f in window w (hours) out of a period of D days means:

        threshold = f * (D * 24) / w

    The canonical pair falls out of this directly:
        (0.02, 1h, 30d) -> 14.4    (2% of budget in an hour: page)
        (0.05, 6h, 30d) ->  6.0    (5% of budget in six hours: ticket)
    """
    if window_hours <= 0.0:
        raise ValueError("window_hours must be positive")
    return budget_fraction * (slo_window_days * 24.0) / window_hours


def burn_rate(failure_ratio: float, error_budget: float) -> float:
    """How fast the error budget is being consumed, as a multiple of nominal."""
    if error_budget <= 0.0:
        raise ValueError("error_budget must be positive; check the SLO target")
    return failure_ratio / error_budget


def budget_consumed_pct(rate: float, window_hours: float, slo_window_days: int = 30) -> float:
    """Percentage of the error budget spent over `window_hours` at this burn rate.


    Inverse of `burn_rate_threshold`: at 14.4x over one hour of a 30-day budget
    this returns 2.0, which is the statement the threshold was defined by.
    """
    return rate * window_hours / (slo_window_days * 24.0) * 100.0


@dataclass(frozen=True, slots=True)
class BurnWindow:
    """One burn class: a threshold plus the two windows that must both breach."""

    burn_class: BurnClass
    threshold: float
    long_window_minutes: int
    short_window_minutes: int

    budget_fraction: float

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL if self.burn_class == "fast" else Severity.HIGH


def build_burn_windows(config: AlertingConfig) -> tuple[BurnWindow, ...]:
    """Derive both burn classes from configuration."""
    return (
        BurnWindow(
            burn_class="fast",
            threshold=burn_rate_threshold(
                config.fast_burn_budget_fraction,
                config.fast_burn_long_window_minutes / 60.0,
                config.slo_window_days,
            ),
            long_window_minutes=config.fast_burn_long_window_minutes,
            short_window_minutes=config.fast_burn_short_window_minutes,
            budget_fraction=config.fast_burn_budget_fraction,
        ),
        BurnWindow(
            burn_class="slow",
            threshold=burn_rate_threshold(
                config.slow_burn_budget_fraction,
                config.slow_burn_long_window_minutes / 60.0,
                config.slo_window_days,
            ),
            long_window_minutes=config.slow_burn_long_window_minutes,
            short_window_minutes=config.slow_burn_short_window_minutes,
            budget_fraction=config.slow_burn_budget_fraction,
        ),
    )


class AlertPayload(BaseModel):
    """Standardized alert format shared by every dispatcher."""

    model_config = ConfigDict(slots=True, frozen=True)

    alert_key: str
    slo_name: str
    entity_id: str
    severity: Severity
    burn_class: BurnClass
    status: AlertStatus

    burn_rate: float = Field(ge=0.0)
    threshold: float = Field(gt=0.0)
    observed_failure_ratio: float = Field(ge=0.0)
    slo_target: float = Field(gt=0.0, lt=1.0)
    budget_consumed_pct: float = Field(ge=0.0)

    long_window_minutes: int = Field(gt=0)
    short_window_minutes: int = Field(gt=0)
    triggered_at: datetime

    @property
    def title(self) -> str:
        verb = "RESOLVED" if self.status == "resolved" else self.severity.value.upper()
        return f"[{verb}] {self.burn_class} burn on {self.slo_name}"

    @property
    def summary(self) -> str:
        if self.status == "resolved":
            return (
                f"{self.slo_name} ({self.entity_id}) recovered: "
                f"{self.burn_class} burn is back under {self.threshold:.1f}x."
            )
        return (
            f"{self.slo_name} ({self.entity_id}) is burning error budget at "
            f"{self.burn_rate:.1f}x, over the {self.burn_class} threshold of "
            f"{self.threshold:.1f}x. Observed failure ratio "
            f"{self.observed_failure_ratio:.4%} against a {self.slo_target:.3%} "
            f"objective over {self.long_window_minutes}m "
            f"(confirmed on a {self.short_window_minutes}m window). "
            f"At this rate {self.budget_consumed_pct:.1f}% of the budget is spent "
            f"per {self.long_window_minutes}m."
        )


@dataclass(frozen=True, slots=True)
class SliSample:
    """A failure ratio plus the event volume it was computed from."""

    failure_ratio: float
    volume: float

    @property
    def has_traffic(self) -> bool:
        return self.volume > 0.0


class SloEvaluator:
    """Computes failure ratios for configured SLOs out of SQLite."""

    __slots__ = ("_db",)

    def __init__(self, db: DatabaseEngine) -> None:
        self._db = db

    async def failure_ratio(self, slo: SloDefinition, *, minutes: int) -> SliSample:
        if slo.source == SloSource.CADDY:
            weighted, volume = await self._db.caddy_sli_window(slo.entity_id, minutes=minutes)
            if volume <= 0.0:
                return SliSample(failure_ratio=0.0, volume=0.0)
            return SliSample(failure_ratio=max(0.0, min(1.0, weighted / volume)), volume=volume)

        if slo.source == SloSource.ICMP:
            sent, received = await self._db.icmp_sli_window(slo.entity_id, minutes=minutes)
            if sent <= 0:
                return SliSample(failure_ratio=0.0, volume=0.0)
            return SliSample(
                failure_ratio=max(0.0, min(1.0, 1.0 - (received / sent))),
                volume=float(sent),
            )

        raise ValueError(f"unsupported SLO source: {slo.source!r}")


class AlertDispatcher(ABC):
    """A notification channel.

    `send` returns True on success and False on a handled failure; it must not
    raise for an ordinary delivery problem, because one broken channel must not
    stop the others or kill the evaluation loop.
    """

    __slots__ = ()

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def send(self, payload: AlertPayload) -> bool: ...

    async def aclose(self) -> None:
        return None


_SEVERITY_COLORS = {
    Severity.LOW: 0x3BA55D,
    Severity.MEDIUM: 0xE9A23B,
    Severity.HIGH: 0xE0603D,
    Severity.CRITICAL: 0xD83C3E,
}
_RESOLVED_COLOR = 0x3BA55D


class _WebhookDispatcher(AlertDispatcher):
    """Shared POST plumbing for the JSON webhook channels."""

    __slots__ = ("_client", "_timeout", "_url")

    def __init__(self, url: str, client: httpx.AsyncClient, timeout: float) -> None:
        self._url = url
        self._client = client
        self._timeout = timeout

    @abstractmethod
    def _body(self, payload: AlertPayload) -> dict: ...

    async def send(self, payload: AlertPayload) -> bool:
        try:
            response = await asyncio.wait_for(
                self._client.post(self._url, json=self._body(payload)),
                timeout=self._timeout,
            )
        except TimeoutError:
            logger.error("%s dispatch timed out after %.0fs", self.name, self._timeout)
            return False
        except httpx.HTTPError as exc:
            logger.error("%s dispatch failed: %s", self.name, exc)
            return False
        if response.status_code >= 400:
            logger.error("%s dispatch rejected with status %d", self.name, response.status_code)
            return False
        return True


class DiscordDispatcher(_WebhookDispatcher):
    __slots__ = ()

    @property
    def name(self) -> str:
        return "discord"

    def _body(self, payload: AlertPayload) -> dict:
        color = _RESOLVED_COLOR if payload.status == "resolved" else _SEVERITY_COLORS[payload.severity]
        return {
            "username": "server-monitor",
            "embeds": [
                {
                    "title": payload.title[:256],
                    "description": payload.summary[:4096],
                    "color": color,
                    "timestamp": payload.triggered_at.isoformat(),
                    "fields": [
                        {"name": "SLO", "value": payload.slo_name, "inline": True},
                        {"name": "Entity", "value": payload.entity_id, "inline": True},
                        {
                            "name": "Burn rate",
                            "value": f"{payload.burn_rate:.2f}x (threshold {payload.threshold:.2f}x)",
                            "inline": True,
                        },
                    ],
                }
            ],
        }


class SlackDispatcher(_WebhookDispatcher):
    __slots__ = ()

    @property
    def name(self) -> str:
        return "slack"

    def _body(self, payload: AlertPayload) -> dict:
        return {
            "text": payload.title,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": payload.title[:150]},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": payload.summary[:3000]},
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"*SLO* {payload.slo_name} | *entity* {payload.entity_id} | "
                                f"*burn* {payload.burn_rate:.2f}x / {payload.threshold:.2f}x"
                            ),
                        }
                    ],
                },
            ],
        }


_EMAIL_TEMPLATE = """\
<html><body style="font-family:system-ui,sans-serif">
  <h2 style="margin-bottom:4px">{{ title }}</h2>
  <p style="color:#555;margin-top:0">{{ summary }}</p>
  <table cellpadding="6" style="border-collapse:collapse;font-size:14px">
    <tr><td><b>SLO</b></td><td>{{ slo_name }}</td></tr>
    <tr><td><b>Entity</b></td><td>{{ entity_id }}</td></tr>
    <tr><td><b>Severity</b></td><td>{{ severity }}</td></tr>
    <tr><td><b>Burn rate</b></td><td>{{ burn_rate }}x (threshold {{ threshold }}x)</td></tr>
    <tr><td><b>Failure ratio</b></td><td>{{ failure_ratio }}</td></tr>
    <tr><td><b>Objective</b></td><td>{{ slo_target }}</td></tr>
    <tr><td><b>Windows</b></td><td>{{ long_window }}m long / {{ short_window }}m canary</td></tr>
    <tr><td><b>Triggered</b></td><td>{{ triggered_at }}</td></tr>
  </table>
</body></html>
"""


class SmtpDispatcher(AlertDispatcher):
    """Fallback email channel.

    Imports of aiosmtplib and jinja2 are deferred to first use so a deployment
    that never configures SMTP does not pay their import cost.
    """

    __slots__ = ("_config", "_template", "_timeout")

    def __init__(self, config: SmtpConfig, timeout: float) -> None:
        self._config = config
        self._timeout = timeout
        self._template = None

    @property
    def name(self) -> str:
        return "smtp"

    def _render(self, payload: AlertPayload) -> str:
        if self._template is None:
            from jinja2 import Template

            self._template = Template(_EMAIL_TEMPLATE, autoescape=True)
        return self._template.render(
            title=payload.title,
            summary=payload.summary,
            slo_name=payload.slo_name,
            entity_id=payload.entity_id,
            severity=payload.severity.value,
            burn_rate=f"{payload.burn_rate:.2f}",
            threshold=f"{payload.threshold:.2f}",
            failure_ratio=f"{payload.observed_failure_ratio:.4%}",
            slo_target=f"{payload.slo_target:.3%}",
            long_window=payload.long_window_minutes,
            short_window=payload.short_window_minutes,
            triggered_at=payload.triggered_at.isoformat(),
        )

    async def send(self, payload: AlertPayload) -> bool:
        from email.message import EmailMessage

        import aiosmtplib

        cfg = self._config
        message = EmailMessage()
        message["From"] = cfg.from_addr
        message["To"] = ", ".join(cfg.to_addrs)
        message["Subject"] = payload.title
        message.set_content(payload.summary)

        message.add_alternative(self._render(payload), subtype="html")

        try:
            await asyncio.wait_for(
                aiosmtplib.send(
                    message,
                    hostname=cfg.host,
                    port=cfg.port,
                    username=cfg.username or None,
                    password=cfg.password or None,
                    use_tls=cfg.security == SmtpSecurity.TLS,
                    start_tls=cfg.security == SmtpSecurity.STARTTLS,
                ),
                timeout=self._timeout,
            )
        except TimeoutError:
            logger.error("smtp dispatch timed out after %.0fs", self._timeout)
            return False
        except Exception as exc:  # noqa: BLE001 - one bad channel must not stop the loop
            logger.error("smtp dispatch failed: %s", exc)
            return False
        return True


def build_dispatchers(
    config: AlertingConfig,
    *,
    client: httpx.AsyncClient | None = None,
) -> tuple[list[AlertDispatcher], httpx.AsyncClient | None]:
    """Construct the configured channels.

    Returns the dispatchers plus the HTTP client that owns their connection pool
    (None when no webhook channel is configured), so the caller can close it in


    the right order during shutdown.


    """
    dispatchers: list[AlertDispatcher] = []
    owned_client: httpx.AsyncClient | None = None

    needs_http = bool(config.discord_webhook_url or config.slack_webhook_url)
    http = client
    if needs_http and http is None:
        timeout = httpx.Timeout(config.request_timeout_seconds)
        http = httpx.AsyncClient(timeout=timeout)
        owned_client = http

    if config.discord_webhook_url and http is not None:
        dispatchers.append(DiscordDispatcher(config.discord_webhook_url, http, config.request_timeout_seconds))
    if config.slack_webhook_url and http is not None:
        dispatchers.append(SlackDispatcher(config.slack_webhook_url, http, config.request_timeout_seconds))
    if config.smtp.is_configured:
        dispatchers.append(SmtpDispatcher(config.smtp, config.request_timeout_seconds))

    return dispatchers, owned_client


@dataclass(slots=True)
class _PendingResolve:
    """Tracks how long a firing alert has been back under its threshold."""

    since: datetime


class AlertEngine:
    """Evaluates SLO burn rates on a tick and dispatches state changes.

    Suppression and flapping protection are both deliberate:

    * Suppression stops a still-firing alert from re-notifying more often than
      `cooldown_minutes`. The alert stays open in `active_alerts` throughout.
    * Flapping protection stops a metric hovering at the threshold from emitting
      a fire/resolve pair every tick: an alert must stay under threshold for
      `resolve_after_seconds` before it actually resolves.
    """

    __slots__ = (
        "_config",
        "_db",
        "_dispatchers",
        "_evaluator",
        "_missing_channel_logged",
        "_owned_client",
        "_pending_resolve",
        "_stop_event",
        "_windows",
    )

    def __init__(
        self,
        config: AlertingConfig,
        db: DatabaseEngine,
        *,
        dispatchers: list[AlertDispatcher] | None = None,
    ) -> None:
        self._config = config
        self._db = db
        self._evaluator = SloEvaluator(db)
        self._windows = build_burn_windows(config)
        self._stop_event: asyncio.Event | None = None
        self._pending_resolve: dict[str, _PendingResolve] = {}
        self._missing_channel_logged = False

        if dispatchers is not None:
            self._dispatchers = dispatchers
            self._owned_client: httpx.AsyncClient | None = None
        else:
            self._dispatchers, self._owned_client = build_dispatchers(config)

    @classmethod
    def from_config(cls, config, db: DatabaseEngine, **kwargs) -> AlertEngine:
        """Build from a full ConfigManager."""
        return cls(config.alerting, db, **kwargs)

    @property
    def dispatchers(self) -> list[AlertDispatcher]:
        return self._dispatchers

    @staticmethod
    def alert_key(slo_name: str, burn_class: str) -> str:
        return f"{slo_name}:{burn_class}"

    async def evaluate_slo(self, slo: SloDefinition, window: BurnWindow) -> AlertPayload | None:
        """Return a firing payload when both windows breach, else None.

        Requiring the short window as well as the long one is what makes this
        multi-window: the long window alone would keep firing for its full
        duration after the incident ended.
        """
        long_sample = await self._evaluator.failure_ratio(slo, minutes=window.long_window_minutes)
        if not long_sample.has_traffic:
            return None

        long_burn = burn_rate(long_sample.failure_ratio, slo.error_budget)
        if long_burn < window.threshold:
            return None

        short_sample = await self._evaluator.failure_ratio(slo, minutes=window.short_window_minutes)
        if not short_sample.has_traffic:
            return None
        short_burn = burn_rate(short_sample.failure_ratio, slo.error_budget)
        if short_burn < window.threshold:
            return None

        return AlertPayload(
            alert_key=self.alert_key(slo.name, window.burn_class),
            slo_name=slo.name,
            entity_id=slo.entity_id,
            severity=window.severity,
            burn_class=window.burn_class,
            status="firing",
            burn_rate=long_burn,
            threshold=window.threshold,
            observed_failure_ratio=long_sample.failure_ratio,
            slo_target=slo.target,
            budget_consumed_pct=budget_consumed_pct(
                long_burn,
                window.long_window_minutes / 60.0,
                self._config.slo_window_days,
            ),
            long_window_minutes=window.long_window_minutes,
            short_window_minutes=window.short_window_minutes,
            triggered_at=datetime.now(UTC),
        )

    async def dispatch(self, payload: AlertPayload) -> bool:
        """Send to every configured channel. True if any succeeded."""
        if not self._dispatchers:
            if not self._missing_channel_logged:
                logger.error(
                    "alerting is enabled but no notification channel is configured; "
                    "alerts are being recorded in active_alerts but not sent. Set "
                    "alerting.discord_webhook_url, alerting.slack_webhook_url, or alerting.smtp."
                )
                self._missing_channel_logged = True
            logger.warning("ALERT %s", format_alert_line(payload))
            return False

        results = await asyncio.gather(
            *(d.send(payload) for d in self._dispatchers),
            return_exceptions=True,
        )
        delivered = False
        for dispatcher, result in zip(self._dispatchers, results, strict=True):
            if isinstance(result, BaseException):
                logger.error("%s dispatcher raised: %r", dispatcher.name, result)
            elif result:
                delivered = True
        return delivered

    async def _handle_firing(self, payload: AlertPayload) -> None:
        key = payload.alert_key
        self._pending_resolve.pop(key, None)

        existing = await self._db.get_active_alert(key)
        if existing is None:
            await self._db.insert_active_alert(
                alert_key=key,
                slo_name=payload.slo_name,
                entity_id=payload.entity_id,
                severity=payload.severity.value,
                burn_class=payload.burn_class,
                burn_rate=payload.burn_rate,
                triggered_at=payload.triggered_at,
            )
            if await self.dispatch(payload):
                await self._db.mark_alert_notified(key, payload.triggered_at)
            return

        await self._db.update_alert_burn_rate(key, payload.burn_rate)
        if self._should_renotify(existing, payload.triggered_at):
            if await self.dispatch(payload):
                await self._db.mark_alert_notified(key, payload.triggered_at)

    def _should_renotify(self, existing: dict, now: datetime) -> bool:
        last = existing.get("last_notified_at")
        if not last:
            return True
        try:
            last_dt = datetime.fromisoformat(last)
        except (TypeError, ValueError):
            return True
        return (now - last_dt) >= timedelta(minutes=self._config.cooldown_minutes)

    async def _handle_not_firing(self, slo: SloDefinition, window: BurnWindow, now: datetime) -> None:
        key = self.alert_key(slo.name, window.burn_class)
        existing = await self._db.get_active_alert(key)
        if existing is None:
            self._pending_resolve.pop(key, None)
            return

        pending = self._pending_resolve.get(key)
        if pending is None:
            self._pending_resolve[key] = _PendingResolve(since=now)
            return
        if (now - pending.since).total_seconds() < self._config.resolve_after_seconds:
            return

        if await self._db.resolve_active_alert(key, now):
            resolved = AlertPayload(
                alert_key=key,
                slo_name=slo.name,
                entity_id=slo.entity_id,
                severity=window.severity,
                burn_class=window.burn_class,
                status="resolved",
                burn_rate=float(existing.get("burn_rate") or 0.0),
                threshold=window.threshold,
                observed_failure_ratio=0.0,
                slo_target=slo.target,
                budget_consumed_pct=0.0,
                long_window_minutes=window.long_window_minutes,
                short_window_minutes=window.short_window_minutes,
                triggered_at=now,
            )
            await self.dispatch(resolved)
        self._pending_resolve.pop(key, None)

    async def evaluate_once(self) -> list[AlertPayload]:
        """One full evaluation pass. Returns the payloads that fired."""
        fired: list[AlertPayload] = []
        now = datetime.now(UTC)
        for slo in self._config.slos:
            for window in self._windows:
                try:
                    payload = await self.evaluate_slo(slo, window)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("failed to evaluate SLO %s (%s burn)", slo.name, window.burn_class)
                    continue

                try:
                    if payload is not None:
                        fired.append(payload)
                        await self._handle_firing(payload)
                    else:
                        await self._handle_not_firing(slo, window, now)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("failed to record alert state for %s", slo.name)
        return fired

    async def run_forever(self) -> None:
        self._stop_event = asyncio.Event()
        if not self._config.slos:
            logger.warning("alert engine: no SLOs configured under alerting.slos; idling")
        else:
            logger.info(
                "alert engine started: %d SLO(s), fast>=%.1fx, slow>=%.1fx, channels=%s",
                len(self._config.slos),
                self._windows[0].threshold,
                self._windows[1].threshold,
                ",".join(d.name for d in self._dispatchers) or "none",
            )
        while not self._stop_event.is_set():
            try:
                await self.evaluate_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("alert evaluation cycle failed")

            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._config.evaluation_interval_seconds,
                )
            except TimeoutError:
                pass

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()

    async def aclose(self) -> None:
        await self.stop()
        for dispatcher in self._dispatchers:
            try:
                await dispatcher.aclose()
            except Exception:  # noqa: BLE001 - shutdown must not raise
                logger.debug("error closing %s dispatcher", dispatcher.name, exc_info=True)
        if self._owned_client is not None:
            await self._owned_client.aclose()
            self._owned_client = None

    async def __aenter__(self) -> AlertEngine:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


def format_alert_line(payload: AlertPayload) -> str:
    """Compact single-line rendering, used by the CLI and by dry-run logging."""
    return json.dumps(
        {
            "alert_key": payload.alert_key,
            "status": payload.status,
            "severity": payload.severity.value,
            "burn_rate": round(payload.burn_rate, 3),
            "threshold": round(payload.threshold, 3),
            "entity_id": payload.entity_id,
        },
        separators=(",", ":"),
    )
