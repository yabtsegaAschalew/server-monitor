"""Tests for the Phase 4 multi-burn-rate alert engine.

NOT RUN in the session that wrote them — authored for a later offline run.

Coverage is deliberately weighted toward the parts that are easy to get subtly
wrong and impossible to notice in production: the burn-rate arithmetic, the
"no traffic is not a failure" case, and the suppression / flapping state
machine, which only misbehaves over time.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from alert_engine import (
    AlertEngine,
    AlertPayload,
    DiscordDispatcher,
    SlackDispatcher,
    SloEvaluator,
    budget_consumed_pct,
    build_burn_windows,
    burn_rate,
    burn_rate_threshold,
)
from config import AlertingConfig, DatabaseConfig, SloDefinition, SloSource
from database import DatabaseEngine, _connect
from providers.models import Severity

DISCORD_URL = "https://discord.example/api/webhooks/test"
SLACK_URL = "https://hooks.slack.example/services/test"


def _db_config(tmp_path: Path) -> DatabaseConfig:
    return DatabaseConfig(
        db_path=str(tmp_path / "alerts.db"),
        queue_maxsize=256,
        batch_size=16,
        prune_interval_seconds=3600.0,
        retention_days=7,
    )


def _slo(name: str = "caddy-availability", source: SloSource = SloSource.CADDY, **kw) -> SloDefinition:
    return SloDefinition(
        name=name,
        source=source,
        entity_id=kw.pop("entity_id", "edge-01"),
        target=kw.pop("target", 0.999),
    )


def _alerting_config(**kw) -> AlertingConfig:

    kw.setdefault("slos", [_slo()])
    return AlertingConfig(**kw)


async def _seed_caddy(db_path: str, rows: list[tuple[float, float, datetime]]) -> None:
    """Insert (requests_per_sec, error_rate, timestamp) samples."""
    async with _connect(db_path) as conn:
        await conn.executemany(
            "INSERT INTO caddy_metrics"
            "(instance_id,requests_per_sec,error_rate,p99_latency_ms,active_conns,created_at)"
            " VALUES ('edge-01',?,?,1.0,1,?)",
            [(rps, err, ts.isoformat()) for rps, err, ts in rows],
        )
        await conn.commit()


async def _seed_icmp(db_path: str, rows: list[tuple[int, int, datetime]]) -> None:
    """Insert (probes_sent, probes_received, timestamp) samples."""
    async with _connect(db_path) as conn:
        await conn.executemany(
            "INSERT INTO icmp_probes"
            "(target_host,target_ip,rtt_ms,avg_rtt_ms,min_rtt_ms,max_rtt_ms,"
            "packet_loss_pct,probes_sent,probes_received,created_at)"
            " VALUES ('8.8.8.8','8.8.8.8',1.0,1.0,1.0,1.0,0.0,?,?,?)",
            [(sent, recv, ts.isoformat()) for sent, recv, ts in rows],
        )
        await conn.commit()


class TestBurnRateMath:
    def test_canonical_fast_threshold(self) -> None:
        """2% of a 30-day budget in one hour is the well-known 14.4x."""
        assert burn_rate_threshold(0.02, 1.0, 30) == pytest.approx(14.4)

    def test_canonical_slow_threshold(self) -> None:
        """5% of a 30-day budget in six hours is 6x."""
        assert burn_rate_threshold(0.05, 6.0, 30) == pytest.approx(6.0)

    def test_threshold_scales_inversely_with_window(self) -> None:
        assert burn_rate_threshold(0.02, 2.0, 30) == pytest.approx(7.2)

    def test_rejects_non_positive_window(self) -> None:
        with pytest.raises(ValueError, match="window_hours"):
            burn_rate_threshold(0.02, 0.0)

    def test_burn_rate_is_ratio_over_budget(self) -> None:
        assert burn_rate(0.01, 0.001) == pytest.approx(10.0)

    def test_burn_rate_rejects_zero_budget(self) -> None:
        with pytest.raises(ValueError, match="error_budget"):
            burn_rate(0.5, 0.0)

    def test_budget_consumed_is_the_inverse_of_threshold(self) -> None:
        """Round-trip: 14.4x for an hour must report back as 2% of budget."""
        assert budget_consumed_pct(14.4, 1.0, 30) == pytest.approx(2.0)

        assert budget_consumed_pct(6.0, 6.0, 30) == pytest.approx(5.0)

    def test_build_burn_windows_uses_config(self) -> None:
        fast, slow = build_burn_windows(_alerting_config())

        assert fast.burn_class == "fast"
        assert fast.threshold == pytest.approx(14.4)
        assert fast.severity is Severity.CRITICAL
        assert slow.burn_class == "slow"
        assert slow.threshold == pytest.approx(6.0)
        assert slow.severity is Severity.HIGH


class TestSloEvaluator:
    async def test_caddy_ratio_is_request_weighted(self, tmp_path: Path) -> None:
        """A busy scrape must count for more than an idle one.

        Unweighted, these two samples average to a 50% error rate. Weighted by
        request volume the true ratio is 100/1100 -> ~9%.
        """
        config = _db_config(tmp_path)
        db = DatabaseEngine(config)
        await db.start()
        try:
            now = datetime.now(UTC)
            await _seed_caddy(
                config.db_path,
                [
                    (1000.0, 0.0, now - timedelta(minutes=2)),
                    (100.0, 1.0, now - timedelta(minutes=1)),
                ],
            )
            sample = await SloEvaluator(db).failure_ratio(_slo(), minutes=60)
            assert sample.failure_ratio == pytest.approx(100.0 / 1100.0)
            assert sample.volume == pytest.approx(1100.0)
        finally:
            await db.aclose()

    async def test_zero_traffic_is_not_a_failure(self, tmp_path: Path) -> None:
        """An empty window must yield 0.0, never a division error or a phantom 100%."""
        config = _db_config(tmp_path)
        db = DatabaseEngine(config)
        await db.start()
        try:
            sample = await SloEvaluator(db).failure_ratio(_slo(), minutes=60)
            assert sample.failure_ratio == 0.0
            assert sample.has_traffic is False
        finally:
            await db.aclose()

    async def test_icmp_ratio_uses_raw_counts(self, tmp_path: Path) -> None:
        """Exact, because icmp_probes stores per-cycle counts rather than rates."""
        config = _db_config(tmp_path)
        db = DatabaseEngine(config)
        await db.start()
        try:
            now = datetime.now(UTC)
            await _seed_icmp(
                config.db_path,
                [(5, 5, now - timedelta(minutes=2)), (5, 1, now - timedelta(minutes=1))],
            )
            slo = _slo(name="dns", source=SloSource.ICMP, entity_id="8.8.8.8", target=0.99)
            sample = await SloEvaluator(db).failure_ratio(slo, minutes=60)
            assert sample.failure_ratio == pytest.approx(0.4)
            assert sample.volume == pytest.approx(10.0)
        finally:
            await db.aclose()

    async def test_window_excludes_older_samples(self, tmp_path: Path) -> None:
        config = _db_config(tmp_path)
        db = DatabaseEngine(config)
        await db.start()
        try:
            now = datetime.now(UTC)
            await _seed_caddy(
                config.db_path,
                [
                    (100.0, 1.0, now - timedelta(hours=5)),
                    (100.0, 0.0, now - timedelta(minutes=1)),
                ],
            )
            sample = await SloEvaluator(db).failure_ratio(_slo(), minutes=60)
            assert sample.failure_ratio == pytest.approx(0.0)
        finally:
            await db.aclose()


class TestMultiWindow:
    async def test_fires_when_both_windows_breach(self, tmp_path: Path) -> None:
        config = _db_config(tmp_path)
        db = DatabaseEngine(config)
        await db.start()
        try:
            now = datetime.now(UTC)
            await _seed_caddy(
                config.db_path,
                [(100.0, 0.05, now - timedelta(minutes=m)) for m in range(1, 50)],
            )
            engine = AlertEngine(_alerting_config(), db, dispatchers=[])
            fast, _slow = build_burn_windows(_alerting_config())
            payload = await engine.evaluate_slo(_slo(), fast)
            assert payload is not None
            assert payload.severity is Severity.CRITICAL
            assert payload.burn_rate > fast.threshold
            assert payload.status == "firing"
        finally:
            await db.aclose()

    async def test_does_not_fire_when_only_long_window_breaches(self, tmp_path: Path) -> None:
        """The canary is the whole point: a spike that has stopped must not page.

        Heavy failures 30-59 minutes ago push the 60m window over the line, but
        the last 5 minutes are clean, so nothing should fire.
        """
        config = _db_config(tmp_path)
        db = DatabaseEngine(config)
        await db.start()
        try:
            now = datetime.now(UTC)
            old = [(100.0, 1.0, now - timedelta(minutes=m)) for m in range(30, 60)]
            recent = [(100.0, 0.0, now - timedelta(minutes=m)) for m in range(0, 5)]
            await _seed_caddy(config.db_path, old + recent)

            engine = AlertEngine(_alerting_config(), db, dispatchers=[])
            fast, _slow = build_burn_windows(_alerting_config())
            assert await engine.evaluate_slo(_slo(), fast) is None
        finally:
            await db.aclose()

    async def test_does_not_fire_below_threshold(self, tmp_path: Path) -> None:

        config = _db_config(tmp_path)
        db = DatabaseEngine(config)
        await db.start()
        try:
            now = datetime.now(UTC)
            await _seed_caddy(
                config.db_path,
                [(100.0, 0.001, now - timedelta(minutes=m)) for m in range(1, 50)],
            )
            engine = AlertEngine(_alerting_config(), db, dispatchers=[])
            fast, _slow = build_burn_windows(_alerting_config())
            assert await engine.evaluate_slo(_slo(), fast) is None
        finally:
            await db.aclose()


class _RecordingDispatcher:
    """Captures payloads instead of sending them."""

    def __init__(self, succeed: bool = True) -> None:
        self.sent: list[AlertPayload] = []
        self._succeed = succeed

    @property
    def name(self) -> str:
        return "recording"

    async def send(self, payload: AlertPayload) -> bool:
        self.sent.append(payload)
        return self._succeed

    async def aclose(self) -> None:
        return None


async def _breaching_db(tmp_path: Path) -> tuple[DatabaseEngine, DatabaseConfig]:
    config = _db_config(tmp_path)
    db = DatabaseEngine(config)
    await db.start()
    now = datetime.now(UTC)
    await _seed_caddy(
        config.db_path,
        [(100.0, 0.05, now - timedelta(minutes=m)) for m in range(0, 50)],
    )
    return db, config


class TestSuppressionAndFlapping:
    async def test_second_evaluation_does_not_renotify_inside_cooldown(self, tmp_path: Path) -> None:
        db, _config = await _breaching_db(tmp_path)
        recorder = _RecordingDispatcher()
        try:
            engine = AlertEngine(_alerting_config(cooldown_minutes=15), db, dispatchers=[recorder])
            await engine.evaluate_once()
            first = len(recorder.sent)
            assert first >= 1, "the first breach must notify"

            await engine.evaluate_once()
            assert len(recorder.sent) == first, "a still-firing alert must not renotify inside the cooldown"

            rows = await db.query_active_alerts(status="firing")
            keys = {r["alert_key"] for r in rows}
            assert "caddy-availability:fast" in keys
            assert len(rows) == len(keys), "suppression must not create duplicate firing rows"
        finally:
            await db.aclose()

    async def test_renotifies_once_cooldown_has_elapsed(self, tmp_path: Path) -> None:
        db, _config = await _breaching_db(tmp_path)
        recorder = _RecordingDispatcher()
        try:
            engine = AlertEngine(_alerting_config(cooldown_minutes=15), db, dispatchers=[recorder])
            await engine.evaluate_once()
            before = len(recorder.sent)

            stale = (datetime.now(UTC) - timedelta(minutes=30)).isoformat()
            async with _connect(db._db_path) as conn:
                await conn.execute("UPDATE active_alerts SET last_notified_at = ?", (stale,))
                await conn.commit()

            await engine.evaluate_once()
            assert len(recorder.sent) > before
        finally:
            await db.aclose()

    async def test_alert_is_held_open_through_one_quiet_tick(self, tmp_path: Path) -> None:
        """Flapping protection: do not resolve on the first sub-threshold tick."""
        db, config = await _breaching_db(tmp_path)
        recorder = _RecordingDispatcher()
        try:
            engine = AlertEngine(
                _alerting_config(cooldown_minutes=15, resolve_after_seconds=300.0),
                db,
                dispatchers=[recorder],
            )
            await engine.evaluate_once()
            assert await db.get_active_alert("caddy-availability:fast") is not None

            async with _connect(config.db_path) as conn:
                await conn.execute("DELETE FROM caddy_metrics")
                await conn.commit()
            now = datetime.now(UTC)
            await _seed_caddy(
                config.db_path,
                [(100.0, 0.0, now - timedelta(minutes=m)) for m in range(0, 50)],
            )

            await engine.evaluate_once()
            assert await db.get_active_alert("caddy-availability:fast") is not None, (
                "must not resolve on the first quiet tick"
            )
            assert all(p.status == "firing" for p in recorder.sent)
        finally:
            await db.aclose()

    async def test_resolves_after_the_grace_period(self, tmp_path: Path) -> None:
        db, config = await _breaching_db(tmp_path)
        recorder = _RecordingDispatcher()
        try:
            engine = AlertEngine(
                _alerting_config(cooldown_minutes=15, resolve_after_seconds=0.0),
                db,
                dispatchers=[recorder],
            )
            await engine.evaluate_once()

            async with _connect(config.db_path) as conn:
                await conn.execute("DELETE FROM caddy_metrics")
                await conn.commit()

            now = datetime.now(UTC)
            await _seed_caddy(
                config.db_path,
                [(100.0, 0.0, now - timedelta(minutes=m)) for m in range(0, 50)],
            )

            await engine.evaluate_once()
            await engine.evaluate_once()

            assert await db.get_active_alert("caddy-availability:fast") is None
            assert any(p.status == "resolved" for p in recorder.sent)
        finally:
            await db.aclose()


def _payload(status: str = "firing") -> AlertPayload:

    return AlertPayload(
        alert_key="caddy-availability:fast",
        slo_name="caddy-availability",
        entity_id="edge-01",
        severity=Severity.CRITICAL,
        burn_class="fast",
        status=status,
        burn_rate=50.0,
        threshold=14.4,
        observed_failure_ratio=0.05,
        slo_target=0.999,
        budget_consumed_pct=6.9,
        long_window_minutes=60,
        short_window_minutes=5,
        triggered_at=datetime.now(UTC),
    )


class TestDispatchers:
    async def test_discord_posts_an_embed(self, respx_mock) -> None:
        route = respx_mock.post(DISCORD_URL).mock(return_value=httpx.Response(204))
        async with httpx.AsyncClient() as client:
            assert await DiscordDispatcher(DISCORD_URL, client, 5.0).send(_payload()) is True
        assert route.called
        body = route.calls[0].request.content.decode()
        assert "caddy-availability" in body
        assert "embeds" in body

    async def test_slack_posts_blocks(self, respx_mock) -> None:
        route = respx_mock.post(SLACK_URL).mock(return_value=httpx.Response(200, text="ok"))
        async with httpx.AsyncClient() as client:
            assert await SlackDispatcher(SLACK_URL, client, 5.0).send(_payload()) is True

        assert route.called
        assert "blocks" in route.calls[0].request.content.decode()

    async def test_dispatch_failure_is_reported_not_raised(self, respx_mock) -> None:
        """A broken channel must not take down the evaluation loop."""
        respx_mock.post(DISCORD_URL).mock(return_value=httpx.Response(500, text="boom"))
        async with httpx.AsyncClient() as client:
            assert await DiscordDispatcher(DISCORD_URL, client, 5.0).send(_payload()) is False

    async def test_transport_error_is_reported_not_raised(self, respx_mock) -> None:
        respx_mock.post(DISCORD_URL).mock(side_effect=httpx.ConnectError("refused"))
        async with httpx.AsyncClient() as client:
            assert await DiscordDispatcher(DISCORD_URL, client, 5.0).send(_payload()) is False

    async def test_resolved_payload_renders_recovery_text(self) -> None:
        payload = _payload(status="resolved")
        assert "RESOLVED" in payload.title
        assert "recovered" in payload.summary


class TestMissingChannel:
    async def test_alert_is_persisted_even_with_no_channel(self, tmp_path: Path) -> None:
        """No channel configured must not lose the alert or raise."""
        db, _config = await _breaching_db(tmp_path)
        try:
            engine = AlertEngine(_alerting_config(), db, dispatchers=[])

            fired = await engine.evaluate_once()
            assert fired, "the breach should still be detected"
            rows = await db.query_active_alerts(status="firing")
            assert rows, "the alert must be recorded even when it cannot be sent"
        finally:
            await db.aclose()

    async def test_missing_channel_is_logged_once(self, tmp_path: Path, caplog) -> None:
        db, _config = await _breaching_db(tmp_path)
        try:
            engine = AlertEngine(_alerting_config(), db, dispatchers=[])
            with caplog.at_level("ERROR"):
                await engine.dispatch(_payload())
                await engine.dispatch(_payload())
            complaints = [r for r in caplog.records if "no notification channel" in r.message]

            assert len(complaints) == 1, "the warning must not repeat for every alert"
        finally:
            await db.aclose()


class TestConfigValidation:
    def test_rejects_duplicate_slo_names(self) -> None:
        with pytest.raises(ValueError, match="duplicate SLO names"):
            AlertingConfig(slos=[_slo(name="dup"), _slo(name="dup")])

    def test_rejects_short_window_longer_than_long_window(self) -> None:
        with pytest.raises(ValueError, match="short_window"):
            AlertingConfig(fast_burn_long_window_minutes=5, fast_burn_short_window_minutes=60)

    def test_has_channel_reflects_configuration(self) -> None:
        assert AlertingConfig().has_channel is False
        assert AlertingConfig(discord_webhook_url=DISCORD_URL).has_channel is True

    def test_rejects_non_ratio_slo_source(self) -> None:
        """host/docker are not good/bad event ratios and must not validate."""
        with pytest.raises(ValueError):
            SloDefinition(name="bad", source="host", entity_id="localhost", target=0.999)

    def test_rejects_impossible_target(self) -> None:
        with pytest.raises(ValueError):
            SloDefinition(name="bad", source=SloSource.CADDY, entity_id="edge-01", target=1.0)


class TestEngineLifecycle:
    async def test_run_forever_stops_on_request(self, tmp_path: Path) -> None:
        config = _db_config(tmp_path)
        db = DatabaseEngine(config)
        await db.start()
        try:
            engine = AlertEngine(_alerting_config(evaluation_interval_seconds=10.0), db, dispatchers=[])
            task = asyncio.create_task(engine.run_forever())
            await asyncio.sleep(0.05)
            await engine.stop()
            await asyncio.wait_for(task, timeout=5.0)
        finally:
            await db.aclose()

    async def test_idles_without_slos(self, tmp_path: Path) -> None:
        config = _db_config(tmp_path)
        db = DatabaseEngine(config)
        await db.start()
        try:
            engine = AlertEngine(AlertingConfig(slos=[]), db, dispatchers=[])
            assert await engine.evaluate_once() == []
        finally:
            await db.aclose()

    async def test_aclose_closes_only_an_owned_client(self, tmp_path: Path) -> None:
        """A caller-supplied client must survive the engine closing."""
        config = _db_config(tmp_path)
        db = DatabaseEngine(config)
        await db.start()
        client = httpx.AsyncClient()
        try:
            engine = AlertEngine(
                _alerting_config(discord_webhook_url=DISCORD_URL),
                db,
                dispatchers=[DiscordDispatcher(DISCORD_URL, client, 5.0)],
            )
            await engine.aclose()
            assert client.is_closed is False
        finally:
            await client.aclose()
            await db.aclose()
