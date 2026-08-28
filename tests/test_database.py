from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from config import DatabaseConfig
from database import DatabaseEngine
from models import CaddyMetric, DockerEvent, HostMetric


def _db_config(tmp_path: Path, **overrides: object) -> DatabaseConfig:
    return DatabaseConfig(
        db_path=str(tmp_path / "test.db"),
        queue_maxsize=overrides.get("queue_maxsize", 256),
        batch_size=overrides.get("batch_size", 16),
        prune_interval_seconds=overrides.get("prune_interval_seconds", 3600.0),
        retention_days=overrides.get("retention_days", 7),
    )


def _host_metric(
    host_id: str = "node-01",
    ts: datetime | None = None,
) -> HostMetric:
    return HostMetric(
        host_id=host_id,
        cpu_percent=42.5,
        memory_percent=67.3,
        disk_percent=55.0,
        load_avg=1.23,
        disk_read_bps=1000.0,
        disk_write_bps=2000.0,
        net_bytes_sent_per_sec=500.0,
        net_bytes_recv_per_sec=1500.0,
        psi_cpu_some_avg10=0.5,
        psi_memory_some_avg10=1.2,
        psi_io_some_avg10=0.1,
        timestamp=ts or datetime.now(UTC),
    )


def _caddy_metric(
    instance_id: str = "edge-01",
    ts: datetime | None = None,
) -> CaddyMetric:
    return CaddyMetric(
        instance_id=instance_id,
        requests_per_second=150.0,
        error_rate=0.02,
        p99_latency_ms=45.0,
        active_conns=12,
        timestamp=ts or datetime.now(UTC),
    )


def _docker_event(
    container_id: str = "abc123",
    status: str = "die",
    ts: datetime | None = None,
) -> DockerEvent:
    return DockerEvent(
        container_id=container_id,
        container_name="web-01",
        status=status,
        image="nginx:latest",
        exit_code=137,
        failure_reason="killed by signal 9",
        timestamp=ts or datetime.now(UTC),
    )


async def test_schema_creates_all_tables(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        async with db._worker._conn.execute(  # type: ignore[union-attr]
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
        ) as cursor:
            tables = {row[0] for row in await cursor.fetchall()}
        expected = {
            "system_metrics",
            "docker_metrics",
            "caddy_metrics",
            "network_probes",
            "ai_diagnostic_logs",
        }
        assert expected.issubset(tables)


async def test_wal_mode_enabled(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        async with db._worker._conn.execute("PRAGMA journal_mode") as cursor:  # type: ignore[union-attr]
            mode = (await cursor.fetchone())[0]
        assert mode == "wal"


async def test_write_host_metric_persists(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        await db.write(_host_metric())
        await asyncio.sleep(0.1)
        rows = await db.query_recent_host_metrics("node-01", minutes=5)
        assert len(rows) == 1
        assert rows[0]["host_id"] == "node-01"
        assert rows[0]["cpu"] == pytest.approx(42.5)
        assert rows[0]["memory"] == pytest.approx(67.3)


async def test_write_caddy_metric_persists(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        await db.write(_caddy_metric())
        await asyncio.sleep(0.1)
        rows = await db.query_recent_caddy_metrics("edge-01", minutes=5)
        assert len(rows) == 1
        assert rows[0]["requests_per_sec"] == pytest.approx(150.0)
        assert rows[0]["active_conns"] == 12


async def test_write_docker_event_persists(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        await db.write(_docker_event())
        await asyncio.sleep(0.1)
        rows = await db.query_recent_docker_events("abc123", minutes=5)
        assert len(rows) == 1
        assert rows[0]["status"] == "die"
        assert rows[0]["exit_code"] == 137


async def test_batch_flush_multiple_items(tmp_path: Path) -> None:
    config = _db_config(tmp_path, batch_size=8)
    async with DatabaseEngine(config) as db:
        for _ in range(10):
            await db.write(_host_metric())
        await asyncio.sleep(0.1)
        rows = await db.query_recent_host_metrics("node-01", minutes=5)
        assert len(rows) == 10


async def test_queue_overflow_drops_with_warning(tmp_path: Path) -> None:
    config = _db_config(tmp_path, queue_maxsize=100, batch_size=2)
    async with DatabaseEngine(config) as db:
        for _ in range(200):
            await db.write(_host_metric())
        assert db.dropped_count > 0


async def test_unsupported_model_type_is_ignored(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        await db.write("not a metric")
        await db.write(42)
        await asyncio.sleep(0.1)
        assert db._queue.empty()


async def test_concurrent_writes_from_multiple_tasks(tmp_path: Path) -> None:
    config = _db_config(tmp_path, batch_size=32)
    async with DatabaseEngine(config) as db:

        async def writer(n: int) -> None:
            for _ in range(20):
                await db.write(_host_metric(host_id=f"node-{n}"))

        await asyncio.gather(*(writer(i) for i in range(5)))
        await asyncio.sleep(0.2)
        for i in range(5):
            rows = await db.query_recent_host_metrics(f"node-{i}", minutes=5)
            assert len(rows) == 20


async def test_pruning_removes_old_rows(tmp_path: Path) -> None:
    config = _db_config(tmp_path, retention_days=1)
    async with DatabaseEngine(config) as db:
        old_ts = datetime.now(UTC) - timedelta(days=10)
        await db.write(_host_metric(ts=old_ts))
        await asyncio.sleep(0.1)
        rows = await db.query_recent_host_metrics("node-01", minutes=60 * 24 * 365)
        assert len(rows) == 1

        from database import _PruneWorker

        pruner = _PruneWorker(config.db_path, 3600.0, 1)
        await pruner._prune()

        rows = await db.query_recent_host_metrics("node-01", minutes=60 * 24 * 365)
        assert len(rows) == 0


async def test_pruning_keeps_recent_rows(tmp_path: Path) -> None:
    config = _db_config(tmp_path, retention_days=7)
    async with DatabaseEngine(config) as db:
        recent_ts = datetime.now(UTC) - timedelta(hours=1)
        await db.write(_host_metric(ts=recent_ts))
        await asyncio.sleep(0.1)

        from database import _PruneWorker

        pruner = _PruneWorker(config.db_path, 3600.0, 7)
        await pruner._prune()

        rows = await db.query_recent_host_metrics("node-01", minutes=60 * 24 * 365)
        assert len(rows) == 1


async def test_insert_diagnostic_log_directly(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        await db.insert_diagnostic_log("health-check", "warning", "disk high", '{"pct":92}')
        rows = await db.query_diagnostic_logs(source="health-check", minutes=5)
        assert len(rows) == 1
        assert rows[0]["severity"] == "warning"
        assert rows[0]["message"] == "disk high"
        assert rows[0]["details"] == '{"pct":92}'


async def test_query_diagnostic_logs_no_source_filter(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        await db.insert_diagnostic_log("a", "info", "msg1")
        await db.insert_diagnostic_log("b", "error", "msg2")
        rows = await db.query_diagnostic_logs(minutes=5)
        assert len(rows) == 2


async def test_query_respects_time_filter(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    async with DatabaseEngine(config) as db:
        old_ts = datetime.now(UTC) - timedelta(hours=2)
        await db.write(_host_metric(ts=old_ts))
        await asyncio.sleep(0.1)
        rows = await db.query_recent_host_metrics("node-01", minutes=30)
        assert len(rows) == 0


async def test_stop_drains_remaining_queue(tmp_path: Path) -> None:
    config = _db_config(tmp_path, batch_size=4)
    async with DatabaseEngine(config) as db:
        for _ in range(3):
            await db.write(_host_metric())
    async with DatabaseEngine(config) as db:
        rows = await db.query_recent_host_metrics("node-01", minutes=5)
        assert len(rows) == 3


async def test_context_manager_entry_exit(tmp_path: Path) -> None:
    config = _db_config(tmp_path)
    db = DatabaseEngine(config)
    async with db:
        await db.write(_host_metric())
        await asyncio.sleep(0.1)
    assert db._worker._conn is None
