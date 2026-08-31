from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import aiosqlite

# collectors/ never imports database, so this direction is cycle-free.
from collectors.caddy_scraper import CaddyScrapeResult
from config import DatabaseConfig
from diagnostic.schema import DIAGNOSTIC_SCHEMA_DDL
from models import (
    CaddyMetric,
    DockerEvent,
    HostMetric,
    IcmpProbeMetric,
    MetricType,
    SnmpHostMetric,
    SnmpInterfaceMetric,
)

logger = logging.getLogger(__name__)

_BUSY_TIMEOUT_MS = 5000


@asynccontextmanager
async def _connect(db_path: str) -> AsyncIterator[aiosqlite.Connection]:
    """Open a connection carrying the same busy_timeout as the writer.

    WAL lets readers run concurrently with the writer, but writers still
    serialise. Without an explicit busy_timeout a query that lands while the
    single-writer task holds the lock raises 'database is locked' immediately
    instead of waiting for the flush to finish.
    """
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        yield conn

_SCHEMA_DDL = """\
CREATE TABLE IF NOT EXISTS system_metrics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     TEXT    NOT NULL,
    cpu         REAL    NOT NULL,
    memory      REAL    NOT NULL,
    disk        REAL    NOT NULL,
    load_avg    REAL    NOT NULL,
    disk_r_bps  REAL    NOT NULL DEFAULT 0.0,
    disk_w_bps  REAL    NOT NULL DEFAULT 0.0,
    net_tx_bps  REAL    NOT NULL DEFAULT 0.0,
    net_rx_bps  REAL    NOT NULL DEFAULT 0.0,
    psi_cpu     REAL,
    psi_mem     REAL,
    psi_io      REAL,
    created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_system_metrics_created
    ON system_metrics(created_at);

CREATE TABLE IF NOT EXISTS docker_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id    TEXT    NOT NULL,
    container_name  TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    image           TEXT,
    exit_code       INTEGER,
    failure_reason  TEXT,
    created_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_docker_metrics_created
    ON docker_metrics(created_at);
CREATE INDEX IF NOT EXISTS idx_docker_metrics_container
    ON docker_metrics(container_id, created_at);

CREATE TABLE IF NOT EXISTS caddy_metrics (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id       TEXT    NOT NULL,
    requests_per_sec  REAL    NOT NULL,
    error_rate        REAL    NOT NULL,
    p99_latency_ms    REAL    NOT NULL,
    active_conns      INTEGER NOT NULL,
    created_at        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_caddy_metrics_created
    ON caddy_metrics(created_at);
CREATE INDEX IF NOT EXISTS idx_caddy_metrics_instance
    ON caddy_metrics(instance_id, created_at);

CREATE TABLE IF NOT EXISTS network_probes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id      TEXT    NOT NULL,
    url              TEXT    NOT NULL,
    status_code      INTEGER NOT NULL,
    response_time_ms REAL    NOT NULL,
    is_up            INTEGER NOT NULL,
    ssl_expiry_days  REAL,
    timeout          INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_network_probes_created
    ON network_probes(created_at);

CREATE TABLE IF NOT EXISTS icmp_probes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_host     TEXT    NOT NULL,
    target_ip       TEXT    NOT NULL,
    rtt_ms          REAL    NOT NULL,
    avg_rtt_ms      REAL    NOT NULL,
    min_rtt_ms      REAL    NOT NULL,
    max_rtt_ms      REAL    NOT NULL,
    packet_loss_pct REAL    NOT NULL,
    probes_sent     INTEGER NOT NULL,
    probes_received INTEGER NOT NULL,
    created_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_icmp_probes_created ON icmp_probes(created_at);
CREATE INDEX IF NOT EXISTS idx_icmp_probes_target ON icmp_probes(target_host, created_at);

CREATE TABLE IF NOT EXISTS snmp_interfaces (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT    NOT NULL,
    device_host     TEXT    NOT NULL,
    if_index        INTEGER NOT NULL,
    if_name         TEXT    NOT NULL,
    if_oper_status  INTEGER NOT NULL,
    if_admin_status INTEGER NOT NULL,
    if_speed_bps    INTEGER NOT NULL,
    if_in_octets    INTEGER NOT NULL,
    if_out_octets   INTEGER NOT NULL,
    if_in_errors    INTEGER NOT NULL,
    if_out_errors   INTEGER NOT NULL,
    in_bps          REAL    NOT NULL,
    out_bps         REAL    NOT NULL,
    created_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snmp_interfaces_created ON snmp_interfaces(created_at);

CREATE TABLE IF NOT EXISTS snmp_hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT    NOT NULL,
    device_host     TEXT    NOT NULL,
    hr_system_descr TEXT,
    hr_cpu_load     REAL,
    hr_memory_total INTEGER,
    hr_memory_used  INTEGER,
    created_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snmp_hosts_created ON snmp_hosts(created_at);

CREATE TABLE IF NOT EXISTS ai_diagnostic_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    source     TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    message    TEXT    NOT NULL,
    details    TEXT,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_diagnostic_logs_created
    ON ai_diagnostic_logs(created_at);
"""

# Phase 4 alerting state. Kept here rather than in diagnostic/schema.py because
# alerting is not part of the diagnostic package: routing it through there would
# make database.py depend on a diagnostic module for alerting DDL while
# alert_engine.py depends on database.py, for no benefit.
#
# slo_name / entity_id / burn_class / last_notified_at go beyond a minimal alert
# row: suppression ("have we notified about this key recently?") and resolution
# tracking are not implementable without them.
_ALERTING_SCHEMA_DDL = """\
CREATE TABLE IF NOT EXISTS active_alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_key        TEXT    NOT NULL,
    slo_name         TEXT    NOT NULL,
    entity_id        TEXT    NOT NULL,
    severity         TEXT    NOT NULL,
    burn_class       TEXT    NOT NULL,
    burn_rate        REAL    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'firing',
    triggered_at     TEXT    NOT NULL,
    resolved_at      TEXT,
    last_notified_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_active_alerts_status
    ON active_alerts(status);
CREATE INDEX IF NOT EXISTS idx_active_alerts_key
    ON active_alerts(alert_key, status);
CREATE INDEX IF NOT EXISTS idx_active_alerts_triggered
    ON active_alerts(triggered_at);
"""

_SCHEMA_DDL = _SCHEMA_DDL + DIAGNOSTIC_SCHEMA_DDL + _ALERTING_SCHEMA_DDL


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class DatabaseError(Exception):
    pass


class _WriterWorker:
    __slots__ = ("_batch_size", "_conn", "_db_path", "_queue")

    def __init__(
        self,
        db_path: str,
        queue: asyncio.Queue[object],
        batch_size: int,
    ) -> None:
        self._db_path = db_path
        self._queue = queue
        self._batch_size = batch_size
        self._conn: aiosqlite.Connection | None = None

    async def start(self) -> None:
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = None
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        await self._conn.executescript(_SCHEMA_DDL)
        await self._conn.commit()

    async def run(self, stop_event: asyncio.Event) -> None:
        assert self._conn is not None
        while not stop_event.is_set():
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except TimeoutError:
                continue
            batch: list[object] = [item]
            self._queue.task_done()
            while len(batch) < self._batch_size:
                try:
                    item = self._queue.get_nowait()
                    batch.append(item)
                    self._queue.task_done()
                except asyncio.QueueEmpty:
                    break
            await self._safe_flush(batch)
        await self._drain_remaining()

    async def _safe_flush(self, batch: list[object]) -> None:
        """Flush a batch, surviving any failure.

        The writer is the only task that persists telemetry. If it dies the
        queue silently fills to maxsize and every subsequent write is dropped
        for the lifetime of the process, while collectors keep scraping and the
        CLI keeps printing. Losing one batch is strictly better than that.
        """
        try:
            await self._flush_batch(batch)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "failed to flush batch of %d rows; dropping the batch and continuing",
                len(batch),
            )

    async def _drain_remaining(self) -> None:
        batch: list[object] = []
        while True:
            try:
                item = self._queue.get_nowait()
                batch.append(item)
                self._queue.task_done()
            except asyncio.QueueEmpty:
                break
            if len(batch) >= self._batch_size:
                await self._safe_flush(batch)
                batch.clear()
        if batch:
            await self._safe_flush(batch)

    async def _flush_batch(self, batch: list[object]) -> None:
        assert self._conn is not None
        by_table: dict[str, list[tuple[Any, ...]]] = {
            "system": [],
            "docker": [],
            "caddy": [],
            "icmp": [],
            "snmp_if": [],
            "snmp_host": [],
        }
        for item in batch:
            result = self._to_row(item)
            if result is None:
                # Never drop silently again: an unrecognised type here is how
                # every Caddy metric was lost for the lifetime of the process.
                logger.warning(
                    "dropping unpersistable item of type %s",
                    type(item).__name__,
                )
                continue
            table, values = result
            by_table[table].append(values)

        any_data = any(by_table[k] for k in by_table)
        if not any_data:
            return

        await self._conn.execute("BEGIN IMMEDIATE")
        try:
            if by_table["system"]:
                await self._conn.executemany(
                    "INSERT INTO system_metrics"
                    "(host_id,cpu,memory,disk,load_avg,disk_r_bps,disk_w_bps,"
                    "net_tx_bps,net_rx_bps,psi_cpu,psi_mem,psi_io,created_at)"
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    by_table["system"],
                )
            if by_table["docker"]:
                await self._conn.executemany(
                    "INSERT INTO docker_metrics"
                    "(container_id,container_name,status,image,exit_code,"
                    "failure_reason,created_at) VALUES (?,?,?,?,?,?,?)",
                    by_table["docker"],
                )
            if by_table["caddy"]:
                await self._conn.executemany(
                    "INSERT INTO caddy_metrics"
                    "(instance_id,requests_per_sec,error_rate,p99_latency_ms,"
                    "active_conns,created_at) VALUES (?,?,?,?,?,?)",
                    by_table["caddy"],
                )
            if by_table["icmp"]:
                await self._conn.executemany(
                    "INSERT INTO icmp_probes"
                    "(target_host,target_ip,rtt_ms,avg_rtt_ms,min_rtt_ms,max_rtt_ms,"
                    "packet_loss_pct,probes_sent,probes_received,created_at)"
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    by_table["icmp"],
                )
            if by_table["snmp_if"]:
                await self._conn.executemany(
                    "INSERT INTO snmp_interfaces"
                    "(device_id,device_host,if_index,if_name,if_oper_status,"
                    "if_admin_status,if_speed_bps,if_in_octets,if_out_octets,"
                    "if_in_errors,if_out_errors,in_bps,out_bps,created_at)"
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    by_table["snmp_if"],
                )
            if by_table["snmp_host"]:
                await self._conn.executemany(
                    "INSERT INTO snmp_hosts"
                    "(device_id,device_host,hr_system_descr,hr_cpu_load,"
                    "hr_memory_total,hr_memory_used,created_at)"
                    "VALUES (?,?,?,?,?,?,?)",
                    by_table["snmp_host"],
                )
            await self._conn.execute("COMMIT")
        except Exception:
            await self._conn.execute("ROLLBACK")
            raise

    @staticmethod
    def _to_row(item: object) -> tuple[str, tuple[Any, ...]] | None:
        # SystemHealthDaemon's caddy loop emits CaddyScrapeResult, a wrapper
        # carrying the CaddyMetric plus a status-code breakdown. Unwrap it or
        # the isinstance(CaddyMetric) branch below never matches and every
        # Caddy sample is silently discarded.
        if isinstance(item, CaddyScrapeResult):
            item = item.metric

        if isinstance(item, HostMetric):
            return (
                "system",
                (
                    item.host_id,
                    item.cpu_percent,
                    item.memory_percent,
                    item.disk_percent,
                    item.load_avg,
                    item.disk_read_bps,
                    item.disk_write_bps,
                    item.net_bytes_sent_per_sec,
                    item.net_bytes_recv_per_sec,
                    item.psi_cpu_some_avg10,
                    item.psi_memory_some_avg10,
                    item.psi_io_some_avg10,
                    item.timestamp.isoformat(),
                ),
            )
        if isinstance(item, CaddyMetric):
            return (
                "caddy",
                (
                    item.instance_id,
                    item.requests_per_second,
                    item.error_rate,
                    item.p99_latency_ms,
                    item.active_conns,
                    item.timestamp.isoformat(),
                ),
            )
        if isinstance(item, DockerEvent):
            return (
                "docker",
                (
                    item.container_id,
                    item.container_name,
                    item.status,
                    item.image,
                    item.exit_code,
                    item.failure_reason,
                    item.timestamp.isoformat(),
                ),
            )
        if isinstance(item, IcmpProbeMetric):
            return (
                "icmp",
                (
                    item.target_host,
                    item.target_ip,
                    item.rtt_ms,
                    item.avg_rtt_ms,
                    item.min_rtt_ms,
                    item.max_rtt_ms,
                    item.packet_loss_pct,
                    item.probes_sent,
                    item.probes_received,
                    item.timestamp.isoformat(),
                ),
            )
        if isinstance(item, SnmpInterfaceMetric):
            return (
                "snmp_if",
                (
                    item.device_id,
                    item.device_host,
                    item.if_index,
                    item.if_name,
                    item.if_oper_status,
                    item.if_admin_status,
                    item.if_speed_bps,
                    item.if_in_octets,
                    item.if_out_octets,
                    item.if_in_errors,
                    item.if_out_errors,
                    item.in_bps,
                    item.out_bps,
                    item.timestamp.isoformat(),
                ),
            )
        if isinstance(item, SnmpHostMetric):
            return (
                "snmp_host",
                (
                    item.device_id,
                    item.device_host,
                    item.hr_system_descr,
                    item.hr_cpu_load,
                    item.hr_memory_total,
                    item.hr_memory_used,
                    item.timestamp.isoformat(),
                ),
            )
        return None

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None


class _PruneWorker:
    __slots__ = ("_db_path", "_interval_seconds", "_retention_days")

    def __init__(self, db_path: str, interval_seconds: float, retention_days: int) -> None:
        self._db_path = db_path
        self._interval_seconds = interval_seconds
        self._retention_days = retention_days

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self._interval_seconds)
                break
            except TimeoutError:
                pass
            await self._prune()

    async def _prune(self) -> None:
        cutoff = (datetime.now(UTC) - timedelta(days=self._retention_days)).isoformat()
        tables = (
            "system_metrics",
            "docker_metrics",
            "caddy_metrics",
            "network_probes",
            "icmp_probes",
            "snmp_interfaces",
            "snmp_hosts",
            "ai_diagnostic_logs",
        )
        CHUNK_SIZE = 1000
        async with _connect(self._db_path) as conn:
            total = 0
            for table in tables:
                while True:
                    # `DELETE ... LIMIT` needs SQLITE_ENABLE_UPDATE_DELETE_LIMIT,
                    # which is a compile-time option that is not universally on.
                    # The rowid subquery is portable and plans identically.
                    cursor = await conn.execute(
                        f"DELETE FROM {table} WHERE rowid IN ("  # noqa: S608 - table names are module constants
                        f"SELECT rowid FROM {table} WHERE created_at < ? LIMIT ?"
                        f")",
                        (cutoff, CHUNK_SIZE),
                    )
                    deleted = cursor.rowcount
                    total += deleted
                    await conn.commit()
                    if deleted < CHUNK_SIZE:
                        break
                    await asyncio.sleep(0)

            # active_alerts is pruned separately: it has no created_at column
            # (adding it to the loop above would raise on every cycle), and a
            # firing alert must never be deleted out from under the engine.
            while True:
                cursor = await conn.execute(
                    "DELETE FROM active_alerts WHERE rowid IN ("
                    "SELECT rowid FROM active_alerts "
                    "WHERE status = 'resolved' AND resolved_at IS NOT NULL AND resolved_at < ? "
                    "LIMIT ?)",
                    (cutoff, CHUNK_SIZE),
                )
                deleted = cursor.rowcount
                total += deleted
                await conn.commit()
                if deleted < CHUNK_SIZE:
                    break
                await asyncio.sleep(0)

            if total > 0:
                logger.info("pruned %d total rows across %d tables", total, len(tables) + 1)


class DatabaseEngine:
    def __init__(self, config: DatabaseConfig | None = None) -> None:
        cfg = config or DatabaseConfig()
        self._db_path = cfg.db_path
        self._queue: asyncio.Queue[object] = asyncio.Queue(maxsize=cfg.queue_maxsize)
        self._worker = _WriterWorker(cfg.db_path, self._queue, cfg.batch_size)
        self._pruner = _PruneWorker(
            cfg.db_path,
            cfg.prune_interval_seconds,
            cfg.retention_days,
        )
        self._stop_event: asyncio.Event | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._dropped = 0

    @property
    def dropped_count(self) -> int:
        return self._dropped

    async def write(self, item: object) -> None:
        try:
            self._queue.put_nowait(item)
        except asyncio.QueueFull:
            self._dropped += 1
            if self._dropped % 100 == 1:
                logger.warning(
                    "ingest queue full, dropped item (total dropped: %d)",
                    self._dropped,
                )

    async def start(self) -> None:
        self._stop_event = asyncio.Event()
        await self._worker.start()
        writer = asyncio.create_task(self._worker.run(self._stop_event), name="db-writer")
        pruner = asyncio.create_task(self._pruner.run(self._stop_event), name="db-pruner")
        writer.add_done_callback(self._on_worker_done)
        pruner.add_done_callback(self._on_worker_done)
        self._tasks = [writer, pruner]

    def _on_worker_done(self, task: asyncio.Task[None]) -> None:
        """Surface a background task that exited on its own.

        Without this a dead writer is invisible: the queue fills to maxsize and
        every write is dropped for the lifetime of the process while collectors
        carry on scraping.
        """
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.error("database task %s died: %r", task.get_name(), exc, exc_info=exc)
        elif self._stop_event is not None and not self._stop_event.is_set():
            logger.error("database task %s exited before shutdown was requested", task.get_name())

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        await self._worker.close()
        if self._dropped:
            logger.warning("ingest queue dropped %d items in total this run", self._dropped)

    async def aclose(self) -> None:
        await self.stop()

    async def __aenter__(self) -> DatabaseEngine:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    @staticmethod
    def _cutoff_iso(minutes: int) -> str:
        return (datetime.now(UTC) - timedelta(minutes=minutes)).isoformat()

    async def _query_table(
        self,
        table: str,
        *,
        where: str,
        params: tuple[Any, ...],
        order: str = "created_at DESC",
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        async with _connect(self._db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(
                f"SELECT * FROM {table} WHERE {where} ORDER BY {order} LIMIT ?",
                (*params, limit),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def query_recent_host_metrics(
        self,
        host_id: str,
        *,
        minutes: int = 60,
    ) -> list[dict[str, Any]]:
        return await self._query_table(
            "system_metrics",
            where="host_id = ? AND created_at >= ?",
            params=(host_id, self._cutoff_iso(minutes)),
        )

    async def query_recent_caddy_metrics(
        self,
        instance_id: str,
        *,
        minutes: int = 60,
    ) -> list[dict[str, Any]]:
        return await self._query_table(
            "caddy_metrics",
            where="instance_id = ? AND created_at >= ?",
            params=(instance_id, self._cutoff_iso(minutes)),
        )

    async def query_recent_docker_events(
        self,
        container_id: str,
        *,
        minutes: int = 60,
    ) -> list[dict[str, Any]]:
        return await self._query_table(
            "docker_metrics",
            where="container_id = ? AND created_at >= ?",
            params=(container_id, self._cutoff_iso(minutes)),
        )

    async def query_recent_docker_events_any(
        self,
        *,
        minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Recent docker events across all containers, for cross-layer context."""
        return await self._query_table(
            "docker_metrics",
            where="created_at >= ?",
            params=(self._cutoff_iso(minutes),),
        )

    async def query_recent_probes(
        self,
        endpoint_id: str,
        *,
        minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """HTTP endpoint probes.

        NOTE: no collector currently writes `network_probes` — EndpointMetric
        has no producer — so this returns [] in the shipped configuration. For
        MetricType.NETWORK use query_recent_icmp_probes instead.
        """
        return await self._query_table(
            "network_probes",
            where="endpoint_id = ? AND created_at >= ?",
            params=(endpoint_id, self._cutoff_iso(minutes)),
        )

    async def query_recent_icmp_probes(
        self,
        target_host: str,
        *,
        minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """ICMP probe results, keyed by the target host the daemon pings."""
        return await self._query_table(
            "icmp_probes",
            where="target_host = ? AND created_at >= ?",
            params=(target_host, self._cutoff_iso(minutes)),
        )

    async def query_diagnostic_logs(
        self,
        *,
        source: str | None = None,
        minutes: int = 60,
    ) -> list[dict[str, Any]]:
        if source is not None:
            return await self._query_table(
                "ai_diagnostic_logs",
                where="source = ? AND created_at >= ?",
                params=(source, self._cutoff_iso(minutes)),
            )
        return await self._query_table(
            "ai_diagnostic_logs",
            where="created_at >= ?",
            params=(self._cutoff_iso(minutes),),
        )

    async def insert_diagnostic_log(
        self,
        source: str,
        severity: str,
        message: str,
        details: str | None = None,
    ) -> None:
        async with _connect(self._db_path) as conn:
            await conn.execute(
                "INSERT INTO ai_diagnostic_logs (source,severity,message,details,created_at) VALUES (?,?,?,?,?)",
                (source, severity, message, details, _now_iso()),
            )
            await conn.commit()

    # ------------------------------------------------------------------
    # Phase 3 diagnostic agent persistence
    # ------------------------------------------------------------------

    async def query_cooldown_all(self) -> list[tuple[str, str]]:
        async with _connect(self._db_path) as conn:
            cursor = await conn.execute("SELECT anomaly_type, last_triggered_at FROM cooldown_state")
            rows = await cursor.fetchall()
            return [(r[0], r[1]) for r in rows]

    async def get_cooldown(self, anomaly_type: str) -> datetime | None:
        async with _connect(self._db_path) as conn:
            cursor = await conn.execute(
                "SELECT last_triggered_at FROM cooldown_state WHERE anomaly_type = ?",
                (anomaly_type,),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        try:
            return datetime.fromisoformat(row[0])
        except ValueError:
            return None

    async def set_cooldown(self, anomaly_type: str, triggered_at: datetime) -> None:
        async with _connect(self._db_path) as conn:
            await conn.execute(
                "INSERT INTO cooldown_state (anomaly_type, last_triggered_at) VALUES (?, ?) "
                "ON CONFLICT(anomaly_type) DO UPDATE SET last_triggered_at = excluded.last_triggered_at",
                (anomaly_type, triggered_at.isoformat()),
            )
            await conn.commit()

    async def count_ai_calls_last_hour(self) -> int:
        # Count failures as well as successes. Filtering on success = 1 meant a
        # provider that was erroring — quota exhaustion, a 5xx run, a rejected
        # response schema — consumed no budget, so the daemon retried every
        # entity every cycle forever. Failed calls are still billed for input
        # tokens, so they must count against the cap.
        async with _connect(self._db_path) as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM ai_call_log WHERE created_at >= ?",
                (self._cutoff_iso(60),),
            )
            row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def query_recent_ai_calls(self, *, minutes: int = 60) -> list[dict[str, Any]]:
        return await self._query_table(
            "ai_call_log",
            where="created_at >= ?",
            params=(self._cutoff_iso(minutes),),
        )

    async def insert_ai_call_log(
        self,
        *,
        anomaly_type: str,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        success: bool,
        error: str | None = None,
    ) -> None:
        async with _connect(self._db_path) as conn:
            await conn.execute(
                "INSERT INTO ai_call_log "
                "(anomaly_type,provider,model,prompt_tokens,completion_tokens,total_tokens,"
                "success,error_message,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    anomaly_type,
                    provider,
                    model,
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                    int(success),
                    error,
                    _now_iso(),
                ),
            )
            await conn.commit()

    async def insert_proposed_rule(
        self,
        *,
        anomaly_type: str,
        metric_type: MetricType,
        entity_id: str,
        action_plan_json: str,
        severity: str,
    ) -> int:
        async with _connect(self._db_path) as conn:
            cursor = await conn.execute(
                "INSERT INTO proposed_remediation_rules "
                "(anomaly_type,metric_type,entity_id,action_plan_json,severity,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (
                    anomaly_type,
                    metric_type.value if hasattr(metric_type, "value") else metric_type,
                    entity_id,
                    action_plan_json,
                    severity,
                    _now_iso(),
                ),
            )
            await conn.commit()
            return int(cursor.lastrowid)

    async def query_proposed_rules(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        async with _connect(self._db_path) as conn:
            conn.row_factory = aiosqlite.Row
            if status is not None:
                cursor = await conn.execute(
                    "SELECT * FROM proposed_remediation_rules WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit),
                )
            else:
                cursor = await conn.execute(
                    "SELECT * FROM proposed_remediation_rules ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                )
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def update_rule_status(
        self,
        rule_id: int,
        status: str,
        *,
        reviewed_by: str | None = None,
    ) -> bool:
        async with _connect(self._db_path) as conn:
            cursor = await conn.execute(
                "UPDATE proposed_remediation_rules SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?",
                (status, _now_iso(), reviewed_by, rule_id),
            )
            await conn.commit()
            # Read rowcount before the connection closes.
            updated = cursor.rowcount > 0
        return updated

    async def list_known_container_ids(self) -> list[str]:
        async with _connect(self._db_path) as conn:
            cursor = await conn.execute("SELECT DISTINCT container_id FROM docker_metrics WHERE container_id != ''")
            rows = await cursor.fetchall()
        return [r[0] for r in rows]

    # ------------------------------------------------------------------
    # Phase 4 alerting — SLI aggregation
    # ------------------------------------------------------------------
    #
    # These aggregate in SQL rather than returning rows. A six-hour burn window
    # at a five-second scrape interval is ~4300 rows per SLO per evaluation;
    # materialising those as dicts every 60s would dominate the <100 MB budget
    # for no reason, and would also collide with the 500-row LIMIT in
    # _query_table. SUM() keeps it O(1) in memory regardless of window length.

    async def caddy_sli_window(
        self,
        instance_id: str,
        *,
        minutes: int,
    ) -> tuple[float, float]:
        """Return (weighted_error_volume, request_volume) over the window.

        Each caddy_metrics row holds a per-scrape error_rate and the request
        rate at that moment. Weighting by requests_per_sec means a busy scrape
        counts for more than an idle one — an unweighted mean would let a quiet
        period with one failed request dominate a busy period with none.

        The caller derives the failure ratio as weighted/volume, treating a zero
        volume as "no traffic, no burn".
        """
        async with _connect(self._db_path) as conn:
            cursor = await conn.execute(
                "SELECT COALESCE(SUM(requests_per_sec * error_rate), 0.0), "
                "       COALESCE(SUM(requests_per_sec), 0.0) "
                "FROM caddy_metrics WHERE instance_id = ? AND created_at >= ?",
                (instance_id, self._cutoff_iso(minutes)),
            )
            row = await cursor.fetchone()
        if row is None:
            return (0.0, 0.0)
        return (float(row[0]), float(row[1]))

    async def icmp_sli_window(
        self,
        target_host: str,
        *,
        minutes: int,
    ) -> tuple[int, int]:
        """Return (probes_sent, probes_received) over the window.

        Exact rather than estimated: icmp_probes stores raw counts. This is only
        meaningful because those counters are per-cycle rather than cumulative
        over the process lifetime — summing lifetime totals across rows would
        multiply-count every probe.
        """
        async with _connect(self._db_path) as conn:
            cursor = await conn.execute(
                "SELECT COALESCE(SUM(probes_sent), 0), COALESCE(SUM(probes_received), 0) "
                "FROM icmp_probes WHERE target_host = ? AND created_at >= ?",
                (target_host, self._cutoff_iso(minutes)),
            )
            row = await cursor.fetchone()
        if row is None:
            return (0, 0)
        return (int(row[0]), int(row[1]))

    # ------------------------------------------------------------------
    # Phase 4 alerting — active alert state
    # ------------------------------------------------------------------

    async def get_active_alert(self, alert_key: str) -> dict[str, Any] | None:
        """Return the currently firing alert for this key, if any."""
        async with _connect(self._db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(
                "SELECT * FROM active_alerts WHERE alert_key = ? AND status = 'firing' "
                "ORDER BY triggered_at DESC LIMIT 1",
                (alert_key,),
            )
            row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def insert_active_alert(
        self,
        *,
        alert_key: str,
        slo_name: str,
        entity_id: str,
        severity: str,
        burn_class: str,
        burn_rate: float,
        triggered_at: datetime | None = None,
        notified: bool = False,
    ) -> int:
        ts = (triggered_at or datetime.now(UTC)).isoformat()
        async with _connect(self._db_path) as conn:
            cursor = await conn.execute(
                "INSERT INTO active_alerts "
                "(alert_key,slo_name,entity_id,severity,burn_class,burn_rate,status,"
                "triggered_at,last_notified_at) VALUES (?,?,?,?,?,?, 'firing', ?, ?)",
                (
                    alert_key,
                    slo_name,
                    entity_id,
                    severity,
                    burn_class,
                    burn_rate,
                    ts,
                    ts if notified else None,
                ),
            )
            await conn.commit()
            return int(cursor.lastrowid)

    async def update_alert_burn_rate(self, alert_key: str, burn_rate: float) -> None:
        """Refresh the observed burn rate on a still-firing alert."""
        async with _connect(self._db_path) as conn:
            await conn.execute(
                "UPDATE active_alerts SET burn_rate = ? WHERE alert_key = ? AND status = 'firing'",
                (burn_rate, alert_key),
            )
            await conn.commit()

    async def mark_alert_notified(self, alert_key: str, when: datetime | None = None) -> None:
        async with _connect(self._db_path) as conn:
            await conn.execute(
                "UPDATE active_alerts SET last_notified_at = ? WHERE alert_key = ? AND status = 'firing'",
                ((when or datetime.now(UTC)).isoformat(), alert_key),
            )
            await conn.commit()

    async def resolve_active_alert(self, alert_key: str, when: datetime | None = None) -> bool:
        async with _connect(self._db_path) as conn:
            cursor = await conn.execute(
                "UPDATE active_alerts SET status = 'resolved', resolved_at = ? "
                "WHERE alert_key = ? AND status = 'firing'",
                ((when or datetime.now(UTC)).isoformat(), alert_key),
            )
            await conn.commit()
            resolved = cursor.rowcount > 0
        return resolved

    async def query_active_alerts(
        self,
        *,
        status: str | None = "firing",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        async with _connect(self._db_path) as conn:
            conn.row_factory = aiosqlite.Row
            if status is not None:
                cursor = await conn.execute(
                    "SELECT * FROM active_alerts WHERE status = ? ORDER BY triggered_at DESC LIMIT ?",
                    (status, limit),
                )
            else:
                cursor = await conn.execute(
                    "SELECT * FROM active_alerts ORDER BY triggered_at DESC LIMIT ?",
                    (limit,),
                )
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]
