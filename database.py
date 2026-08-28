from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import aiosqlite

from config import DatabaseConfig
from models import CaddyMetric, DockerEvent, HostMetric, IcmpProbeMetric, SnmpHostMetric, SnmpInterfaceMetric

logger = logging.getLogger(__name__)

_BUSY_TIMEOUT_MS = 5000

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
            await self._flush_batch(batch)
        await self._drain_remaining()

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
                await self._flush_batch(batch)
                batch.clear()
        if batch:
            await self._flush_batch(batch)

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
            if result is not None:
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
        async with aiosqlite.connect(self._db_path) as conn:
            total = 0
            for table in tables:
                while True:
                    cursor = await conn.execute(
                        f"DELETE FROM {table} WHERE created_at < ? LIMIT ?",
                        (cutoff, CHUNK_SIZE),
                    )
                    deleted = cursor.rowcount
                    total += deleted
                    await conn.commit()
                    if deleted < CHUNK_SIZE:
                        break
                    await asyncio.sleep(0)
            if total > 0:
                logger.info("pruned %d total rows across %d tables", total, len(tables))


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
        self._tasks = [
            asyncio.create_task(self._worker.run(self._stop_event)),
            asyncio.create_task(self._pruner.run(self._stop_event)),
        ]

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        await self._worker.close()

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
        async with aiosqlite.connect(self._db_path) as conn:
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

    async def query_recent_probes(
        self,
        endpoint_id: str,
        *,
        minutes: int = 60,
    ) -> list[dict[str, Any]]:
        return await self._query_table(
            "network_probes",
            where="endpoint_id = ? AND created_at >= ?",
            params=(endpoint_id, self._cutoff_iso(minutes)),
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
        async with aiosqlite.connect(self._db_path) as conn:
            await conn.execute(
                "INSERT INTO ai_diagnostic_logs (source,severity,message,details,created_at) VALUES (?,?,?,?,?)",
                (source, severity, message, details, _now_iso()),
            )
            await conn.commit()
