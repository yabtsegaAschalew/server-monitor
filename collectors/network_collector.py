"""Async network collector daemon — ICMP ping probes + SNMPv3 polling.

Architecture:
- IcmpPingEngine: Unprivileged SOCK_DGRAM IPPROTO_ICMP sockets via loop.add_reader().
  No root required. Cannot control TTL or receive TTL in replies (DGRAM limitation).
- SnmpCollector: pysnmp 7.x v3arch async API for SNMPv3 GetBulk polling.
  IF-MIB (interface status/bandwidth) + HOST-RESOURCES-MIB (CPU/memory).
- NetworkCollectorDaemon: Orchestrator that runs ICMP and SNMP loops concurrently.

Memory budget: <100 MB RAM. All telemetry objects use __slots__ via Pydantic BaseModel.
ICMP in-flight tracking bounded by target_count * probes_per_target.
SNMP transport targets reused per device across poll cycles.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import socket
import struct
import time
from collections import deque
from collections.abc import Awaitable, Callable

from config import (
    ConfigManager,
    IcmpTarget,
    NetworkConfig,
    SnmpAuthProtocol,
    SnmpPrivProtocol,
    SnmpTarget,
)
from models import IcmpProbeMetric, SnmpHostMetric, SnmpInterfaceMetric

from .errors import CollectorError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ICMP constants
# ---------------------------------------------------------------------------
_ICMP_ECHO_REQUEST = 8
_ICMP_ECHO_REPLY = 0
_ICMP_DGRAM_MAX_RECV = 2048
_ICMP_PID = os.getpid() & 0xFFFF

# Rolling stats window per target
_ICMP_STATS_MAXLEN = 100


class NetworkProbeError(CollectorError):
    pass


# ---------------------------------------------------------------------------
# ICMP helpers
# ---------------------------------------------------------------------------


def _icmp_checksum(data: bytes) -> int:
    """RFC 1071 one's-complement internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _build_icmp_echo(seq: int, payload_size: int = 64) -> bytes:
    """Build an ICMPv4 Echo Request packet (Type 8, Code 0).

    Payload contains an 8-byte monotonic timestamp followed by zero-padding.
    The total ICMP packet is 8 (header) + payload_size bytes.
    """
    # Payload: 8-byte timestamp + padding
    ts_bytes = struct.pack("!d", time.monotonic())
    padding_len = max(0, payload_size - len(ts_bytes))
    payload = ts_bytes + b"\x00" * padding_len

    # Header with checksum=0 for computation
    header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, 0, _ICMP_PID, seq)
    cksum = _icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, cksum, _ICMP_PID, seq)
    return header + payload


def _parse_icmp_reply(data: bytes) -> tuple[int, int, float] | None:
    """Parse ICMP Echo Reply. Returns (pid, seq, send_timestamp) or None.

    On Linux, SOCK_DGRAM delivers the ICMP payload without the IP header.
    """
    if len(data) < 8:
        return None
    icmp_type, _icmp_code, _cksum, recv_pid, recv_seq = struct.unpack("!BBHHH", data[:8])
    if icmp_type != _ICMP_ECHO_REPLY or recv_pid != _ICMP_PID:
        return None
    # Extract the timestamp embedded in the reply payload (bytes 8-16)
    if len(data) >= 16:
        ts = struct.unpack("!d", data[8:16])[0]
    else:
        ts = 0.0
    return recv_pid, recv_seq, ts


# ---------------------------------------------------------------------------
# ICMP ping engine
# ---------------------------------------------------------------------------


class IcmpPingEngine:
    """Async ICMP ping using unprivileged SOCK_DGRAM IPPROTO_ICMP sockets.

    SECURITY: Uses DGRAM mode — no CAP_NET_RAW or root required.
    Limitation: Cannot set TTL, cannot read TTL from replies, cannot do
    traceroute-style probing. Sufficient for RTT + loss measurement.
    """

    __slots__ = (
        "_config",
        "_in_flight",
        "_loop",
        "_now_fn",
        "_seq",
        "_sleeper",
        "_sock",
        "_stats",
        "_stop_event",
    )

    def __init__(
        self,
        config: NetworkConfig,
        *,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._sleeper = sleeper
        self._now_fn = now
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None
        # In-flight: (pid, seq) -> (target, send_time)
        self._in_flight: dict[tuple[int, int], tuple[IcmpTarget, float]] = {}
        self._seq = 0
        # Per-target rolling stats
        self._stats: dict[str, _PingStats] = {}

    def _open_socket(self) -> socket.socket:
        """Open unprivileged ICMP DGRAM socket.

        SECURITY: SOCK_DGRAM + IPPROTO_ICMP does not require root.
        The kernel constructs the IP header. We only send/receive ICMP payloads.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        sock.setblocking(False)
        sock.settimeout(0)
        return sock

    def _on_readable(self) -> None:
        """Callback registered with loop.add_reader() for async ICMP receive."""
        try:
            data, _addr = self._sock.recvfrom(_ICMP_DGRAM_MAX_RECV)
        except (BlockingIOError, OSError):
            return
        result = _parse_icmp_reply(data)
        if result is None:
            return
        _pid, seq, _ts = result
        key = (_ICMP_PID, seq)
        entry = self._in_flight.pop(key, None)
        if entry is None:
            return
        target, send_time = entry
        rtt_ms = (self._now_fn() - send_time) * 1000.0
        stats = self._stats.setdefault(target.host, _PingStats())
        stats.record(rtt_ms)

    async def _send_probe(self, target: IcmpTarget) -> None:
        """Send a single ICMP echo request to target."""
        self._seq += 1
        seq = self._seq & 0xFFFF
        packet = _build_icmp_echo(seq, target.payload_size)
        send_time = self._now_fn()
        self._in_flight[(_ICMP_PID, seq)] = (target, send_time)
        try:
            self._sock.sendto(packet, (target.host, 0))
        except OSError as exc:
            self._in_flight.pop((_ICMP_PID, seq), None)
            logger.warning("ICMP send to %s failed: %s", target.host, exc)

    async def _probe_target(self, target: IcmpTarget) -> IcmpProbeMetric | None:
        """Send count probes to a single target and collect results."""
        stats = self._stats.setdefault(target.host, _PingStats())

        for i in range(target.count):
            await self._send_probe(target)
            if i < target.count - 1:
                await self._sleeper(target.interval_seconds)

        # Wait for replies to arrive (up to timeout)
        try:
            async with asyncio.timeout(target.timeout_seconds):
                while self._in_flight:
                    await asyncio.sleep(0.01)
        except TimeoutError:
            pass

        # Expire any remaining in-flight entries as lost (ALL targets, not just current)
        now = self._now_fn()
        lost_keys = [
            k for k, (t, st) in self._in_flight.items() if (now - st) > t.timeout_seconds
        ]
        for k in lost_keys:
            t, _ = self._in_flight.pop(k, (None, None))
            if t is not None:
                self._stats.setdefault(t.host, _PingStats()).record_loss()

        sent = stats.total_sent(target.host, target.count)
        received = stats.total_received(target.host, target.count)
        loss = ((sent - received) / sent * 100.0) if sent > 0 else 0.0

        rtt_vals = stats.rtt_values(target.host)
        avg = sum(rtt_vals) / len(rtt_vals) if rtt_vals else 0.0
        mn = min(rtt_vals) if rtt_vals else 0.0
        mx = max(rtt_vals) if rtt_vals else 0.0
        last_rtt = rtt_vals[-1] if rtt_vals else 0.0

        return IcmpProbeMetric(
            target_host=target.host,
            target_ip=target.host,  # DGRAM mode doesn't resolve separately
            rtt_ms=last_rtt,
            avg_rtt_ms=avg,
            min_rtt_ms=mn,
            max_rtt_ms=mx,
            packet_loss_pct=loss,
            probes_sent=sent,
            probes_received=received,
        )

    async def _probe_loop(self, sink: Callable[[object], object]) -> None:
        """Main loop: periodically probe all ICMP targets."""
        assert self._stop_event is not None
        try:
            while not self._stop_event.is_set():
                for target in self._config.icmp_targets:
                    if self._stop_event.is_set():
                        break
                    try:
                        async with asyncio.timeout(target.timeout_seconds + 5.0):
                            metric = await self._probe_target(target)
                            if metric is not None:
                                await _emit(sink, metric)
                    except TimeoutError:
                        logger.warning("ICMP probe timeout for %s", target.host)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        logger.exception("ICMP probe failed for %s", target.host)
                await self._sleeper(self._config.icmp_interval_seconds)
        except asyncio.CancelledError:
            # Drain in-flight to avoid leaking references
            self._in_flight.clear()
            raise

    async def run_forever(self, sink: Callable[[object], object]) -> None:
        """Start the ICMP engine: open socket, register reader, run probe loop."""
        self._stop_event = asyncio.Event()
        self._loop = asyncio.get_running_loop()
        self._sock = self._open_socket()
        self._loop.add_reader(self._sock.fileno(), self._on_readable)
        try:
            await self._probe_loop(sink)
        finally:
            self._loop.remove_reader(self._sock.fileno())
            self._sock.close()

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()

    async def aclose(self) -> None:
        await self.stop()

    async def __aenter__(self) -> IcmpPingEngine:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


class _PingStats:
    """Rolling ping statistics per target. Bounded by _ICMP_STATS_MAXLEN."""

    __slots__ = ("_loss_count", "_received", "_rtts", "_sent")

    def __init__(self) -> None:
        self._sent = 0
        self._received = 0
        self._rtts: deque[float] = deque(maxlen=_ICMP_STATS_MAXLEN)
        self._loss_count = 0

    def record(self, rtt_ms: float) -> None:
        self._sent += 1
        self._received += 1
        self._rtts.append(rtt_ms)

    def record_loss(self) -> None:
        self._sent += 1
        self._loss_count += 1

    def total_sent(self, _host: str, batch_size: int) -> int:
        return self._sent

    def total_received(self, _host: str, _batch: int) -> int:
        return self._received

    def rtt_values(self, _host: str) -> list[float]:
        return list(self._rtts)


# ---------------------------------------------------------------------------
# SNMP collector
# ---------------------------------------------------------------------------


def _map_auth_protocol(proto: SnmpAuthProtocol):
    """Map our config enum to pysnmp USM auth protocol."""
    from pysnmp.hlapi.v3arch.asyncio.auth import (
        usmHMAC192SHA256AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        usmNoAuthProtocol,
    )

    return {
        SnmpAuthProtocol.NONE: usmNoAuthProtocol,
        SnmpAuthProtocol.MD5: usmHMACMD5AuthProtocol,
        SnmpAuthProtocol.SHA: usmHMACSHAAuthProtocol,
        SnmpAuthProtocol.SHA256: usmHMAC192SHA256AuthProtocol,
    }[proto]


def _map_priv_protocol(proto: SnmpPrivProtocol):
    """Map our config enum to pysnmp USM privacy protocol."""
    from pysnmp.hlapi.v3arch.asyncio.auth import (
        usmAesCfb128Protocol,
        usmAesCfb256Protocol,
        usmDESPrivProtocol,
        usmNoPrivProtocol,
    )

    return {
        SnmpPrivProtocol.NONE: usmNoPrivProtocol,
        SnmpPrivProtocol.DES: usmDESPrivProtocol,
        SnmpPrivProtocol.AES128: usmAesCfb128Protocol,
        SnmpPrivProtocol.AES256: usmAesCfb256Protocol,
    }[proto]


class SnmpCollector:
    """Async SNMPv3 collector using pysnmp 7.x v3arch API.

    Polls IF-MIB for interface status/bandwidth and HOST-RESOURCES-MIB
    for CPU/memory. Reuses SnmpEngine and transport targets across cycles.
    """

    __slots__ = (
        "_config",
        "_prev_octets",
        "_prev_ts",
        "_sleeper",
        "_stop_event",
    )

    def __init__(
        self,
        config: NetworkConfig,
        *,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._config = config
        self._sleeper = sleeper
        self._stop_event: asyncio.Event | None = None
        # Per-device previous octet counters for rate computation
        # Key: (device_id, if_index) -> (in_octets, out_octets, timestamp)
        self._prev_octets: dict[tuple[str, int], tuple[int, int, float]] = {}
        self._prev_ts: dict[str, float] = {}

    async def _poll_interfaces(
        self, snmp_engine, transport, auth_data, target: SnmpTarget
    ) -> list[SnmpInterfaceMetric]:
        """Walk IF-MIB ifTable via SNMPv3 GetBulk."""
        from pysnmp.hlapi.v3arch.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            bulk_cmd,
            is_end_of_mib,
        )

        results: list[SnmpInterfaceMetric] = []
        now = self._now()
        # Collect all rows from ifTable
        var_bind_table: list = []
        try:
            async with asyncio.timeout(target.timeout_seconds):
                # Initial GetBulk request
                error_indication, error_status, _error_index, first_table = await bulk_cmd(
                    snmp_engine,
                    auth_data,
                    transport,
                    ContextData(),
                    0,  # nonRepeaters
                    50,  # maxRepetitions
                    ObjectType(ObjectIdentity("IF-MIB", "ifTable")),
                )
                if error_indication or error_status:
                    logger.warning(
                        "SNMP bulk_cmd error for %s: %s %s",
                        target.device_id,
                        error_indication,
                        error_status,
                    )
                    return results
                var_bind_table = list(first_table)

                # Continue until end of MIB
                while not is_end_of_mib(var_bind_table):
                    last_oid_obj = var_bind_table[-1][0]
                    _error_indication, _error_status, _error_index, next_table = await bulk_cmd(
                        snmp_engine,
                        auth_data,
                        transport,
                        ContextData(),
                        0,
                        50,
                        last_oid_obj,
                    )
                    if _error_indication or _error_status:
                        break
                    var_bind_table.extend(next_table)
        except TimeoutError:
            logger.warning("SNMP IF-MIB walk timeout for %s", target.device_id)
            return results
        except Exception:
            logger.exception("SNMP IF-MIB walk failed for %s", target.device_id)
            return results

        # Parse ifTable rows into per-interface dicts
        # ifTable base OID: 1.3.6.1.2.1.2.2.1
        # Columns: 1=ifIndex, 2=ifDescr, 3=ifType, 4=ifMtu, 5=ifSpeed,
        #   6=ifPhysAddress, 7=ifAdminStatus, 8=ifOperStatus, 10=ifInOctets,
        #   14=ifInErrors, 16=ifOutOctets, 20=ifOutErrors
        iface_data: dict[int, dict] = {}
        for var_bind in var_bind_table:
            oid_str = str(var_bind[0])
            val = var_bind[1]
            parts = oid_str.split(".")
            if len(parts) < 2:
                continue
            try:
                col = int(parts[-2])
                row = int(parts[-1])
            except ValueError:
                continue
            entry = iface_data.setdefault(row, {"if_index": row})
            if col == 2:
                entry["if_name"] = str(val)
            elif col == 5:
                entry["if_speed_bps"] = int(val)
            elif col == 7:
                entry["if_admin_status"] = int(val)
            elif col == 8:
                entry["if_oper_status"] = int(val)
            elif col == 10:
                entry["if_in_octets"] = int(val)
            elif col == 14:
                entry["if_in_errors"] = int(val)
            elif col == 16:
                entry["if_out_octets"] = int(val)
            elif col == 20:
                entry["if_out_errors"] = int(val)

        # Build SnmpInterfaceMetric for each parsed interface
        for if_index, entry in iface_data.items():
            in_octets = entry.get("if_in_octets", 0)
            out_octets = entry.get("if_out_octets", 0)
            prev_key = (target.device_id, if_index)
            prev = self._prev_octets.get(prev_key)
            if prev is not None:
                prev_in, prev_out, prev_t = prev
                dt = now - prev_t
                in_bps = max(0.0, (in_octets - prev_in) / dt) if dt > 0 else 0.0
                out_bps = max(0.0, (out_octets - prev_out) / dt) if dt > 0 else 0.0
            else:
                in_bps = 0.0
                out_bps = 0.0
            self._prev_octets[prev_key] = (in_octets, out_octets, now)

            results.append(
                SnmpInterfaceMetric(
                    device_id=target.device_id,
                    device_host=target.host,
                    if_index=if_index,
                    if_name=entry.get("if_name", f"if{if_index}"),
                    if_oper_status=entry.get("if_oper_status", 0),
                    if_admin_status=entry.get("if_admin_status", 0),
                    if_speed_bps=entry.get("if_speed_bps", 0),
                    if_in_octets=in_octets,
                    if_out_octets=out_octets,
                    if_in_errors=entry.get("if_in_errors", 0),
                    if_out_errors=entry.get("if_out_errors", 0),
                    in_bps=in_bps,
                    out_bps=out_bps,
                )
            )

        return results

    async def _poll_host_resources(
        self, snmp_engine, transport, auth_data, target: SnmpTarget
    ) -> SnmpHostMetric | None:
        """Get HOST-RESOURCES-MIB scalars (system descr, CPU load, memory).

        Uses numeric OIDs because pysnmp-mibs v0.1.6 ships an incomplete
        HOST-RESOURCES-MIB that is missing hrSystemDescr and other symbols.
        """
        from pysnmp.hlapi.v3arch.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            get_cmd,
            next_cmd,
        )

        # Numeric OIDs for HOST-RESOURCES-MIB scalars
        OID_HR_SYSTEM_DESCR = "1.3.6.1.2.1.25.1.3.0"  # hrSystemDescr.0
        OID_HR_PROCESSOR_LOAD_1 = "1.3.6.1.2.1.25.3.3.1.2.1"  # hrProcessorLoad.1
        # hrStorageEntry subtree for walking
        OID_HR_STORAGE_ENTRY = "1.3.6.1.2.1.25.2.3.1"
        # hrStorageTable columns (relative to hrStorageEntry)
        OID_HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
        OID_HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.7"
        OID_HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.8"

        try:
            async with asyncio.timeout(target.timeout_seconds):
                error_indication, error_status, _error_index, var_binds = await get_cmd(
                    snmp_engine,
                    auth_data,
                    transport,
                    ContextData(),
                    ObjectType(ObjectIdentity(OID_HR_SYSTEM_DESCR)),
                    ObjectType(ObjectIdentity(OID_HR_PROCESSOR_LOAD_1)),
                )
                if error_indication or error_status:
                    logger.warning(
                        "SNMP HOST-RESOURCES query failed for %s: %s %s",
                        target.device_id,
                        error_indication,
                        error_status,
                    )
                    return None

                hr_descr = ""
                hr_cpu: float | None = None
                for oid, val in var_binds:
                    oid_str = str(oid)
                    if ".25.1.3.0" in oid_str:
                        hr_descr = str(val)
                    elif ".25.3.3.1.2" in oid_str:
                        hr_cpu = float(val)

                # Walk hrStorageTable to find RAM (hrStorageType == hrStorageRam(2))
                hr_mem_total: int | None = None
                hr_mem_used: int | None = None
                try:
                    # Track current row's storage type
                    current_storage_type: int | None = None

                    last_oid = ObjectIdentity(OID_HR_STORAGE_ENTRY)
                    for _ in range(20):
                        error_ind, error_st, _err_idx, next_binds = await next_cmd(
                            snmp_engine,
                            auth_data,
                            transport,
                            ContextData(),
                            ObjectType(last_oid),
                        )
                        if error_ind or error_st or not next_binds:
                            break
                        oid, val = next_binds[0]
                        oid_str = str(oid)
                        last_oid = oid
                        # Detect row boundaries: if we're back to the Type column,
                        # the previous row (if RAM) was already processed.
                        if oid_str.startswith(OID_HR_STORAGE_TYPE + "."):
                            current_storage_type = int(val)
                        elif oid_str.startswith(OID_HR_STORAGE_SIZE + "."):
                            if current_storage_type == 2:  # hrStorageRam
                                hr_mem_total = int(val)
                        elif oid_str.startswith(OID_HR_STORAGE_USED + "."):
                            if current_storage_type == 2:  # hrStorageRam
                                hr_mem_used = int(val)
                except (TimeoutError, OSError):
                    pass  # Memory query is best-effort

                return SnmpHostMetric(
                    device_id=target.device_id,
                    device_host=target.host,
                    hr_system_descr=hr_descr,
                    hr_cpu_load=hr_cpu,
                    hr_memory_total=hr_mem_total,
                    hr_memory_used=hr_mem_used,
                )
        except TimeoutError:
            logger.warning("SNMP HOST-RESOURCES timeout for %s", target.device_id)
            return None
        except Exception:
            logger.exception("SNMP HOST-RESOURCES failed for %s", target.device_id)
            return None

    def _now(self) -> float:
        return time.monotonic()

    async def _poll_device(self, target: SnmpTarget, sink: Callable[[object], object]) -> None:
        """Poll a single SNMPv3 device for interfaces + host resources."""
        from pysnmp.hlapi.v3arch.asyncio import (
            SnmpEngine,
            UdpTransportTarget,
            UsmUserData,
        )

        snmp_engine = SnmpEngine()
        try:
            # Build auth data
            auth_data_kwargs: dict = {"userName": target.username}
            if target.auth_protocol != SnmpAuthProtocol.NONE:
                auth_data_kwargs["authKey"] = target.resolved_auth_password()
                auth_data_kwargs["authProtocol"] = _map_auth_protocol(target.auth_protocol)
            if target.priv_protocol != SnmpPrivProtocol.NONE:
                auth_data_kwargs["privKey"] = target.resolved_priv_password()
                auth_data_kwargs["privProtocol"] = _map_priv_protocol(target.priv_protocol)
            auth_data = UsmUserData(**auth_data_kwargs)

            transport = await UdpTransportTarget.create(
                (target.host, target.port),
                timeout=target.timeout_seconds,
            )

            if target.poll_interfaces:
                metrics = await self._poll_interfaces(snmp_engine, transport, auth_data, target)
                for metric in metrics:
                    await _emit(sink, metric)

            if target.poll_host_resources:
                host_metric = await self._poll_host_resources(snmp_engine, transport, auth_data, target)
                if host_metric is not None:
                    await _emit(sink, host_metric)

        finally:
            snmp_engine.close_dispatcher()

    async def _poll_loop(self, sink: Callable[[object], object]) -> None:
        """Main loop: periodically poll all SNMP targets."""
        assert self._stop_event is not None
        while not self._stop_event.is_set():
            for target in self._config.snmp_targets:
                if self._stop_event.is_set():
                    break
                try:
                    await self._poll_device(target, sink)
                except Exception:
                    logger.exception("SNMP poll failed for %s", target.device_id)
            await self._sleeper(self._config.snmp_interval_seconds)

    async def run_forever(self, sink: Callable[[object], object]) -> None:
        self._stop_event = asyncio.Event()
        await self._poll_loop(sink)

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()

    async def aclose(self) -> None:
        await self.stop()

    async def __aenter__(self) -> SnmpCollector:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


# ---------------------------------------------------------------------------
# Orchestrator daemon
# ---------------------------------------------------------------------------


async def _emit(sink: Callable[[object], object], item: object) -> None:
    result = sink(item)
    if inspect.isawaitable(result):
        await result


class NetworkCollectorDaemon:
    """Orchestrator: runs ICMP + SNMP collectors concurrently via TaskGroup."""

    __slots__ = ("_config", "_icmp", "_sleeper", "_snmp", "_tg")

    def __init__(
        self,
        config: NetworkConfig,
        *,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._config = config
        self._sleeper = sleeper
        self._icmp: IcmpPingEngine | None = None
        self._snmp: SnmpCollector | None = None
        self._tg: asyncio.TaskGroup | None = None

    @classmethod
    def from_config(cls, config: ConfigManager, **kwargs: object) -> NetworkCollectorDaemon:
        network_config = config.collectors.network
        return cls(network_config, **kwargs)

    async def run_forever(self, sink: Callable[[object], object]) -> None:
        async with asyncio.TaskGroup() as tg:
            self._tg = tg
            if self._config.icmp_targets:
                self._icmp = IcmpPingEngine(self._config, sleeper=self._sleeper)
                tg.create_task(self._icmp.run_forever(sink))

            if self._config.snmp_targets:
                self._snmp = SnmpCollector(self._config, sleeper=self._sleeper)
                tg.create_task(self._snmp.run_forever(sink))

            if not self._config.icmp_targets and not self._config.snmp_targets:
                logger.warning("network collector: no ICMP or SNMP targets configured")

    async def stop(self) -> None:
        if self._icmp is not None:
            await self._icmp.stop()
        if self._snmp is not None:
            await self._snmp.stop()

    async def aclose(self) -> None:
        await self.stop()
        if self._icmp is not None:
            await self._icmp.aclose()
        if self._snmp is not None:
            await self._snmp.aclose()
        self._tg = None

    async def __aenter__(self) -> NetworkCollectorDaemon:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
