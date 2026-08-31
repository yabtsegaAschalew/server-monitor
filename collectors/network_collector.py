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
# Written into the outgoing identifier field. Meaningful only on SOCK_RAW; on
# SOCK_DGRAM the kernel overwrites it with the socket's ephemeral port, which is
# why replies are correlated by sequence number instead. See _parse_icmp_reply.
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
    """Parse an ICMP Echo Reply. Returns (ident, seq, send_timestamp) or None.

    On Linux, SOCK_DGRAM delivers the ICMP payload without the IP header.

    CORRELATION: do NOT match the identifier field against our PID. On a
    SOCK_DGRAM/IPPROTO_ICMP socket the kernel *rewrites* the identifier to the
    socket's ephemeral port on send, and the peer echoes that port back — it is
    never the PID. Matching on the PID rejected every real reply, so the engine
    reported 100% packet loss and 0 ms RTT indefinitely.

    The socket is not shared between engines, so the sequence number alone is a
    sufficient key. The observed identifier is returned for diagnostics only.
    """
    if len(data) < 8:
        return None
    icmp_type, _icmp_code, _cksum, recv_ident, recv_seq = struct.unpack("!BBHHH", data[:8])
    if icmp_type != _ICMP_ECHO_REPLY:
        return None
    # Extract the timestamp embedded in the reply payload (bytes 8-16)
    if len(data) >= 16:
        ts = struct.unpack("!d", data[8:16])[0]
    else:
        ts = 0.0
    return recv_ident, recv_seq, ts


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
        # In-flight: seq -> (target, send_time). Keyed by sequence number only;
        # see _parse_icmp_reply for why the identifier field is not usable.
        self._in_flight: dict[int, tuple[IcmpTarget, float]] = {}
        self._seq = 0
        self._sock: socket.socket | None = None
        # Per-target rolling stats
        self._stats: dict[str, _PingStats] = {}

    def _open_socket(self) -> socket.socket | None:
        """Open an ICMP socket, preferring the unprivileged DGRAM form.

        SECURITY: SOCK_DGRAM + IPPROTO_ICMP does not require root. The kernel
        constructs the IP header; we only send and receive ICMP payloads. It
        does require the process GID to fall inside net.ipv4.ping_group_range,
        which is not satisfied by default everywhere.

        When that is unavailable we fall back to SOCK_RAW, which needs
        CAP_NET_RAW. If neither is permitted we return None so ICMP disables
        itself — previously the bare constructor raised, which killed the
        TaskGroup and took the SNMP collector down with it.
        """
        for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
            try:
                sock = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
            except (PermissionError, OSError) as exc:
                logger.warning("ICMP %s socket unavailable: %s", kind.name, exc)
                continue
            sock.setblocking(False)
            logger.info("ICMP engine using %s", kind.name)
            return sock
        logger.error(
            "ICMP disabled: neither DGRAM (needs net.ipv4.ping_group_range to include "
            "this process GID) nor RAW (needs CAP_NET_RAW) sockets are permitted"
        )
        return None

    def _on_readable(self) -> None:
        """Callback registered with loop.add_reader() for async ICMP receive."""
        if self._sock is None:
            return
        try:
            data, _addr = self._sock.recvfrom(_ICMP_DGRAM_MAX_RECV)
        except (BlockingIOError, OSError):
            return
        result = _parse_icmp_reply(data)
        if result is None:
            return
        _ident, seq, _ts = result
        entry = self._in_flight.pop(seq, None)
        if entry is None:
            return
        target, send_time = entry
        rtt_ms = (self._now_fn() - send_time) * 1000.0
        stats = self._stats.setdefault(target.host, _PingStats())
        stats.record(rtt_ms)

    async def _send_probe(self, target: IcmpTarget) -> int | None:
        """Send a single ICMP echo request. Returns the sequence number used."""
        if self._sock is None:
            return None
        self._seq += 1
        seq = self._seq & 0xFFFF
        packet = _build_icmp_echo(seq, target.payload_size)
        send_time = self._now_fn()
        self._in_flight[seq] = (target, send_time)
        self._stats.setdefault(target.host, _PingStats()).record_sent()
        try:
            self._sock.sendto(packet, (target.host, 0))
        except OSError as exc:
            self._in_flight.pop(seq, None)
            logger.warning("ICMP send to %s failed: %s", target.host, exc)
            return None
        return seq

    async def _probe_target(self, target: IcmpTarget) -> IcmpProbeMetric | None:
        """Send count probes to a single target and collect results."""
        stats = self._stats.setdefault(target.host, _PingStats())
        stats.begin_cycle()

        issued: list[int] = []
        for i in range(target.count):
            seq = await self._send_probe(target)
            if seq is not None:
                issued.append(seq)
            if i < target.count - 1:
                await self._sleeper(target.interval_seconds)

        # Wait only on THIS target's outstanding probes. Waiting on the shared
        # _in_flight dict meant one target's unanswered packets stalled every
        # other target's cycle.
        try:
            async with asyncio.timeout(target.timeout_seconds):
                while any(seq in self._in_flight for seq in issued):
                    await asyncio.sleep(0.01)
        except TimeoutError:
            pass

        # Reap this cycle's unanswered probes plus any stragglers from earlier
        # cycles, so _in_flight cannot grow without bound. Loss is derived from
        # sent-vs-received, so expiry needs no separate accounting.
        now = self._now_fn()
        for seq in list(self._in_flight):
            entry = self._in_flight.get(seq)
            if entry is not None and (now - entry[1]) > entry[0].timeout_seconds:
                self._in_flight.pop(seq, None)

        sent = stats.sent
        received = stats.received
        loss = ((sent - received) / sent * 100.0) if sent > 0 else 0.0

        # min/avg/max come from the bounded rolling window (as the model fields
        # document); loss comes from this cycle only.
        rtt_vals = stats.window_rtts()
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
                    # Budget must cover the send phase as well as the reply
                    # wait. A flat timeout+5s starved any target configured with
                    # count * interval greater than 5 seconds, so every one of
                    # its cycles aborted with a spurious timeout.
                    budget = (target.count - 1) * target.interval_seconds + target.timeout_seconds + 5.0
                    try:
                        async with asyncio.timeout(budget):
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
        if self._sock is None:
            # Degrade cleanly instead of raising: an exception here propagates
            # into NetworkCollectorDaemon's TaskGroup and cancels the SNMP
            # collector as collateral damage. But do NOT return: a returned ICMP
            # task empties the TaskGroup and makes the whole network daemon exit,
            # which the supervisor in main.py treats as an early fatal shutdown.
            # Stay alive (honouring stop_event) so the process keeps running.
            try:
                await self._stop_event.wait()
            finally:
                self._in_flight.clear()
            return
        self._loop.add_reader(self._sock.fileno(), self._on_readable)
        try:
            await self._probe_loop(sink)
        finally:
            self._loop.remove_reader(self._sock.fileno())
            self._sock.close()
            self._sock = None
            self._in_flight.clear()

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
    """Per-target ping statistics.

    Send/receive counters are scoped to a single poll cycle so packet_loss_pct
    describes current conditions. They previously accumulated for the whole
    process lifetime, which meant that after a few hours of uptime even a total
    outage barely moved the percentage — the metric could not be alerted on.

    RTTs keep a bounded rolling window (_ICMP_STATS_MAXLEN) across cycles,
    matching the "rolling average" / "in window" semantics the IcmpProbeMetric
    fields document.
    """

    __slots__ = ("_cycle_received", "_cycle_sent", "_rtts")

    def __init__(self) -> None:
        self._cycle_sent = 0
        self._cycle_received = 0
        self._rtts: deque[float] = deque(maxlen=_ICMP_STATS_MAXLEN)

    def begin_cycle(self) -> None:
        """Reset the per-cycle counters. Called once per target per poll."""
        self._cycle_sent = 0
        self._cycle_received = 0

    def record_sent(self) -> None:
        self._cycle_sent += 1

    def record(self, rtt_ms: float) -> None:
        self._cycle_received += 1
        self._rtts.append(rtt_ms)

    @property
    def sent(self) -> int:
        return self._cycle_sent

    @property
    def received(self) -> int:
        return self._cycle_received

    def window_rtts(self) -> list[float]:
        return list(self._rtts)


# ---------------------------------------------------------------------------
# SNMP collector
# ---------------------------------------------------------------------------

# IF-MIB ifEntry. Every column we care about lives under this prefix; the walk
# stops as soon as it leaves, so a device cannot lead us through the rest of
# its MIB tree.
_IF_TABLE_PREFIX = "1.3.6.1.2.1.2.2.1"
_SNMP_MAX_REPETITIONS = 50
# 50 repetitions * 40 rounds = 2000 varbinds, far more than any real ifTable.
# The cap is what stops an agent that never signals end-of-MIB from growing the
# accumulator until the process runs out of memory.
_SNMP_MAX_WALK_ROUNDS = 40


def _in_if_table(var_bind) -> bool:
    """True when a varbind's OID is inside IF-MIB ifEntry."""
    try:
        return str(var_bind[0]).lstrip(".").startswith(_IF_TABLE_PREFIX)
    except (IndexError, TypeError):
        return False


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
    for CPU/memory. The SnmpEngine and per-device transport targets are built
    once and reused across cycles — pysnmp engines carry MIB compilation state
    and are expensive to construct, so rebuilding one per device per cycle was
    sustained allocation churn against a <100 MB budget.
    """

    __slots__ = (
        "_config",
        "_engine",
        "_prev_octets",
        "_prev_ts",
        "_sleeper",
        "_stop_event",
        "_transports",
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
        # Built lazily on first poll and reused for the daemon's lifetime.
        self._engine: object | None = None
        self._transports: dict[str, object] = {}

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
                    _SNMP_MAX_REPETITIONS,
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
                var_bind_table = [vb for vb in first_table if _in_if_table(vb)]

                # Walk on, with three guards the original loop lacked:
                #   1. is_end_of_mib() is evaluated on the CHUNK just returned,
                #      not on the whole accumulated list (which never reports
                #      end-of-MIB once real rows are in it).
                #   2. A hard round cap, so an agent that never signals
                #      end-of-MIB cannot grow this list without bound.
                #   3. A prefix check, so the walk stops at the edge of ifTable
                #      instead of continuing into unrelated MIB subtrees and
                #      parsing them as interface columns.
                last_chunk = list(first_table)
                rounds = 0
                while rounds < _SNMP_MAX_WALK_ROUNDS:
                    rounds += 1
                    if not last_chunk or is_end_of_mib(last_chunk):
                        break
                    if not _in_if_table(last_chunk[-1]):
                        break
                    last_oid_obj = last_chunk[-1][0]
                    _error_indication, _error_status, _error_index, next_table = await bulk_cmd(
                        snmp_engine,
                        auth_data,
                        transport,
                        ContextData(),
                        0,
                        _SNMP_MAX_REPETITIONS,
                        last_oid_obj,
                    )
                    if _error_indication or _error_status or not next_table:
                        break
                    last_chunk = list(next_table)
                    var_bind_table.extend(vb for vb in last_chunk if _in_if_table(vb))
                else:
                    logger.warning(
                        "SNMP ifTable walk for %s hit the %d-round cap; results may be partial",
                        target.device_id,
                        _SNMP_MAX_WALK_ROUNDS,
                    )

            # Parse ifTable rows into per-interface dicts. This runs inside the
            # try: values come from an untrusted device, and a single malformed
            # integer used to escape and abort the whole poll cycle.
            #
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
                try:
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
                except (TypeError, ValueError):
                    # One unusable column must not cost us the whole device.
                    logger.debug("skipping unparsable SNMP value at %s", oid_str)
                    continue
        except TimeoutError:
            logger.warning("SNMP IF-MIB walk timeout for %s", target.device_id)
            return results
        except Exception:
            logger.exception("SNMP IF-MIB walk failed for %s", target.device_id)
            return results

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

            # Model validation can reject an out-of-range counter from a
            # misbehaving device; skip that interface rather than the device.
            try:
                metric = SnmpInterfaceMetric(
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
            except Exception:
                logger.warning(
                    "skipping malformed interface %s on %s",
                    if_index,
                    target.device_id,
                    exc_info=True,
                )
                continue
            results.append(metric)

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

    def _get_engine(self):
        """Return the shared SnmpEngine, building it on first use."""
        if self._engine is None:
            from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

            self._engine = SnmpEngine()
        return self._engine

    async def _get_transport(self, target: SnmpTarget):
        """Return this device's UDP transport target, building it on first use."""
        transport = self._transports.get(target.device_id)
        if transport is None:
            from pysnmp.hlapi.v3arch.asyncio import UdpTransportTarget

            transport = await UdpTransportTarget.create(
                (target.host, target.port),
                timeout=target.timeout_seconds,
            )
            self._transports[target.device_id] = transport
        return transport

    async def _poll_device(self, target: SnmpTarget, sink: Callable[[object], object]) -> None:
        """Poll a single SNMPv3 device for interfaces + host resources."""
        from pysnmp.hlapi.v3arch.asyncio import UsmUserData

        # Engine and transport are reused across cycles; only the per-call
        # credential object is rebuilt. Constructing an SnmpEngine per device
        # per cycle re-did MIB compilation every minute.
        snmp_engine = self._get_engine()

        auth_data_kwargs: dict = {"userName": target.username}
        if target.auth_protocol != SnmpAuthProtocol.NONE:
            auth_data_kwargs["authKey"] = target.resolved_auth_password()
            auth_data_kwargs["authProtocol"] = _map_auth_protocol(target.auth_protocol)
        if target.priv_protocol != SnmpPrivProtocol.NONE:
            auth_data_kwargs["privKey"] = target.resolved_priv_password()
            auth_data_kwargs["privProtocol"] = _map_priv_protocol(target.priv_protocol)
        auth_data = UsmUserData(**auth_data_kwargs)

        transport = await self._get_transport(target)

        if target.poll_interfaces:
            metrics = await self._poll_interfaces(snmp_engine, transport, auth_data, target)
            for metric in metrics:
                await _emit(sink, metric)

        if target.poll_host_resources:
            host_metric = await self._poll_host_resources(snmp_engine, transport, auth_data, target)
            if host_metric is not None:
                await _emit(sink, host_metric)

    def _close_engine(self) -> None:
        """Tear down the shared engine and cached transports."""
        engine, self._engine = self._engine, None
        self._transports.clear()
        if engine is not None:
            try:
                engine.close_dispatcher()
            except Exception:  # noqa: BLE001 - shutdown must not raise
                logger.debug("error closing SNMP dispatcher", exc_info=True)

    async def _poll_loop(self, sink: Callable[[object], object]) -> None:
        """Main loop: periodically poll all SNMP targets."""
        assert self._stop_event is not None
        while not self._stop_event.is_set():
            for target in self._config.snmp_targets:
                if self._stop_event.is_set():
                    break
                try:
                    await self._poll_device(target, sink)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("SNMP poll failed for %s", target.device_id)
            await self._sleeper(self._config.snmp_interval_seconds)

    async def run_forever(self, sink: Callable[[object], object]) -> None:
        self._stop_event = asyncio.Event()
        try:
            await self._poll_loop(sink)
        finally:
            self._close_engine()

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()

    async def aclose(self) -> None:
        await self.stop()
        self._close_engine()

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

    __slots__ = ("_config", "_icmp", "_sleeper", "_snmp", "_tasks", "_tg")

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
        self._tasks: list[asyncio.Task[None]] = []

    @classmethod
    def from_config(cls, config: ConfigManager, **kwargs: object) -> NetworkCollectorDaemon:
        network_config = config.collectors.network
        return cls(network_config, **kwargs)

    async def run_forever(self, sink: Callable[[object], object]) -> None:
        async with asyncio.TaskGroup() as tg:
            self._tg = tg
            self._tasks = []
            if self._config.icmp_targets:
                self._icmp = IcmpPingEngine(self._config, sleeper=self._sleeper)
                self._tasks.append(tg.create_task(self._icmp.run_forever(sink), name="icmp"))

            if self._config.snmp_targets:
                self._snmp = SnmpCollector(self._config, sleeper=self._sleeper)
                self._tasks.append(tg.create_task(self._snmp.run_forever(sink), name="snmp"))

            if not self._config.icmp_targets and not self._config.snmp_targets:
                logger.warning("network collector: no ICMP or SNMP targets configured")

            # Keep the TaskGroup alive for the daemon's lifetime. Without a live
            # task the group exits as soon as the last sub-engine returns (which
            # happens when ICMP cannot open a socket), making the whole network
            # daemon complete and triggering a premature shutdown in main.py.
            self._tasks.append(tg.create_task(self._keep_alive(), name="keeps-alive"))

    @staticmethod
    async def _keep_alive() -> None:
        await asyncio.Event().wait()

    async def stop(self) -> None:
        # Set the stop flags first so a loop between sleeps exits cleanly, then
        # cancel: the loops spend most of their time inside a sleep of up to
        # snmp_interval_seconds (60s by default), and waiting that out on every
        # shutdown is not acceptable.
        if self._icmp is not None:
            await self._icmp.stop()
        if self._snmp is not None:
            await self._snmp.stop()
        for task in self._tasks:
            if not task.done():
                task.cancel()

    async def aclose(self) -> None:
        await self.stop()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks = []
        if self._icmp is not None:
            await self._icmp.aclose()
        if self._snmp is not None:
            await self._snmp.aclose()
        self._tg = None

    async def __aenter__(self) -> NetworkCollectorDaemon:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()
