from __future__ import annotations

import struct

from collectors.network_collector import (
    IcmpPingEngine,
    NetworkCollectorDaemon,
    SnmpCollector,
    _build_icmp_echo,
    _icmp_checksum,
    _parse_icmp_reply,
    _PingStats,
)
from config import (
    IcmpTarget,
    NetworkConfig,
    SnmpAuthProtocol,
    SnmpPrivProtocol,
    SnmpTarget,
)
from models import IcmpProbeMetric, SnmpHostMetric, SnmpInterfaceMetric

# ---------------------------------------------------------------------------
# ICMP helpers
# ---------------------------------------------------------------------------


class TestIcmpChecksum:
    def test_empty_data(self) -> None:
        assert _icmp_checksum(b"") == 0xFFFF

    def test_known_value(self) -> None:
        data = b"\x00\x00\x00\x00"
        cksum = _icmp_checksum(data)
        assert 0 <= cksum <= 0xFFFF

    def test_odd_length_padded(self) -> None:
        result = _icmp_checksum(b"\x01\x02\x03")
        assert 0 <= result <= 0xFFFF

    def test_roundtrip_consistency(self) -> None:
        data = b"\x08\x00" + b"\x00\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00" * 32
        cksum = _icmp_checksum(data)
        assert cksum != 0
        full = data[:2] + struct.pack("!H", cksum) + data[4:]
        assert _icmp_checksum(full) == 0


class TestBuildIcmpEcho:
    def test_packet_length(self) -> None:
        pkt = _build_icmp_echo(seq=1, payload_size=64)
        assert len(pkt) == 72

    def test_type_and_code(self) -> None:
        pkt = _build_icmp_echo(seq=1)
        icmp_type = pkt[0]
        icmp_code = pkt[1]
        assert icmp_type == 8
        assert icmp_code == 0

    def test_pid_matches(self) -> None:
        import os

        pkt = _build_icmp_echo(seq=42)
        pid = struct.unpack("!H", pkt[4:6])[0]
        assert pid == (os.getpid() & 0xFFFF)

    def test_seq_matches(self) -> None:
        pkt = _build_icmp_echo(seq=99)
        seq = struct.unpack("!H", pkt[6:8])[0]
        assert seq == 99

    def test_checksum_valid(self) -> None:
        pkt = _build_icmp_echo(seq=0)
        assert _icmp_checksum(pkt) == 0


class TestParseIcmpReply:
    def test_returns_none_for_too_short(self) -> None:
        assert _parse_icmp_reply(b"\x00" * 4) is None

    def test_returns_none_for_non_echo_reply(self) -> None:
        header = struct.pack("!BBHHH", 3, 0, 0, 1234, 1)
        assert _parse_icmp_reply(header + b"\x00" * 8) is None

    def test_accepts_reply_whose_identifier_is_not_our_pid(self) -> None:
        """Regression: the identifier field must NOT be matched against the PID.

        On a SOCK_DGRAM/IPPROTO_ICMP socket the kernel rewrites the identifier
        to the socket's ephemeral port, so a real reply never carries our PID.
        Rejecting those replies made the engine report 100% loss forever.
        """
        import os

        kernel_chosen_ident = (os.getpid() + 1) & 0xFFFF
        header = struct.pack("!BBHHH", 0, 0, 0, kernel_chosen_ident, 1)
        result = _parse_icmp_reply(header + b"\x00" * 8)
        assert result is not None
        ident, seq, _ts = result
        assert ident == kernel_chosen_ident
        assert seq == 1

    def test_valid_reply(self) -> None:
        ts = 12345.678
        payload = struct.pack("!d", ts)
        ident = 4242  # an arbitrary kernel-assigned identifier
        header = struct.pack("!BBHHH", 0, 0, 0, ident, 7)
        result = _parse_icmp_reply(header + payload)
        assert result is not None
        parsed_ident, seq, parsed_ts = result
        assert parsed_ident == ident
        assert seq == 7
        assert abs(parsed_ts - ts) < 0.001


# ---------------------------------------------------------------------------
# Ping stats
# ---------------------------------------------------------------------------


class TestPingStats:
    def test_counters_are_per_cycle(self) -> None:
        stats = _PingStats()
        stats.begin_cycle()
        stats.record_sent()
        stats.record_sent()
        stats.record_sent()
        stats.record(10.0)
        stats.record(20.0)
        assert stats.sent == 3
        assert stats.received == 2
        assert stats.window_rtts() == [10.0, 20.0]

    def test_begin_cycle_resets_counters_but_keeps_rtt_window(self) -> None:
        """Loss must describe the current cycle, not the whole process run."""
        stats = _PingStats()
        stats.begin_cycle()
        stats.record_sent()
        stats.record(10.0)
        assert stats.sent == 1

        stats.begin_cycle()
        assert stats.sent == 0
        assert stats.received == 0
        # RTTs are a rolling window across cycles, as the model fields document.
        assert stats.window_rtts() == [10.0]

    def test_empty_stats(self) -> None:
        stats = _PingStats()
        assert stats.sent == 0
        assert stats.received == 0
        assert stats.window_rtts() == []


# ---------------------------------------------------------------------------
# IcmpPingEngine
# ---------------------------------------------------------------------------


class TestIcmpPingEngine:
    def _make_config(self) -> NetworkConfig:
        return NetworkConfig(
            icmp_targets=[IcmpTarget(host="127.0.0.1", count=2, timeout_seconds=1.0)],
            icmp_interval=10,
            icmp_probes=2,
            icmp_timeout=1.0,
        )

    async def test_stop_sets_event(self) -> None:
        engine = IcmpPingEngine(self._make_config())
        # stop() is a no-op before run_forever() - event doesn't exist yet
        await engine.stop()
        assert engine._stop_event is None

    async def test_context_manager(self) -> None:
        engine = IcmpPingEngine(self._make_config())
        async with engine:
            pass

    async def test_build_and_parse_roundtrip(self) -> None:
        seq = 42
        pkt = _build_icmp_echo(seq)
        ts_bytes = pkt[8:16]
        # A real kernel rewrites the identifier on a DGRAM socket, so the reply
        # comes back with an identifier we never chose. Correlation is by seq.
        reply_header = struct.pack("!BBHHH", 0, 0, 0, 51234, seq)
        result = _parse_icmp_reply(reply_header + ts_bytes)
        assert result is not None
        assert result[1] == seq

    async def test_on_readable_matches_reply_by_sequence(self) -> None:
        """The full receive path: an in-flight probe is resolved by seq alone."""
        engine = IcmpPingEngine(self._make_config())
        target = IcmpTarget(host="127.0.0.1", count=1, timeout_seconds=1.0)

        clock = iter([100.0, 100.25])
        engine._now_fn = lambda: next(clock)
        engine._in_flight[7] = (target, 100.0)

        class _FakeSock:
            def recvfrom(self, _n: int) -> tuple[bytes, tuple[str, int]]:
                # Identifier deliberately unrelated to our PID.
                header = struct.pack("!BBHHH", 0, 0, 0, 9999, 7)
                return header + struct.pack("!d", 0.0), ("127.0.0.1", 0)

        engine._sock = _FakeSock()
        engine._stats["127.0.0.1"] = _PingStats()
        engine._stats["127.0.0.1"].begin_cycle()

        engine._on_readable()

        assert 7 not in engine._in_flight
        assert engine._stats["127.0.0.1"].received == 1

    def test_open_socket_returns_none_when_no_socket_type_permitted(self, monkeypatch) -> None:
        """ICMP must disable itself rather than raise.

        Raising here propagated into NetworkCollectorDaemon's TaskGroup and
        cancelled the SNMP collector as collateral damage.
        """
        import socket as socket_mod

        def _denied(*_args, **_kwargs):
            raise PermissionError("operation not permitted")

        monkeypatch.setattr(socket_mod, "socket", _denied)
        engine = IcmpPingEngine(self._make_config())
        assert engine._open_socket() is None


# ---------------------------------------------------------------------------
# SnmpCollector
# ---------------------------------------------------------------------------


class TestSnmpCollector:
    async def test_stop_sets_event(self) -> None:
        cfg = NetworkConfig()
        collector = SnmpCollector(cfg)
        assert collector._stop_event is None
        await collector.stop()
        assert collector._stop_event is None

    async def test_context_manager(self) -> None:
        cfg = NetworkConfig()
        async with SnmpCollector(cfg) as collector:
            assert collector._stop_event is None


# ---------------------------------------------------------------------------
# Config models
# ---------------------------------------------------------------------------


class TestNetworkConfig:
    def test_defaults(self) -> None:
        cfg = NetworkConfig()
        assert cfg.icmp_interval_seconds == 5.0
        assert cfg.snmp_interval_seconds == 60.0
        assert cfg.icmp_targets == []
        assert cfg.snmp_targets == []

    def test_icmp_target_defaults(self) -> None:
        t = IcmpTarget(host="10.0.0.1")
        assert t.count == 4
        assert t.payload_size == 64
        assert t.timeout_seconds == 5.0

    def test_snmp_target_defaults(self) -> None:
        t = SnmpTarget(host="10.0.0.2", device_id="r1")
        assert t.port == 161
        assert t.auth_protocol == SnmpAuthProtocol.NONE
        assert t.priv_protocol == SnmpPrivProtocol.NONE
        assert t.poll_interfaces is True
        assert t.poll_host_resources is True


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_icmp_probe_metric(self) -> None:
        m = IcmpProbeMetric(
            target_host="8.8.8.8",
            target_ip="8.8.8.8",
            rtt_ms=12.3,
            avg_rtt_ms=11.0,
            min_rtt_ms=10.0,
            max_rtt_ms=13.0,
            packet_loss_pct=0.0,
            probes_sent=5,
            probes_received=5,
        )
        assert m.target_host == "8.8.8.8"
        assert m.rtt_ms == 12.3

    def test_snmp_interface_metric(self) -> None:
        m = SnmpInterfaceMetric(
            device_id="r1",
            device_host="10.0.0.1",
            if_index=1,
            if_name="eth0",
            if_oper_status=1,
            if_admin_status=1,
            if_speed_bps=1000000000,
            if_in_octets=0,
            if_out_octets=0,
            if_in_errors=0,
            if_out_errors=0,
            in_bps=0.0,
            out_bps=0.0,
        )
        assert m.if_name == "eth0"
        assert m.if_speed_bps == 1_000_000_000

    def test_snmp_host_metric(self) -> None:
        m = SnmpHostMetric(
            device_id="r1",
            device_host="10.0.0.1",
            hr_system_descr="Linux 6.1",
            hr_cpu_load=2.5,
            hr_memory_total=8_000_000_000,
            hr_memory_used=4_000_000_000,
        )
        assert m.hr_system_descr == "Linux 6.1"
        assert m.hr_memory_used == 4_000_000_000


# ---------------------------------------------------------------------------
# Database integration (to_row)
# ---------------------------------------------------------------------------


class TestDatabaseToRow:
    def test_icmp_metric(self) -> None:
        from database import _WriterWorker
        from models import IcmpProbeMetric

        m = IcmpProbeMetric(
            target_host="8.8.8.8",
            target_ip="8.8.8.8",
            rtt_ms=10.0,
            avg_rtt_ms=10.0,
            min_rtt_ms=10.0,
            max_rtt_ms=10.0,
            packet_loss_pct=0.0,
            probes_sent=1,
            probes_received=1,
        )
        result = _WriterWorker._to_row(m)
        assert result is not None
        table, values = result
        assert table == "icmp"
        assert values[0] == "8.8.8.8"

    def test_snmp_interface_metric(self) -> None:
        from database import _WriterWorker

        m = SnmpInterfaceMetric(
            device_id="r1",
            device_host="10.0.0.1",
            if_index=1,
            if_name="eth0",
            if_oper_status=1,
            if_admin_status=1,
            if_speed_bps=1000000000,
            if_in_octets=0,
            if_out_octets=0,
            if_in_errors=0,
            if_out_errors=0,
            in_bps=0.0,
            out_bps=0.0,
        )
        result = _WriterWorker._to_row(m)
        assert result is not None
        table, values = result
        assert table == "snmp_if"
        assert values[1] == "10.0.0.1"

    def test_snmp_host_metric(self) -> None:
        from database import _WriterWorker

        m = SnmpHostMetric(
            device_id="r1",
            device_host="10.0.0.1",
        )
        result = _WriterWorker._to_row(m)
        assert result is not None
        table, values = result
        assert table == "snmp_host"
        assert values[0] == "r1"


# ---------------------------------------------------------------------------
# NetworkCollectorDaemon
# ---------------------------------------------------------------------------


class TestNetworkCollectorDaemon:
    async def test_stop(self) -> None:
        cfg = NetworkConfig()
        daemon = NetworkCollectorDaemon(config=cfg)
        await daemon.stop()
        assert daemon._icmp is None
        assert daemon._snmp is None

    async def test_context_manager(self) -> None:
        cfg = NetworkConfig()
        async with NetworkCollectorDaemon(config=cfg):
            pass
