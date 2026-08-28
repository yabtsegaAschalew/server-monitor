from __future__ import annotations

import argparse
import asyncio
import logging
import os

from collectors import CaddyScrapeResult, CrashLoopEvent, DockerMonitor, NetworkCollectorDaemon, SystemHealthDaemon
from config import ConfigManager
from database import DatabaseEngine
from models import DockerEvent, HostMetric, IcmpProbeMetric, SnmpHostMetric, SnmpInterfaceMetric

_COLLECTOR_CHOICES = frozenset({"host", "caddy", "docker", "network"})
_DEBUG = os.environ.get("DEBUG", "").lower() in ("true", "1", "yes")


def _print_item(item: object) -> None:
    if isinstance(item, HostMetric):
        print(
            f"[host] cpu={item.cpu_percent:.1f}% mem={item.memory_percent:.1f}% disk={item.disk_percent:.1f}% "
            f"load={item.load_avg:.2f} disk_io={item.disk_read_bps:.0f}/{item.disk_write_bps:.0f} B/s "
            f"net={item.net_bytes_sent_per_sec:.0f}/{item.net_bytes_recv_per_sec:.0f} B/s"
        )
    elif isinstance(item, CaddyScrapeResult):
        print(
            f"[caddy] 2xx={item.two_xx:.0f} 4xx={item.four_xx:.0f} 5xx={item.five_xx:.0f} "
            f"rps={item.metric.requests_per_second:.1f} p99={item.metric.p99_latency_ms:.1f}ms "
            f"error_rate={item.metric.error_rate:.2%} conns={item.metric.active_conns}"
        )
    elif isinstance(item, DockerEvent):
        details = f" exit={item.exit_code}" if item.exit_code is not None else ""
        details += f" reason={item.failure_reason}" if item.failure_reason else ""
        print(f"[docker] container={item.container_name} status={item.status}{details}")
    elif isinstance(item, CrashLoopEvent):
        print(
            f"[docker] CRASH-LOOP container={item.container_name} restarts={item.event_count} "
            f"window={item.window_seconds:.0f}s"
        )
    elif isinstance(item, IcmpProbeMetric):
        print(
            f"[network] icmp host={item.target_host} ip={item.target_ip} "
            f"rtt={item.avg_rtt_ms:.2f}ms loss={item.packet_loss_pct:.1f}% "
            f"min={item.min_rtt_ms:.2f}ms max={item.max_rtt_ms:.2f}ms"
        )
    elif isinstance(item, SnmpInterfaceMetric):
        print(
            f"[network] snmp-if device={item.device_id} iface={item.if_name} "
            f"status={item.if_oper_status} in_bps={item.in_bps:.0f} out_bps={item.out_bps:.0f}"
        )
    elif isinstance(item, SnmpHostMetric):
        print(
            f"[network] snmp-host device={item.device_id} host={item.device_host} "
            f"cpu_load={item.hr_cpu_load or 0:.1f}% mem_used={item.hr_memory_used or 0}B"
        )


def parse_collectors(value: str) -> frozenset[str]:
    if value == "all":
        return _COLLECTOR_CHOICES
    tokens = {token.strip() for token in value.split(",")}
    if not tokens or not tokens.issubset(_COLLECTOR_CHOICES):
        raise ValueError(f"invalid collectors: {value!r} (choose from {', '.join(sorted(_COLLECTOR_CHOICES))})")
    return tokens


async def run(config: ConfigManager, interval: float | None, collectors: frozenset[str]) -> None:
    tasks: list[asyncio.Task[None]] = []
    daemon = None
    docker = None
    network = None
    db = DatabaseEngine(config.collectors.database)
    try:
        await db.start()
        if _DEBUG:
            print(f"[DEBUG] Database started, db_path={config.collectors.database.db_path}")

        async def sink(item: object) -> None:
            _print_item(item)
            await db.write(item)

        if _DEBUG:
            print(f"[DEBUG] Collectors enabled: {collectors}")
        if "host" in collectors or "caddy" in collectors:
            overrides: dict[str, float] = {}
            if interval is not None:
                overrides = {"host_interval": interval, "caddy_interval": interval}
            daemon = SystemHealthDaemon.from_config(config, **overrides)
            tasks.append(asyncio.create_task(daemon.run_forever(sink)))
        if "docker" in collectors:
            docker_cfg = config.collectors.docker
            if _DEBUG:
                print(f"[DEBUG] Docker transport={docker_cfg.transport_mode} base_url={docker_cfg.base_url}")
            docker = DockerMonitor.from_config(config)
            if _DEBUG:
                print("[DEBUG] Docker monitor task created")
            tasks.append(asyncio.create_task(docker.run_forever(sink)))
        if "network" in collectors:
            network = NetworkCollectorDaemon(config=config.collectors.network)
            tasks.append(asyncio.create_task(network.run_forever(sink)))
        if _DEBUG:
            print("[DEBUG] All tasks started, waiting...")
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        if daemon is not None:
            await daemon.aclose()
        if docker is not None:
            await docker.aclose()
        if network is not None:
            await network.aclose()
        await db.aclose()


def main() -> None:
    from dotenv import load_dotenv
    load_dotenv()

    parser = argparse.ArgumentParser(description="Run the system health daemon for manual testing.")
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config (default: config.yaml)")
    parser.add_argument("--interval", type=float, default=None, help="Override both scrape intervals (seconds)")
    parser.add_argument(
        "--collectors",
        default="all",
        help="Comma-separated subset of host,caddy,docker,network (default: all)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    config = ConfigManager.from_file(args.config)
    asyncio.run(run(config, args.interval, parse_collectors(args.collectors)))


if __name__ == "__main__":
    main()
