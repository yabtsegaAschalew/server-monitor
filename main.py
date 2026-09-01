from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
from collections.abc import Awaitable, Callable

from collectors import CaddyScrapeResult, CrashLoopEvent, DockerMonitor, NetworkCollectorDaemon, SystemHealthDaemon
from config import ConfigManager
from database import DatabaseEngine
from diagnostic import cli as diagnostic_cli
from models import DockerEvent, HostMetric, IcmpProbeMetric, SnmpHostMetric, SnmpInterfaceMetric

logger = logging.getLogger(__name__)

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


def _install_signal_handlers(shutdown: asyncio.Event) -> None:
    """Translate SIGINT/SIGTERM into a graceful shutdown request.

    The first signal sets the event, which unblocks the supervisor and runs the
    ordered teardown. A second signal cancels the supervising task outright, so
    an operator is never trapped by a daemon that refuses to stop.

    add_signal_handler is POSIX-only; on a platform without it we fall back to
    default behaviour rather than failing to start.
    """
    loop = asyncio.get_running_loop()
    main_task = asyncio.current_task()
    received = 0

    def _handle(signame: str) -> None:
        nonlocal received
        received += 1
        if received == 1:
            logger.info("received %s, shutting down gracefully (repeat to force)", signame)
            shutdown.set()
        else:
            logger.warning("received %s again, forcing shutdown", signame)
            if main_task is not None:
                main_task.cancel()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle, sig.name)
        except (NotImplementedError, RuntimeError):
            logger.debug("signal handler for %s unavailable on this platform", sig.name)


async def _wait_for_exit(tasks: list[asyncio.Task[None]], shutdown: asyncio.Event) -> None:
    """Block until shutdown is requested or a daemon exits on its own.

    A run_forever daemon returning is always abnormal, so it is reported rather
    than silently ending the process.
    """
    waiter = asyncio.create_task(shutdown.wait(), name="shutdown-wait")
    try:
        done, _pending = await asyncio.wait([*tasks, waiter], return_when=asyncio.FIRST_COMPLETED)
    finally:
        waiter.cancel()

    for task in done:
        if task is waiter or task.cancelled():
            continue
        exc = task.exception()
        if exc is not None:
            logger.error("daemon %s died: %r", task.get_name(), exc, exc_info=exc)

        else:
            logger.warning("daemon %s exited unexpectedly", task.get_name())


async def run_supervised(
    config: ConfigManager,
    *,
    collectors: frozenset[str] | None = None,
    interval: float | None = None,
    with_diagnostic: bool = False,
    with_alert_engine: bool = False,
) -> None:
    """Run the selected daemons concurrently over one shared DatabaseEngine.

    One engine, not one per daemon: the whole persistence design is a single
    writer serialising behind one queue, and three engines against one SQLite
    file would defeat it.
    """
    shutdown = asyncio.Event()
    _install_signal_handlers(shutdown)

    tasks: list[asyncio.Task[None]] = []
    closers: list[Callable[[], Awaitable[None]]] = []

    db = DatabaseEngine(config.collectors.database)
    await db.start()
    if _DEBUG:
        print(f"[DEBUG] Database started, db_path={config.collectors.database.db_path}")

    try:

        async def sink(item: object) -> None:
            _print_item(item)
            await db.write(item)

        if collectors:
            if "host" in collectors or "caddy" in collectors:
                overrides: dict[str, float] = {}
                if interval is not None:
                    overrides = {"host_interval": interval, "caddy_interval": interval}
                daemon = SystemHealthDaemon.from_config(config, **overrides)
                tasks.append(asyncio.create_task(daemon.run_forever(sink), name="system-health"))
                closers.append(daemon.aclose)
            if "docker" in collectors:
                if _DEBUG:
                    docker_cfg = config.collectors.docker
                    print(f"[DEBUG] Docker transport={docker_cfg.transport_mode} base_url={docker_cfg.base_url}")
                docker = DockerMonitor.from_config(config)
                tasks.append(asyncio.create_task(docker.run_forever(sink), name="docker"))
                closers.append(docker.aclose)
            if "network" in collectors:
                network = NetworkCollectorDaemon(config=config.collectors.network)
                tasks.append(asyncio.create_task(network.run_forever(sink), name="network"))
                closers.append(network.aclose)

        if with_diagnostic:
            agent = await _build_diagnostic_agent(config, db)
            if agent is not None:
                tasks.append(asyncio.create_task(agent.run_daemon(), name="diagnostic"))
                closers.append(agent.aclose)

        if with_alert_engine:
            engine = _build_alert_engine(config, db)
            if engine is not None:
                tasks.append(asyncio.create_task(engine.run_forever(), name="alert-engine"))
                closers.append(engine.aclose)

        if not tasks:
            logger.error("no daemons started; nothing to do")
            return

        logger.info("running daemons: %s", ", ".join(t.get_name() for t in tasks))
        await _wait_for_exit(tasks, shutdown)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for close in closers:
            try:
                await close()

            except Exception:  # noqa: BLE001 - shutdown must not mask the original exit
                logger.exception("error during daemon shutdown")
        await db.aclose()
        logger.info("shutdown complete")


async def _build_diagnostic_agent(config: ConfigManager, db: DatabaseEngine):
    """Build the diagnostic agent, or None when it cannot run."""
    from diagnostic.agent import DiagnosticAgent, is_diagnostic_enabled, resolve_api_key

    if not is_diagnostic_enabled(config):
        logger.warning("diagnostic daemon not started: disabled in config")

        return None
    if resolve_api_key(config.diagnostic) is None:
        logger.warning(
            "diagnostic daemon not started: no API key configured for provider %r",
            config.diagnostic.provider,
        )
        return None
    agent = DiagnosticAgent(config, db)
    await agent.start()
    return agent


def _build_alert_engine(config: ConfigManager, db: DatabaseEngine):
    """Build the alert engine, or None when it is disabled."""

    from alert_engine import AlertEngine

    if not config.alerting.enabled:
        logger.warning("alert engine not started: alerting.enabled is false")

        return None
    if not config.alerting.has_channel:
        logger.error(
            "alert engine starting with NO notification channel configured; alerts will be recorded but not sent"
        )
    return AlertEngine.from_config(config, db)


async def run(config: ConfigManager, interval: float | None, collectors: frozenset[str]) -> None:
    await run_supervised(config, collectors=collectors, interval=interval)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser.

    Two interfaces coexist deliberately:

    * Mode flags (``--all``, ``--collectors``, ``--diagnostic``,
      ``--alert-engine``) are the current interface and can be combined.
    * The ``collectors`` and ``diagnostic`` subcommands are retained unchanged,
      because compose.yaml and the container image invoke the former and a
      regression test asserts that invocation stays valid.

    Subparsers are NOT required, since a bare mode flag is now a complete
    invocation; a run with neither a flag nor a subcommand exits with help.
    """
    parser = argparse.ArgumentParser(
        prog="python -m main",
        description="Async server monitoring system.",
    )

    parser.add_argument("--config", default="config.yaml", help="Path to YAML config (default: config.yaml)")
    parser.add_argument("--interval", type=float, default=None, help="Override both scrape intervals (seconds)")
    parser.add_argument(
        "--only",
        default="all",
        metavar="host,caddy,docker,network",
        help="Restrict --collectors/--all to a subset (default: all)",
    )

    modes = parser.add_argument_group("daemon selection")
    modes.add_argument("--all", action="store_true", help="Run collectors, diagnostic agent and alert engine")
    modes.add_argument("--collectors", action="store_true", help="Run the telemetry collectors")
    modes.add_argument("--diagnostic", action="store_true", help="Run the diagnostic agent (polling)")
    modes.add_argument("--alert-engine", action="store_true", help="Run the multi-burn-rate alert engine")

    sub = parser.add_subparsers(dest="command", required=False)

    collectors_parser = sub.add_parser("collectors", help="Run the telemetry collectors (compatibility alias)")
    collectors_parser.add_argument("--config", default="config.yaml", help="Path to YAML config (default: config.yaml)")

    collectors_parser.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Override both scrape intervals (seconds)",
    )
    collectors_parser.add_argument(
        "--collectors",
        default="all",
        help="Comma-separated subset of host,caddy,docker,network (default: all)",
    )

    diag_parser = sub.add_parser("diagnostic", help="Diagnostic agent commands (see also: python -m diagnostic)")
    diagnostic_cli.add_arguments(diag_parser)

    return parser


def _selected_modes(args: argparse.Namespace) -> tuple[bool, bool, bool]:
    """(collectors, diagnostic, alert_engine) from the mode flags."""
    if args.all:
        return (True, True, True)
    return (args.collectors, args.diagnostic, getattr(args, "alert_engine", False))


def main(argv: list[str] | None = None) -> None:
    from dotenv import load_dotenv

    load_dotenv()

    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    if args.command == "collectors":
        config = ConfigManager.from_file(args.config)
        asyncio.run(run(config, args.interval, parse_collectors(args.collectors)))

        return
    if args.command == "diagnostic":
        asyncio.run(_dispatch_diagnostic(args))
        return

    want_collectors, want_diagnostic, want_alerts = _selected_modes(args)

    if not (want_collectors or want_diagnostic or want_alerts):
        parser.print_help()
        raise SystemExit("select at least one of --all, --collectors, --diagnostic, --alert-engine")

    config = ConfigManager.from_file(args.config)
    asyncio.run(
        run_supervised(
            config,
            collectors=parse_collectors(args.only) if want_collectors else None,
            interval=args.interval,
            with_diagnostic=want_diagnostic,
            with_alert_engine=want_alerts,
        )
    )


async def _dispatch_diagnostic(args: argparse.Namespace) -> None:
    await diagnostic_cli.dispatch(args)


if __name__ == "__main__":
    main()
