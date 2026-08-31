from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from main import _selected_modes, build_parser, parse_collectors


def test_parse_collectors_all() -> None:
    assert parse_collectors("all") == frozenset({"host", "caddy", "docker", "network"})


def test_parse_collectors_single() -> None:
    assert parse_collectors("docker") == frozenset({"docker"})


def test_parse_collectors_subset() -> None:
    assert parse_collectors("host,caddy") == frozenset({"host", "caddy"})


def test_parse_collectors_ignores_whitespace() -> None:
    assert parse_collectors(" host , caddy ") == frozenset({"host", "caddy"})


@pytest.mark.parametrize("value", ["", "kubernetes", "host,evil", "caddy,"])
def test_parse_collectors_rejects_invalid(value: str) -> None:
    with pytest.raises(ValueError, match="invalid collectors"):
        parse_collectors(value)


# ---------------------------------------------------------------------------
# CLI argv shapes — the compose crash-loop regression
# ---------------------------------------------------------------------------


def test_bare_collectors_with_value_is_still_rejected() -> None:
    """`--collectors docker` is not a valid invocation.

    compose.yaml used to pass exactly this as `command:`, so the container
    exited 2 on every start and `restart: unless-stopped` made it a crash loop.
    `--collectors` is now a boolean mode flag, so `docker` is left over as a
    positional and argparse still rejects it — the crash-loop shape stays
    invalid rather than silently starting the wrong thing.
    """
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--collectors", "docker"])


def test_collectors_subcommand_parses() -> None:
    args = build_parser().parse_args(["collectors", "--collectors", "docker"])
    assert args.command == "collectors"
    assert parse_collectors(args.collectors) == frozenset({"docker"})


# ---------------------------------------------------------------------------
# Mode flags (Phase 4 unified entrypoint)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "attr"),
    [
        (["--collectors"], "collectors"),
        (["--diagnostic"], "diagnostic"),
        (["--alert-engine"], "alert_engine"),
    ],
)
def test_mode_flags_parse(argv: list[str], attr: str) -> None:
    args = build_parser().parse_args(argv)
    assert getattr(args, attr) is True
    assert args.command is None


def test_all_flag_selects_every_daemon() -> None:
    args = build_parser().parse_args(["--all"])
    assert _selected_modes(args) == (True, True, True)


def test_mode_flags_combine() -> None:
    args = build_parser().parse_args(["--collectors", "--alert-engine"])
    assert _selected_modes(args) == (True, False, True)


def test_only_restricts_the_collector_subset() -> None:
    args = build_parser().parse_args(["--collectors", "--only", "host,caddy"])
    assert parse_collectors(args.only) == frozenset({"host", "caddy"})


def test_no_mode_selected_is_not_a_valid_run() -> None:
    """A bare invocation must not silently start nothing."""
    args = build_parser().parse_args([])
    assert args.command is None
    assert _selected_modes(args) == (False, False, False)


def test_flags_and_subcommands_coexist() -> None:
    """The compatibility aliases must survive the flag interface."""
    parser = build_parser()
    assert parser.parse_args(["--all"]).command is None
    assert parser.parse_args(["collectors"]).command == "collectors"
    assert parser.parse_args(["diagnostic", "list-rules"]).command == "diagnostic"


def test_compose_command_is_a_valid_invocation() -> None:
    """The shipped compose `command:` must actually parse.

    This is the test that would have caught the crash loop: it reads the real
    manifest rather than a copy of it.
    """
    compose = yaml.safe_load((Path(__file__).resolve().parent.parent / "compose.yaml").read_text())
    command = compose["services"]["monitor"]["command"]
    assert isinstance(command, list), "command must be exec-form so argv is unambiguous"

    args = build_parser().parse_args(command)
    assert args.command == "collectors"


def test_compose_does_not_publish_the_docker_socket_proxy() -> None:
    """The proxy must stay on the internal network.

    Even read-only, a published 2375 hands out an unauthenticated inventory of
    every container on the host.
    """
    compose = yaml.safe_load((Path(__file__).resolve().parent.parent / "compose.yaml").read_text())
    proxy = compose["services"]["docker-socket-proxy"]
    assert "ports" not in proxy, "docker-socket-proxy must not publish a host port"


def test_dockerignore_excludes_secrets_and_local_state() -> None:
    """`COPY . .` must not be able to bake .env or the telemetry DB into a layer."""
    entries = {
        line.strip()
        for line in (Path(__file__).resolve().parent.parent / ".dockerignore").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    for required in (".env", "*.db", "*.db-wal", "*.db-shm"):
        assert required in entries, f".dockerignore must exclude {required}"
