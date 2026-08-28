from __future__ import annotations

import pytest

from main import parse_collectors


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
