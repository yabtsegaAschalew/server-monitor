from __future__ import annotations

from typing import Any

__all__ = [
    "DiagnosticAgent",
    "DiagnosticState",
    "Guardrails",
    "build_provider",
    "compile_graph",
    "is_diagnostic_enabled",
    "resolve_api_key",
]


def __getattr__(name: str) -> Any:
    # NOTE: do not add a "cli" branch here. `from diagnostic import cli` inside
    # this function would re-enter __getattr__ and recurse forever. The import
    # machinery already resolves `from diagnostic import cli` and
    # `from diagnostic.cli import ...` on its own, which is all the entry points
    # need; this hook exists only for the eager re-exports below.
    if name == "DiagnosticAgent":
        from diagnostic.agent import DiagnosticAgent

        return DiagnosticAgent
    if name == "build_provider":
        from diagnostic.agent import build_provider

        return build_provider
    if name == "compile_graph":
        from diagnostic.agent import compile_graph

        return compile_graph
    if name == "is_diagnostic_enabled":
        from diagnostic.agent import is_diagnostic_enabled

        return is_diagnostic_enabled
    if name == "resolve_api_key":
        from diagnostic.agent import resolve_api_key

        return resolve_api_key
    if name == "DiagnosticState":
        from diagnostic.state import DiagnosticState

        return DiagnosticState
    if name == "Guardrails":
        from diagnostic.guardrails import Guardrails

        return Guardrails
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
