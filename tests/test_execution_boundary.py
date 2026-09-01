"""The read-only guarantee, asserted rather than assumed.

This system's core safety claim is that it proposes remediation but never runs
it: the diagnostic agent writes an ActionPlan to SQLite as status='pending', and
`approve` only flips a status column. That claim currently holds because nobody
has written an executor — not because anything prevents one.

These tests make the property enforceable. If someone later adds a background
worker that shells out an approved rule, CI fails here first.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

_FORBIDDEN_CALLS = {
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.execl",
    "os.execlp",
    "os.execvp",
    "os.spawnl",
    "os.spawnv",
    "os.posix_spawn",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.getoutput",
    "eval",
    "exec",
    "compile",
}

_FORBIDDEN_IMPORTS = {"subprocess", "shlex", "pty", "commands", "pickle", "marshal"}

_EXEMPT = {"tests/test_execution_boundary.py"}


def _python_sources() -> list[pathlib.Path]:
    return [
        path
        for path in _REPO_ROOT.rglob("*.py")
        if not any(part in {".venv", "__pycache__", "build", "dist"} for part in path.parts)
        and str(path.relative_to(_REPO_ROOT)) not in _EXEMPT
    ]


def _dotted_name(node: ast.AST) -> str:
    """Render a Name/Attribute chain as a dotted string."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def test_no_process_execution_or_dynamic_eval() -> None:
    """No shipped module may spawn a process or evaluate code at runtime."""
    offenders: list[str] = []
    for path in _python_sources():
        rel = path.relative_to(_REPO_ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = _dotted_name(node.func)
                if name in _FORBIDDEN_CALLS:
                    offenders.append(f"{rel}:{node.lineno} calls {name}()")
    assert not offenders, "execution primitives introduced:\n  " + "\n  ".join(offenders)


def test_no_imports_of_process_or_deserialization_modules() -> None:
    """Importing these is the step before using them; block it at the import."""
    offenders: list[str] = []
    for path in _python_sources():
        rel = path.relative_to(_REPO_ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in _FORBIDDEN_IMPORTS:
                        offenders.append(f"{rel}:{node.lineno} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root in _FORBIDDEN_IMPORTS:
                    offenders.append(f"{rel}:{node.lineno} imports from {node.module}")
    assert not offenders, "forbidden imports introduced:\n  " + "\n  ".join(offenders)


def test_no_shell_true_keyword_anywhere() -> None:
    offenders: list[str] = []
    for path in _python_sources():
        rel = path.relative_to(_REPO_ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        offenders.append(f"{rel}:{node.lineno} passes shell=True")
    assert not offenders, "\n".join(offenders)


def test_yaml_is_loaded_safely() -> None:
    """Config comes from a file on disk; yaml.load would be arbitrary construction."""
    offenders: list[str] = []
    for path in _python_sources():
        rel = path.relative_to(_REPO_ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _dotted_name(node.func) == "yaml.load":
                offenders.append(f"{rel}:{node.lineno} uses yaml.load (use yaml.safe_load)")
    assert not offenders, "\n".join(offenders)


def test_proposed_rules_have_no_consumer() -> None:
    """Nothing may read a pending/approved rule in order to act on it.

    `approve` deliberately only updates a status column. If a future change adds
    a worker that drains this table, this test is the tripwire.
    """
    import database

    source = pathlib.Path(database.__file__).read_text(encoding="utf-8")
    assert "def update_rule_status" in source
    assert "def query_proposed_rules" in source

    _REVIEW_PATH = {"database.py", "main.py", "diagnostic/cli.py"}

    callers: list[str] = []

    for path in _python_sources():
        rel = str(path.relative_to(_REPO_ROOT))
        if rel in _REVIEW_PATH or rel.startswith("tests/"):
            continue
        text = path.read_text(encoding="utf-8")
        if "query_proposed_rules" in text or "update_rule_status" in text:
            callers.append(rel)
    assert not callers, f"proposed rules are being consumed outside the CLI review path: {callers}"


def test_review_path_never_executes_a_suggested_command() -> None:
    """The review CLI must move a status column and nothing more.

    `approve` is the single most dangerous-sounding verb in this system. This
    asserts that the module implementing it contains no execution primitive and
    never reads the command text out of a plan in order to run it.


    """
    cli = _REPO_ROOT / "diagnostic" / "cli.py"

    tree = ast.parse(cli.read_text(encoding="utf-8"), filename=str(cli))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted_name(node.func)
            assert name not in _FORBIDDEN_CALLS, f"diagnostic/cli.py calls {name}()"
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in _FORBIDDEN_IMPORTS
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in _FORBIDDEN_IMPORTS


@pytest.mark.parametrize("snippet", ["os.system('id')", "subprocess.run(['id'])", "eval('1+1')"])
def test_detector_actually_detects(snippet: str) -> None:
    """Guard against the guard silently matching nothing."""
    tree = ast.parse(snippet)
    found = [_dotted_name(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert any(name in _FORBIDDEN_CALLS for name in found)
