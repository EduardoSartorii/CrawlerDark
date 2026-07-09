"""Architecture guard: the core must not depend on infrastructure/cli.

This enforces the Dependency Rule of Clean/Hexagonal architecture at CI time, so
a well-meaning import can never quietly couple the domain to a framework.
"""

from __future__ import annotations

import ast
from pathlib import Path

_CORE = Path(__file__).resolve().parents[2] / "threat_hunting" / "core"
_FORBIDDEN = ("threat_hunting.infrastructure", "threat_hunting.cli")


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return modules


def test_core_never_imports_infrastructure_or_cli() -> None:
    offenders: dict[str, list[str]] = {}
    for py_file in _CORE.rglob("*.py"):
        bad = [m for m in _imports(py_file) if m.startswith(_FORBIDDEN)]
        if bad:
            offenders[str(py_file)] = bad
    assert offenders == {}, f"core layer leaks into infrastructure/cli: {offenders}"
