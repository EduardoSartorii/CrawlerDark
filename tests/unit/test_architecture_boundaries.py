"""Architecture guard test.

Enforces the Clean Architecture dependency rule automatically: nothing under
``threat_hunting/core`` may import from ``threat_hunting.infrastructure``,
``threat_hunting.cli`` or ``threat_hunting.config``. This keeps the core pure
and framework-free over time, catching accidental inward dependency violations
in CI rather than in review.
"""

from __future__ import annotations

import ast
from pathlib import Path

CORE = Path(__file__).resolve().parents[2] / "threat_hunting" / "core"
FORBIDDEN_PREFIXES = (
    "threat_hunting.infrastructure",
    "threat_hunting.cli",
    "threat_hunting.config",
)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_core_never_imports_outer_layers():
    violations: list[str] = []
    for py_file in CORE.rglob("*.py"):
        for module in _imports(py_file):
            if module.startswith(FORBIDDEN_PREFIXES):
                violations.append(f"{py_file.name} -> {module}")
    assert not violations, f"core imports outer layers: {violations}"
