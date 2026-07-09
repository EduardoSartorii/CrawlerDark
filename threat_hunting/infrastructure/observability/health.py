"""Health checks for dependencies and runtime components."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class HealthCheckRegistry:
    """Registry of health check functions."""

    def __init__(self) -> None:
        self._checks: dict[str, Callable[[], bool]] = {}

    def register(self, name: str, check: Callable[[], bool]) -> None:
        self._checks[name] = check

    def run(self) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for name, check in self._checks.items():
            try:
                results[name] = {"ok": bool(check())}
            except Exception as exc:
                results[name] = {"ok": False, "error": str(exc)}
        results["status"] = "ok" if all(v.get("ok") for v in results.values() if isinstance(v, dict)) else "degraded"
        return results
