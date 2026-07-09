"""``ExportFindingsUseCase`` — export stored findings to a destination.

Responsibility
--------------
Read findings from persistence (through the Unit of Work) and hand them to a
selected exporter. Used by ``hunt export <name>``. Selection of *which* exporter
happens by name so new destinations require no change here.
"""

from __future__ import annotations

from collections.abc import Mapping

from threat_hunting.core.application.ports.exporter import ExporterPort
from threat_hunting.core.application.ports.repository import UnitOfWorkPort
from threat_hunting.core.domain.exceptions import ExporterError


class ExportFindingsUseCase:
    """Exports persisted findings via a named exporter strategy."""

    def __init__(
        self,
        *,
        uow: UnitOfWorkPort,
        exporters: Mapping[str, ExporterPort],
    ) -> None:
        self._uow = uow
        self._exporters = dict(exporters)

    def available(self) -> list[str]:
        """Return the names of the registered exporters."""
        return sorted(self._exporters)

    def export(self, name: str, *, min_score: float = 0.0, limit: int | None = None) -> int:
        """Export findings (optionally filtered by score) via one exporter."""
        exporter = self._exporters.get(name)
        if exporter is None:
            raise ExporterError(f"unknown exporter: {name!r}")
        findings = [
            f for f in self._uow.collect_all(limit=limit) if f.score >= min_score
        ]
        return exporter.export(findings)
