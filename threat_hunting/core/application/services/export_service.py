"""Export use-case service.

Responsibility
--------------
Fetch stored findings (optionally filtered by a minimum score) and hand them to
a named exporter. Used by ``hunt export <target>`` and by the automatic
threshold-based export path.
"""

from __future__ import annotations

from collections.abc import Mapping

from threat_hunting.core.application.ports.exporter import Exporter, ExportResult
from threat_hunting.core.application.ports.repository import UnitOfWork
from threat_hunting.core.domain.exceptions import ExportError


class ExportService:
    """Exports persisted findings through a registered exporter."""

    def __init__(self, uow: UnitOfWork, exporters: Mapping[str, Exporter]) -> None:
        self._uow = uow
        self._exporters = dict(exporters)

    def available(self) -> list[str]:
        """Return the names of the registered exporters."""
        return sorted(self._exporters)

    def export(self, exporter_name: str, min_score: float = 0.0) -> ExportResult:
        """Export findings with ``score >= min_score`` via ``exporter_name``."""
        exporter = self._exporters.get(exporter_name)
        if exporter is None:
            raise ExportError(
                f"Unknown exporter '{exporter_name}'. Available: {self.available()}"
            )
        with self._uow as uow:
            findings = [f for f in uow.findings.list() if f.score.value >= min_score]
        return exporter.export(findings)
