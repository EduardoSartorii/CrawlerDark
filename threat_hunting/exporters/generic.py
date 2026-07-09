"""Generic exporter adapters for pluggable destinations."""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.contracts import ExporterPort
from threat_hunting.domain.entities import ExecutionContext, Finding


class GenericExporter(ExporterPort):
    """Generic exporter stub for integrations implemented later."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._sent_batches: list[int] = []

    def export(self, findings: Sequence[Finding], context: ExecutionContext) -> None:
        self._sent_batches.append(len(findings))
