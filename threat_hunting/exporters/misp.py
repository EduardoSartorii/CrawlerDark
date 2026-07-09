"""MISP exporter adapter."""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.contracts import ExporterPort
from threat_hunting.domain.entities import ExecutionContext, Finding


class MispExporter(ExporterPort):
    """Exports findings to MISP-like endpoint (adapter-ready)."""

    name = "misp"

    def __init__(self) -> None:
        self.sent_findings: list[str] = []

    def export(self, findings: Sequence[Finding], context: ExecutionContext) -> None:
        """Collect ids as exported artifacts in this baseline implementation."""
        self.sent_findings.extend(str(finding.id) for finding in findings)
