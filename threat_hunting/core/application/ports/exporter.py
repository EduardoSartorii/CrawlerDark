"""Exporter port.

Responsibility
--------------
Define the contract for shipping findings to external systems (MISP, OpenCTI,
Splunk, OpenSearch, STIX/TAXII, Webhook, JSON, CSV, ...). Every exporter is an
Adapter over a downstream system, selected via config and discovered/built by a
factory. Threshold-based auto-export is driven by domain events, not by the
exporter itself.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from threat_hunting.core.domain.entities.finding import Finding


class ExportResult(BaseModel):
    """Outcome of an export operation."""

    exporter: str
    exported: int = 0
    destination: str = ""
    detail: str = ""


@runtime_checkable
class Exporter(Protocol):
    """Contract for exporting findings to an external destination."""

    name: str

    def export(self, findings: Sequence[Finding]) -> ExportResult:
        """Export the given findings and return a summary result."""
        ...
