"""Exporter port (Strategy pattern).

Responsibility
--------------
Define how a finding leaves the platform. Each destination (JSON, CSV, STIX,
MISP, Splunk, webhook, ...) is an independent strategy implementing this port.
Exporters are selected and combined at runtime; adding one never touches the
pipeline.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence

from threat_hunting.core.domain.entities import Finding


class ExporterPort(abc.ABC):
    """Abstract destination for findings."""

    #: Unique exporter name (used by the CLI ``hunt export <name>``).
    name: str = "abstract"

    @abc.abstractmethod
    def supports_auto_export(self) -> bool:
        """Whether this exporter may fire automatically on a score threshold."""

    @abc.abstractmethod
    def export(self, findings: Sequence[Finding]) -> int:
        """Export the given findings; return the number successfully exported."""

    def export_one(self, finding: Finding) -> int:
        """Export a single finding (default: delegate to :meth:`export`)."""
        return self.export([finding])
