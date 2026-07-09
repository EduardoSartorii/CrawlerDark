"""
IExporter Port
==============

Contract for all exporters. Exporters are strategy implementations —
each exporter handles one destination platform.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding


class IExporter(ABC):
    """Abstract exporter port."""

    exporter_id: str = ""
    exporter_name: str = ""

    @abstractmethod
    async def export(self, finding: "Finding") -> bool:
        """Export a Finding to the destination platform.

        Args:
            finding: The Finding to export.

        Returns:
            True when export succeeded, False otherwise.

        Raises:
            ExportError: On unrecoverable export failure.
        """

    @abstractmethod
    async def export_batch(self, findings: list["Finding"]) -> dict[str, bool]:
        """Export multiple Findings in a batch.

        Returns:
            A mapping from finding_id to success status.
        """

    @abstractmethod
    async def health(self) -> bool:
        """Verify the exporter can reach its destination."""
