"""
Base Exporter Interface.

All exporters implement this interface for consistent integration
with the pipeline and CLI export commands.

Design Pattern: Strategy Pattern — each exporter is a pluggable strategy
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ...core.domain.entities.finding import Finding


@dataclass
class ExportResult:
    """Result from an export operation."""

    destination: str
    exported_count: int = 0
    failed_count: int = 0
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.failed_count == 0 and not self.errors

    @property
    def total(self) -> int:
        return self.exported_count + self.failed_count


class BaseExporter(ABC):
    """Abstract base for all exporters."""

    exporter_id: str = ""
    name: str = ""
    description: str = ""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}

    @abstractmethod
    async def export(self, findings: list[Finding]) -> ExportResult:
        """Export findings to the destination platform."""

    @abstractmethod
    async def health(self) -> bool:
        """Check if the destination is reachable."""
