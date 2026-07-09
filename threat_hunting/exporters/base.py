"""Exporter base adapter."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from threat_hunting.core.domain.entities import Finding


class BaseExporter(ABC):
    """Base class for all exporter adapters."""

    name: str

    @abstractmethod
    def export(self, findings: Sequence[Finding]) -> None:
        """Export findings to a target backend."""
