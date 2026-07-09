"""Base connector SDK.

Every source connector extends this class and implements the same lifecycle:
``connect -> collect -> parse -> normalize -> health -> close``. The connector
never persists, scores or exports findings; those responsibilities belong to the
pipeline and application services.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from threat_hunting.core.domain.entities import Finding


class BaseConnector(ABC):
    """Abstract base class for all collection plugins."""

    name: str
    source: str

    def __init__(self, name: str, source: str, config: dict[str, Any] | None = None) -> None:
        self.name = name
        self.source = source
        self.config = config or {}

    @abstractmethod
    def connect(self) -> None:
        """Initialize the connector."""

    @abstractmethod
    def collect(self) -> Iterable[Any]:
        """Yield raw records collected from the source."""

    @abstractmethod
    def parse(self, raw_item: Any) -> dict[str, Any]:
        """Parse one raw record into structured data."""

    @abstractmethod
    def normalize(self, parsed_item: dict[str, Any]) -> Finding:
        """Normalize one parsed record into a canonical finding."""

    @abstractmethod
    def health(self) -> dict[str, Any]:
        """Return health details for observability and scheduler decisions."""

    @abstractmethod
    def close(self) -> None:
        """Release connector resources."""
