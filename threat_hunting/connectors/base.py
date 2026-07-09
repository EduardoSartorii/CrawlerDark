"""Connector SDK.

New sources are integrated by subclassing ``BaseConnector`` and registering the
class as a plugin. Connectors own source-specific collection details only; they
do not persist data, score findings, export alerts, or know infrastructure
internals.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, Field

from threat_hunting.core.domain.entities import Finding


RawCollectionItem = dict[str, Any]


class ConnectorHealth(BaseModel):
    """Health-check result for connector operations."""

    healthy: bool
    connector: str
    details: dict[str, Any] = Field(default_factory=dict)


class BaseConnector(ABC):
    """Base class for every collection connector."""

    name: str
    source: str
    category: str
    groups: set[str] = set()

    def __init__(self, config: dict[str, Any] | None = None, transport: Any | None = None) -> None:
        self.config = config or {}
        self.transport = transport
        self.enabled = bool(self.config.get("enabled", True))

    @abstractmethod
    def connect(self) -> None:
        """Initialize source-specific sessions or credentials."""

    @abstractmethod
    def collect(self) -> Iterable[RawCollectionItem]:
        """Collect raw source records."""

    @abstractmethod
    def parse(self, raw: RawCollectionItem) -> RawCollectionItem:
        """Parse raw source records into a source-neutral intermediate dict."""

    def extract(self, parsed: RawCollectionItem) -> RawCollectionItem:
        """Extract artifacts before normalization.

        The default builder keeps connector development lightweight. Advanced
        connectors can override this method or delegate to extractor plugins.
        """

        return parsed

    @abstractmethod
    def normalize(self, parsed: RawCollectionItem) -> Finding:
        """Normalize parsed records into the canonical Finding aggregate."""

    @abstractmethod
    def health(self) -> ConnectorHealth:
        """Return connector health details."""

    @abstractmethod
    def close(self) -> None:
        """Release resources opened by ``connect``."""
