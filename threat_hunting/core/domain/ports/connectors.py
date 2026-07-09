"""
IConnector Port
===============

The primary boundary between the Collection layer and the Core.
Every connector must implement this interface.

Design:
    - connect() / close() manage the lifecycle (session, auth).
    - collect() performs the actual data retrieval.
    - parse() converts raw bytes/str to structured dicts.
    - normalize() converts structured dicts to Finding objects.
    - health() is used by the health-check endpoint.

The connector is responsible ONLY for data retrieval and initial
normalization. Detection, scoring, and enrichment happen downstream.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, AsyncIterator

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding
    from threat_hunting.core.domain.entities.connector_config import ConnectorConfig


class ConnectorHealthStatus:
    """Simple health status container for a connector."""

    def __init__(self, healthy: bool, message: str = "", latency_ms: float = 0.0) -> None:
        self.healthy = healthy
        self.message = message
        self.latency_ms = latency_ms

    def __repr__(self) -> str:
        return f"ConnectorHealthStatus(healthy={self.healthy}, message={self.message!r})"


class IConnector(ABC):
    """
    Abstract connector port.

    All connectors must implement this interface. New connectors are added by
    subclassing BaseConnector (the provided implementation) and placing the
    file in the connectors/ directory. The registry discovers them automatically.
    """

    # Must be overridden by each connector class.
    connector_id: str = ""
    connector_name: str = ""
    source_type: str = ""

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection / authenticate with the source.

        Raises:
            ConnectorError: When authentication or connection fails.
        """

    @abstractmethod
    async def collect(self) -> AsyncIterator[dict]:
        """Yield raw items from the source.

        Yields:
            Raw dict-like items to be passed to parse().

        Raises:
            CollectionError: On unrecoverable collection failure.
        """

    @abstractmethod
    async def parse(self, raw_item: dict) -> dict:
        """Convert a raw item into a structured dict.

        Args:
            raw_item: Raw dict from collect().

        Returns:
            Structured dict ready for normalize().

        Raises:
            ParseError: When the item cannot be parsed.
        """

    @abstractmethod
    async def normalize(self, parsed_item: dict) -> "Finding":
        """Convert a structured dict into a Finding domain object.

        Args:
            parsed_item: Dict from parse().

        Returns:
            A Finding ready for the detection pipeline.

        Raises:
            NormalizationError: When the Finding cannot be constructed.
        """

    @abstractmethod
    async def health(self) -> ConnectorHealthStatus:
        """Check the health of the connector and its upstream source.

        Returns:
            ConnectorHealthStatus indicating availability.
        """

    @abstractmethod
    async def close(self) -> None:
        """Release resources (HTTP sessions, DB connections, auth tokens)."""
