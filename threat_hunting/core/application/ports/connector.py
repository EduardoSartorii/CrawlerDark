"""Connector port (collection contract).

Responsibility
--------------
Define the lifecycle every collection source must honour. The concrete
``BaseConnector`` SDK (infrastructure) implements this port and every real
connector subclasses that SDK. The application only ever sees this interface.

Contract
--------
``connect`` -> ``collect`` -> ``parse`` -> ``normalize`` -> ``close`` with
``health`` callable at any time. Methods are async because collection is
I/O-bound (network).
"""

from __future__ import annotations

import abc
from collections.abc import Sequence

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import ConnectorStatus


class ConnectorPort(abc.ABC):
    """Abstract collection source."""

    #: Unique connector name (used by the CLI and registry).
    name: str = "abstract"
    #: Human-readable source label.
    source: str = "abstract"

    @abc.abstractmethod
    async def connect(self) -> None:
        """Acquire any resources needed for collection (sessions, clients)."""

    @abc.abstractmethod
    async def collect(self) -> Sequence[RawRecord]:
        """Collect raw records from the source."""

    @abc.abstractmethod
    def parse(self, record: RawRecord) -> RawRecord:
        """Turn source-specific payloads into clean text/structured content."""

    @abc.abstractmethod
    def normalize(self, record: RawRecord) -> Finding:
        """Map a raw record into the canonical ``Finding`` model."""

    @abc.abstractmethod
    async def health(self) -> ConnectorStatus:
        """Report the connector's current health/availability."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Release resources acquired in :meth:`connect`."""
