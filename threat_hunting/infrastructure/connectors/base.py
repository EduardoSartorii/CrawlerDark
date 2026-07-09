"""Base connector SDK and connector implementations.

All connectors inherit BaseConnector and are auto-discovered via plugin registry.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import AsyncIterator
from typing import Any

import structlog

from threat_hunting.core.contracts.services import (
    CollectionContext,
    IConnector,
    ParsedData,
    RawPayload,
)
from threat_hunting.core.domain.entities import FindingDraft
from threat_hunting.core.domain.enums import HealthStatus, SourceType
from threat_hunting.infrastructure.opsec.transport import OpsecProfile, OpsecTransport

logger = structlog.get_logger(__name__)


class BaseConnector(IConnector):
    """Abstract base connector — all source connectors MUST inherit this class.

    Implements the connector SDK contract:
    connect() → collect() → parse() → normalize() → health() → close()

    OPSEC transport is injected; connectors never manage proxies directly.
    """

    name: str = "base"
    source_type: str = SourceType.API.value

    def __init__(self, transport: OpsecTransport | None = None, config: dict[str, Any] | None = None) -> None:
        self._transport = transport
        self._config = config or {}
        self._connected = False

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to data source."""
        self._connected = True

    @abstractmethod
    async def collect(self, context: CollectionContext) -> AsyncIterator[RawPayload]:
        """Collect raw payloads. Must be overridden by subclasses."""
        if False:  # pragma: no cover
            yield RawPayload({})

    @abstractmethod
    def parse(self, payload: RawPayload) -> ParsedData:
        """Parse raw payload into structured data."""

    @abstractmethod
    def normalize(self, parsed: ParsedData) -> FindingDraft:
        """Normalize parsed data into finding draft."""

    async def health(self) -> HealthStatus:
        """Default health check based on connection state."""
        return HealthStatus.HEALTHY if self._connected else HealthStatus.DEGRADED

    async def close(self) -> None:
        """Release resources."""
        if self._transport:
            await self._transport.close()
        self._connected = False

    def _default_normalize(self, parsed: ParsedData, title_field: str = "title") -> FindingDraft:
        """Helper for standard normalization across social connectors."""
        fields = parsed.fields
        return FindingDraft(
            title=str(fields.get(title_field, f"{self.name} finding")),
            description=str(fields.get("content", fields.get("body", ""))),
            source=SourceType(self.source_type),
            connector=self.name,
            raw_data=parsed.fields,
            normalized_data={"content": parsed.content, **parsed.metadata},
            metadata={"source_uri": parsed.metadata.get("source_uri", "")},
        )
