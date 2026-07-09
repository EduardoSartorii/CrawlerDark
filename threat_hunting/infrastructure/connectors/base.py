"""``BaseConnector`` — the connector SDK.

Responsibility
--------------
Provide the reusable machinery every connector shares so that authoring a new
source is reduced to overriding ``collect`` (and optionally ``parse`` /
``normalize`` / ``health``). It implements :class:`ConnectorPort` and manages the
OPSEC transport lifecycle, leaving connectors free of network/OPSEC concerns.

Contract for subclasses
------------------------
* MUST set the class attributes ``name`` and ``source``.
* MUST implement :meth:`collect`.
* MAY override :meth:`parse`, :meth:`normalize` and :meth:`health`.
* MUST NOT modify the core or the pipeline.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence
from typing import Any

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.application.ports.connector import ConnectorPort
from threat_hunting.core.application.ports.transport import (
    TransportFactoryPort,
    TransportPort,
)
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import Category, ConnectorStatus
from threat_hunting.infrastructure.config.settings import ConnectorSettings


class BaseConnector(ConnectorPort, abc.ABC):
    """Base class for all connectors (Template Method + Adapter)."""

    name: str = "base"
    source: str = "base"
    #: Default hunting category for findings produced by this connector.
    default_category: Category = Category.OSINT

    def __init__(
        self,
        *,
        transport_factory: TransportFactoryPort | None = None,
        settings: ConnectorSettings | None = None,
    ) -> None:
        self._transport_factory = transport_factory
        self._settings = settings or ConnectorSettings()
        self._transport: TransportPort | None = None

    # -- configuration helpers ---------------------------------------------

    @property
    def options(self) -> dict[str, Any]:
        """Connector-specific options from configuration."""
        return self._settings.options

    @property
    def category(self) -> Category:
        """Resolved hunting category (config overrides the class default)."""
        configured = self._settings.category
        if configured:
            try:
                return Category(configured)
            except ValueError:
                return self.default_category
        return self.default_category

    @property
    def transport(self) -> TransportPort:
        """Return the acquired transport, raising if used before ``connect``."""
        if self._transport is None:
            raise RuntimeError(
                f"connector {self.name!r} used before connect() was called"
            )
        return self._transport

    # -- lifecycle (Template Method) ---------------------------------------

    async def connect(self) -> None:
        """Acquire an OPSEC transport for this connector's profile."""
        if self._transport_factory is not None:
            self._transport = self._transport_factory.for_profile(
                self._settings.opsec_profile
            )

    @abc.abstractmethod
    async def collect(self) -> Sequence[RawRecord]:
        """Collect raw records from the source (implemented per connector)."""

    def parse(self, record: RawRecord) -> RawRecord:
        """Default parse is identity; override for source-specific payloads."""
        return record

    def normalize(self, record: RawRecord) -> Finding:
        """Map a raw record to the canonical ``Finding`` (sensible default)."""
        title = str(record.metadata.get("title") or record.url or self.source)
        return Finding(
            title=title[:300],
            description=record.content[:2000],
            source=record.source,
            connector=self.name,
            category=self.category,
            raw_data=record.raw or {"content": record.content},
            metadata={"url": record.url, **record.metadata},
        )

    async def health(self) -> ConnectorStatus:
        """Default health is HEALTHY when enabled; override for live probes."""
        return (
            ConnectorStatus.HEALTHY
            if self._settings.enabled
            else ConnectorStatus.DISABLED
        )

    async def close(self) -> None:
        """Release the OPSEC transport."""
        if self._transport is not None:
            await self._transport.aclose()
            self._transport = None

    # -- convenience -------------------------------------------------------

    def _record(
        self,
        *,
        content: str,
        url: str | None = None,
        metadata: dict[str, Any] | None = None,
        raw: dict[str, Any] | None = None,
    ) -> RawRecord:
        """Build a :class:`RawRecord` stamped with this connector's identity."""
        return RawRecord(
            source=self.source,
            connector=self.name,
            content=content,
            url=url,
            metadata=metadata or {},
            raw=raw or {},
        )
