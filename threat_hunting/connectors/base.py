"""BaseConnector — Connector SDK (Template Method + Plugin Pattern).

Responsibility
--------------
Abstract base every connector MUST inherit. Provides Template Method hooks
and shared helpers. New connectors only inherit BaseConnector — Core is
never modified. Discovery via ConnectorRegistry (Plugin Pattern).
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import AsyncIterator
from typing import Any, ClassVar

import structlog

from threat_hunting.core.application.ports import (
    ConnectorPort,
    OpsecTransportPort,
    ParsedDocument,
    RawDocument,
)
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import FindingCategory, HealthState, IndicatorType, Severity
from threat_hunting.core.domain.services import FindingBuilder
from threat_hunting.core.domain.value_objects import (
    FindingMetadata,
    HealthStatus,
    Indicator,
    OpsecProfile,
)
from threat_hunting.core.domain.value_objects import utc_now

logger = structlog.get_logger(__name__)


class BaseConnector(ConnectorPort):
    """SDK base class for all collection connectors.

    Required overrides
    ------------------
    - name (ClassVar)
    - category_group (ClassVar)
    - connect(), collect(), parse(), normalize(), health(), close()

    Optional
    --------
    - default_category, default_source
    - opsec_profile_name
    """

    name: ClassVar[str] = "base"
    category_group: ClassVar[str] = "other"
    default_category: ClassVar[FindingCategory] = FindingCategory.OSINT
    default_source: ClassVar[str] = ""
    opsec_profile_name: ClassVar[str] = "default"

    def __init__(
        self,
        *,
        transport: OpsecTransportPort | None = None,
        opsec_profile: OpsecProfile | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        self._transport = transport
        self._opsec_profile = opsec_profile or OpsecProfile(name=self.opsec_profile_name)
        self._options = options or {}
        self._connected = False
        self._log = logger.bind(connector=self.name)

    @property
    def source(self) -> str:
        return self.default_source or self.name

    @property
    def options(self) -> dict[str, Any]:
        return self._options

    @property
    def transport(self) -> OpsecTransportPort:
        if self._transport is None:
            raise RuntimeError(f"Connector '{self.name}' has no OPSEC transport bound")
        return self._transport

    @property
    def opsec_profile(self) -> OpsecProfile:
        return self._opsec_profile

    # --- Template Method abstract hooks ---

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    def collect(self) -> AsyncIterator[RawDocument]: ...

    @abstractmethod
    async def parse(self, raw: RawDocument) -> ParsedDocument: ...

    @abstractmethod
    async def normalize(self, parsed: ParsedDocument) -> Finding: ...

    async def health(self) -> HealthStatus:
        return HealthStatus(
            component=f"connector:{self.name}",
            state=HealthState.HEALTHY.value if self._connected else HealthState.UNKNOWN.value,
            message="connected" if self._connected else "not connected",
            checked_at=utc_now(),
        )

    async def close(self) -> None:
        self._connected = False
        self._log.info("connector.closed")

    # --- Helpers for subclasses ---

    def build_finding(
        self,
        *,
        title: str,
        description: str = "",
        category: FindingCategory | None = None,
        severity: Severity = Severity.INFORMATIONAL,
        raw_data: dict[str, Any] | None = None,
        url: str | None = None,
        author: str | None = None,
        tags: list[str] | None = None,
        indicators: list[dict[str, str]] | None = None,
        normalized_data: dict[str, Any] | None = None,
    ) -> Finding:
        """Convenience FindingBuilder wrapper for connectors."""
        builder = (
            FindingBuilder()
            .with_title(title)
            .with_description(description)
            .with_source(self.source)
            .with_connector(self.name)
            .with_category(category or self.default_category)
            .with_severity(severity)
            .with_raw_data(raw_data or {})
            .with_normalized_data(normalized_data or {})
            .with_metadata(FindingMetadata(url=url, author=author))
        )
        for tag in tags or []:
            builder.add_tag(tag)
        finding = builder.build()
        for item in indicators or []:
            try:
                finding.add_indicator(
                    Indicator(
                        type=IndicatorType(item["type"]),
                        value=item["value"],
                        context=item.get("context"),
                    )
                )
            except Exception:
                continue
        # Attach extracted indicators from pipeline if present
        extracted = (raw_data or {}).get("_extracted") or (normalized_data or {}).get("extracted")
        if isinstance(extracted, dict):
            for item in extracted.get("indicators", []):
                try:
                    finding.add_indicator(
                        Indicator(
                            type=IndicatorType(item["type"]),
                            value=item["value"],
                            context=item.get("context"),
                        )
                    )
                except Exception:
                    continue
        return finding

    async def http_get(self, url: str, **kwargs: Any) -> Any:
        return await self.transport.get(url, profile=self.opsec_profile, **kwargs)

    async def http_post(self, url: str, **kwargs: Any) -> Any:
        return await self.transport.post(url, profile=self.opsec_profile, **kwargs)


__all__ = ["BaseConnector"]
