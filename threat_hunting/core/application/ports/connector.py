"""Connector ports & metadata.

Responsibility
--------------
Define the contract every data-source connector must satisfy and the metadata
used to describe/discover it. The application depends on :class:`ConnectorPort`
and :class:`ConnectorRegistryPort`; concrete connectors live in infrastructure
and are auto-discovered (Plugin Pattern).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.entities.raw_item import RawItem
from threat_hunting.core.domain.enums import Category, SourceType


class ConnectorMeta(BaseModel):
    """Static description of a connector (declared on the connector class)."""

    name: str = Field(description="Unique connector id, e.g. 'reddit'.")
    source: SourceType
    category: Category
    description: str = ""
    enabled: bool = True
    groups: list[str] = Field(
        default_factory=list,
        description="Logical groups the connector belongs to (e.g. 'social', 'darkweb').",
    )


class HealthStatus(BaseModel):
    """Result of a connector/component health probe."""

    healthy: bool
    component: str
    detail: str = ""


@runtime_checkable
class ConnectorPort(Protocol):
    """Lifecycle contract implemented by every connector (Template Method)."""

    meta: ConnectorMeta

    def connect(self) -> None:
        """Establish any session/authentication needed before collection."""
        ...

    def collect(self) -> Iterable[RawItem]:
        """Yield raw items from the source."""
        ...

    def parse(self, item: RawItem) -> Finding:
        """Turn a raw item into a provisional :class:`Finding`."""
        ...

    def normalize(self, finding: Finding) -> Finding:
        """Apply connector-specific normalisation to a finding."""
        ...

    def health(self) -> HealthStatus:
        """Probe whether the connector/source is reachable."""
        ...

    def close(self) -> None:
        """Release any resources held by the connector."""
        ...


@runtime_checkable
class ConnectorRegistryPort(Protocol):
    """Contract for discovering and retrieving connectors (Plugin Pattern)."""

    def discover(self) -> None:
        """Scan for and register all available connectors."""
        ...

    def all(self) -> Sequence[ConnectorMeta]:
        """Return metadata for every registered connector."""
        ...

    def get(self, name: str) -> ConnectorPort:
        """Instantiate and return the connector registered under ``name``."""
        ...

    def by_group(self, group: str) -> Sequence[ConnectorPort]:
        """Instantiate every connector belonging to ``group``."""
        ...
