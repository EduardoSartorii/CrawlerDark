"""Repository ports (Hexagonal Architecture).

Responsibility
--------------
Define abstract persistence contracts. Infrastructure adapters implement
these interfaces. The Core NEVER imports concrete storage drivers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Sequence

from threat_hunting.core.domain.entities import (
    Campaign,
    ConnectorConfig,
    Finding,
    HuntJob,
    ThreatActor,
    Watchlist,
)


class FindingRepositoryPort(ABC):
    """Persistence port for Finding aggregate."""

    @abstractmethod
    async def save(self, finding: Finding) -> Finding:
        """Persist or update a Finding."""

    @abstractmethod
    async def get_by_id(self, finding_id: str) -> Finding | None:
        """Retrieve Finding by id."""

    @abstractmethod
    async def find_by_content_hash(self, content_hash: str) -> Finding | None:
        """Lookup by content hash for deduplication."""

    @abstractmethod
    async def find_by_indicator(self, value: str) -> Sequence[Finding]:
        """Find Findings sharing an IOC value."""

    @abstractmethod
    async def list_recent(self, *, limit: int = 100) -> Sequence[Finding]:
        """List most recent Findings."""

    @abstractmethod
    async def list_by_connector(
        self, connector: str, *, limit: int = 100
    ) -> Sequence[Finding]:
        """List Findings produced by a connector."""

    @abstractmethod
    async def delete(self, finding_id: str) -> bool:
        """Delete a Finding by id."""


class WatchlistRepositoryPort(ABC):
    """Persistence port for Watchlist aggregate."""

    @abstractmethod
    async def save(self, watchlist: Watchlist) -> Watchlist: ...

    @abstractmethod
    async def get_by_id(self, watchlist_id: str) -> Watchlist | None: ...

    @abstractmethod
    async def get_by_name(self, name: str) -> Watchlist | None: ...

    @abstractmethod
    async def list_enabled(self) -> Sequence[Watchlist]: ...

    @abstractmethod
    async def list_all(self) -> Sequence[Watchlist]: ...


class ThreatActorRepositoryPort(ABC):
    """Persistence port for ThreatActor aggregate."""

    @abstractmethod
    async def save(self, actor: ThreatActor) -> ThreatActor: ...

    @abstractmethod
    async def get_by_id(self, actor_id: str) -> ThreatActor | None: ...

    @abstractmethod
    async def get_by_name(self, name: str) -> ThreatActor | None: ...

    @abstractmethod
    async def list_enabled(self) -> Sequence[ThreatActor]: ...


class CampaignRepositoryPort(ABC):
    """Persistence port for Campaign aggregate."""

    @abstractmethod
    async def save(self, campaign: Campaign) -> Campaign: ...

    @abstractmethod
    async def get_by_id(self, campaign_id: str) -> Campaign | None: ...

    @abstractmethod
    async def list_all(self) -> Sequence[Campaign]: ...


class HuntJobRepositoryPort(ABC):
    """Persistence port for HuntJob aggregate."""

    @abstractmethod
    async def save(self, job: HuntJob) -> HuntJob: ...

    @abstractmethod
    async def get_by_id(self, job_id: str) -> HuntJob | None: ...

    @abstractmethod
    async def list_recent(self, *, limit: int = 50) -> Sequence[HuntJob]: ...


class ConnectorConfigRepositoryPort(ABC):
    """Persistence port for ConnectorConfig."""

    @abstractmethod
    async def save(self, config: ConnectorConfig) -> ConnectorConfig: ...

    @abstractmethod
    async def get_by_name(self, name: str) -> ConnectorConfig | None: ...

    @abstractmethod
    async def list_enabled(self) -> Sequence[ConnectorConfig]: ...

    @abstractmethod
    async def list_all(self) -> Sequence[ConnectorConfig]: ...

    @abstractmethod
    async def list_by_group(self, group: str) -> Sequence[ConnectorConfig]: ...


__all__ = [
    "FindingRepositoryPort",
    "WatchlistRepositoryPort",
    "ThreatActorRepositoryPort",
    "CampaignRepositoryPort",
    "HuntJobRepositoryPort",
    "ConnectorConfigRepositoryPort",
]
