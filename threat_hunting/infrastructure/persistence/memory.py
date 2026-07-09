"""In-memory + SQLAlchemy persistence adapters.

Responsibility
--------------
Implement repository ports and Unit of Work. Business rules never depend
on these adapters — swap backends via DI without Core changes.
"""

from __future__ import annotations

from typing import Any, Sequence

from threat_hunting.core.application.ports import StorageBackendPort, UnitOfWorkPort
from threat_hunting.core.domain.entities import (
    Campaign,
    ConnectorConfig,
    Finding,
    HuntJob,
    ThreatActor,
    Watchlist,
)
from threat_hunting.core.domain.enums import HealthState
from threat_hunting.core.domain.repositories import (
    CampaignRepositoryPort,
    ConnectorConfigRepositoryPort,
    FindingRepositoryPort,
    HuntJobRepositoryPort,
    ThreatActorRepositoryPort,
    WatchlistRepositoryPort,
)
from threat_hunting.core.domain.value_objects import HealthStatus, utc_now


class InMemoryFindingRepository(FindingRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, Finding] = {}

    async def save(self, finding: Finding) -> Finding:
        self._store[str(finding.id)] = finding
        return finding

    async def get_by_id(self, finding_id: str) -> Finding | None:
        return self._store.get(finding_id)

    async def find_by_content_hash(self, content_hash: str) -> Finding | None:
        for f in self._store.values():
            if f.content_hash == content_hash:
                return f
        return None

    async def find_by_indicator(self, value: str) -> Sequence[Finding]:
        value_l = value.lower()
        return [
            f
            for f in self._store.values()
            if any(i.value.lower() == value_l for i in f.indicators)
        ]

    async def list_recent(self, *, limit: int = 100) -> Sequence[Finding]:
        items = sorted(self._store.values(), key=lambda f: f.created_at, reverse=True)
        return items[:limit]

    async def list_by_connector(self, connector: str, *, limit: int = 100) -> Sequence[Finding]:
        items = [f for f in self._store.values() if f.connector == connector]
        items.sort(key=lambda f: f.created_at, reverse=True)
        return items[:limit]

    async def delete(self, finding_id: str) -> bool:
        return self._store.pop(finding_id, None) is not None


class InMemoryWatchlistRepository(WatchlistRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, Watchlist] = {}

    async def save(self, watchlist: Watchlist) -> Watchlist:
        self._store[watchlist.id] = watchlist
        return watchlist

    async def get_by_id(self, watchlist_id: str) -> Watchlist | None:
        return self._store.get(watchlist_id)

    async def get_by_name(self, name: str) -> Watchlist | None:
        for w in self._store.values():
            if w.name == name:
                return w
        return None

    async def list_enabled(self) -> Sequence[Watchlist]:
        return [w for w in self._store.values() if w.enabled]

    async def list_all(self) -> Sequence[Watchlist]:
        return list(self._store.values())


class InMemoryThreatActorRepository(ThreatActorRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, ThreatActor] = {}

    async def save(self, actor: ThreatActor) -> ThreatActor:
        self._store[actor.id] = actor
        return actor

    async def get_by_id(self, actor_id: str) -> ThreatActor | None:
        return self._store.get(actor_id)

    async def get_by_name(self, name: str) -> ThreatActor | None:
        for a in self._store.values():
            if a.name.lower() == name.lower():
                return a
        return None

    async def list_enabled(self) -> Sequence[ThreatActor]:
        return [a for a in self._store.values() if a.enabled]


class InMemoryCampaignRepository(CampaignRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, Campaign] = {}

    async def save(self, campaign: Campaign) -> Campaign:
        self._store[campaign.id] = campaign
        return campaign

    async def get_by_id(self, campaign_id: str) -> Campaign | None:
        return self._store.get(campaign_id)

    async def list_all(self) -> Sequence[Campaign]:
        return list(self._store.values())


class InMemoryHuntJobRepository(HuntJobRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, HuntJob] = {}

    async def save(self, job: HuntJob) -> HuntJob:
        self._store[job.id] = job
        return job

    async def get_by_id(self, job_id: str) -> HuntJob | None:
        return self._store.get(job_id)

    async def list_recent(self, *, limit: int = 50) -> Sequence[HuntJob]:
        items = sorted(
            self._store.values(),
            key=lambda j: j.started_at or utc_now(),
            reverse=True,
        )
        return items[:limit]


class InMemoryConnectorConfigRepository(ConnectorConfigRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, ConnectorConfig] = {}

    async def save(self, config: ConnectorConfig) -> ConnectorConfig:
        self._store[config.name] = config
        return config

    async def get_by_name(self, name: str) -> ConnectorConfig | None:
        return self._store.get(name)

    async def list_enabled(self) -> Sequence[ConnectorConfig]:
        return [c for c in self._store.values() if c.enabled]

    async def list_all(self) -> Sequence[ConnectorConfig]:
        return list(self._store.values())

    async def list_by_group(self, group: str) -> Sequence[ConnectorConfig]:
        return [c for c in self._store.values() if c.category_group == group]


class InMemoryUnitOfWork(UnitOfWorkPort):
    """In-memory UoW — suitable for tests and default CLI runs."""

    def __init__(self) -> None:
        self.findings = InMemoryFindingRepository()
        self.watchlists = InMemoryWatchlistRepository()
        self.threat_actors = InMemoryThreatActorRepository()
        self.campaigns = InMemoryCampaignRepository()
        self.hunt_jobs = InMemoryHuntJobRepository()
        self.connectors = InMemoryConnectorConfigRepository()
        self._committed = False

    async def __aenter__(self) -> InMemoryUnitOfWork:
        self._committed = False
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if exc[0] is not None:
            await self.rollback()

    async def commit(self) -> None:
        self._committed = True

    async def rollback(self) -> None:
        self._committed = False


class InMemoryStorageBackend(StorageBackendPort):
    """StorageBackendPort adapter over in-memory finding repo."""

    name = "memory"

    def __init__(self, findings: InMemoryFindingRepository | None = None) -> None:
        self._findings = findings or InMemoryFindingRepository()

    async def initialize(self) -> None:
        return None

    async def persist_finding(self, finding: Finding) -> None:
        await self._findings.save(finding)

    async def fetch_finding(self, finding_id: str) -> Finding | None:
        return await self._findings.get_by_id(finding_id)

    async def query_findings(self, **filters: Any) -> Sequence[Finding]:
        limit = int(filters.get("limit", 100))
        connector = filters.get("connector")
        if connector:
            return await self._findings.list_by_connector(str(connector), limit=limit)
        return await self._findings.list_recent(limit=limit)

    async def health(self) -> HealthStatus:
        return HealthStatus(
            component="storage:memory",
            state=HealthState.HEALTHY.value,
            message=f"{len(self._findings._store)} findings",
        )

    async def close(self) -> None:
        return None


__all__ = [
    "InMemoryFindingRepository",
    "InMemoryWatchlistRepository",
    "InMemoryThreatActorRepository",
    "InMemoryCampaignRepository",
    "InMemoryHuntJobRepository",
    "InMemoryConnectorConfigRepository",
    "InMemoryUnitOfWork",
    "InMemoryStorageBackend",
]
