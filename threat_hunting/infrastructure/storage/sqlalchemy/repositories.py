"""Repositórios SQLAlchemy — implementam as interfaces do domínio.

Cada repositório trabalha em uma ``AsyncSession`` recebida pelo ``UnitOfWork``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.domain.entities import (
    DetectionRule,
    Finding,
    Indicator,
    Job,
    ThreatActor,
    WatchlistItem,
)
from .mappers import (
    apply_finding_updates,
    apply_job_updates,
    finding_from_model,
    finding_to_model,
    indicator_from_model,
    indicator_to_model,
    job_from_model,
    job_to_model,
    rule_from_model,
    rule_to_model,
    threat_actor_from_model,
    threat_actor_to_model,
    watchlist_from_model,
    watchlist_to_model,
)
from .models import (
    DetectionRuleModel,
    FindingModel,
    IndicatorModel,
    JobModel,
    ThreatActorModel,
    WatchlistItemModel,
)


class SqlAlchemyFindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, id: UUID) -> Finding | None:
        model = await self._session.get(FindingModel, id)
        return finding_from_model(model) if model else None

    async def add(self, entity: Finding) -> None:
        model = finding_to_model(entity)
        self._session.add(model)

    async def update(self, entity: Finding) -> None:
        model = await self._session.get(FindingModel, entity.id)
        if model is None:
            self._session.add(finding_to_model(entity))
            return
        apply_finding_updates(model, entity)
        # Reset indicators (simples; para performance pode-se fazer diff)
        await self._session.execute(
            delete(IndicatorModel).where(IndicatorModel.finding_id == entity.id)
        )
        for ind in entity.indicators:
            im = indicator_to_model(ind)
            im.finding_id = entity.id
            self._session.add(im)

    async def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Finding]:
        stmt = (
            select(FindingModel)
            .order_by(FindingModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = (await self._session.execute(stmt)).scalars().unique().all()
        return [finding_from_model(m) for m in rows]

    async def find_by_dedup_hash(self, dedup_hash: str) -> Finding | None:
        stmt = select(FindingModel).where(FindingModel.dedup_hash == dedup_hash).limit(1)
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        return finding_from_model(model) if model else None

    async def find_recent(self, *, limit: int = 500) -> Sequence[Finding]:
        return await self.list(limit=limit)

    async def find_unexported(
        self, target: str, *, min_score: float = 0.0, limit: int = 200
    ) -> Sequence[Finding]:
        stmt = (
            select(FindingModel)
            .where(FindingModel.score >= min_score)
            .order_by(FindingModel.created_at.desc())
            .limit(limit)
        )
        rows = (await self._session.execute(stmt)).scalars().unique().all()
        result: list[Finding] = []
        for row in rows:
            if target in (row.exported_to or []):
                continue
            result.append(finding_from_model(row))
        return result


class SqlAlchemyIndicatorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, id: UUID) -> Indicator | None:
        model = await self._session.get(IndicatorModel, id)
        return indicator_from_model(model) if model else None

    async def add(self, entity: Indicator) -> None:
        self._session.add(indicator_to_model(entity))

    async def update(self, entity: Indicator) -> None:
        model = await self._session.get(IndicatorModel, entity.id)
        if model is None:
            self._session.add(indicator_to_model(entity))
            return
        model.confidence = int(entity.confidence)
        model.tags = sorted(entity.tags)
        model.last_seen = entity.last_seen
        model.context = dict(entity.context)

    async def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Indicator]:
        stmt = select(IndicatorModel).limit(limit).offset(offset)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [indicator_from_model(m) for m in rows]

    async def find_by_value(self, value: str) -> Sequence[Indicator]:
        stmt = select(IndicatorModel).where(IndicatorModel.value == value)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [indicator_from_model(m) for m in rows]


class SqlAlchemyThreatActorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, id: UUID) -> ThreatActor | None:
        model = await self._session.get(ThreatActorModel, id)
        return threat_actor_from_model(model) if model else None

    async def add(self, entity: ThreatActor) -> None:
        self._session.add(threat_actor_to_model(entity))

    async def update(self, entity: ThreatActor) -> None:
        model = await self._session.get(ThreatActorModel, entity.id)
        if model is None:
            self._session.add(threat_actor_to_model(entity))
            return
        model.name = entity.name
        model.aliases = sorted(entity.aliases)
        model.description = entity.description
        model.motivations = sorted(entity.motivations)
        model.countries = sorted(entity.countries)
        model.tags = sorted(entity.tags)
        model.context = dict(entity.context)

    async def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[ThreatActor]:
        stmt = select(ThreatActorModel).limit(limit).offset(offset)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [threat_actor_from_model(m) for m in rows]

    async def find_by_alias(self, alias: str) -> ThreatActor | None:
        stmt = select(ThreatActorModel)
        rows = (await self._session.execute(stmt)).scalars().all()
        alias_lower = alias.lower()
        for m in rows:
            if m.name.lower() == alias_lower or alias_lower in [a.lower() for a in (m.aliases or [])]:
                return threat_actor_from_model(m)
        return None


class SqlAlchemyWatchlistRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, id: UUID) -> WatchlistItem | None:
        model = await self._session.get(WatchlistItemModel, id)
        return watchlist_from_model(model) if model else None

    async def add(self, entity: WatchlistItem) -> None:
        self._session.add(watchlist_to_model(entity))

    async def update(self, entity: WatchlistItem) -> None:
        model = await self._session.get(WatchlistItemModel, entity.id)
        if model is None:
            self._session.add(watchlist_to_model(entity))
            return
        model.kind = entity.kind.value
        model.value = entity.value
        model.aliases = sorted(entity.aliases)
        model.tags = sorted(entity.tags)
        model.enabled = entity.enabled
        model.context = dict(entity.context)

    async def list(self, *, limit: int = 500, offset: int = 0) -> Sequence[WatchlistItem]:
        stmt = select(WatchlistItemModel).limit(limit).offset(offset)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [watchlist_from_model(m) for m in rows]

    async def all_enabled(self) -> Sequence[WatchlistItem]:
        stmt = select(WatchlistItemModel).where(WatchlistItemModel.enabled.is_(True))
        rows = (await self._session.execute(stmt)).scalars().all()
        return [watchlist_from_model(m) for m in rows]

    async def bulk_replace(self, items: Iterable[WatchlistItem]) -> None:
        await self._session.execute(delete(WatchlistItemModel))
        for it in items:
            self._session.add(watchlist_to_model(it))


class SqlAlchemyDetectionRuleRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, id: UUID) -> DetectionRule | None:
        model = await self._session.get(DetectionRuleModel, id)
        return rule_from_model(model) if model else None

    async def add(self, entity: DetectionRule) -> None:
        self._session.add(rule_to_model(entity))

    async def update(self, entity: DetectionRule) -> None:
        model = await self._session.get(DetectionRuleModel, entity.id)
        if model is None:
            self._session.add(rule_to_model(entity))
            return
        model.pattern = entity.pattern
        model.description = entity.description
        model.category = entity.category.value
        model.severity = entity.severity.name
        model.confidence = int(entity.confidence)
        model.tags = sorted(entity.tags)
        model.enabled = entity.enabled
        model.depends_on = list(entity.depends_on)

    async def list(self, *, limit: int = 500, offset: int = 0) -> Sequence[DetectionRule]:
        stmt = select(DetectionRuleModel).limit(limit).offset(offset)
        rows = (await self._session.execute(stmt)).scalars().all()
        return [rule_from_model(m) for m in rows]

    async def all_enabled(self) -> Sequence[DetectionRule]:
        stmt = select(DetectionRuleModel).where(DetectionRuleModel.enabled.is_(True))
        rows = (await self._session.execute(stmt)).scalars().all()
        return [rule_from_model(m) for m in rows]


class SqlAlchemyJobRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, id: UUID) -> Job | None:
        model = await self._session.get(JobModel, id)
        return job_from_model(model) if model else None

    async def add(self, entity: Job) -> None:
        self._session.add(job_to_model(entity))

    async def update(self, entity: Job) -> None:
        model = await self._session.get(JobModel, entity.id)
        if model is None:
            self._session.add(job_to_model(entity))
            return
        apply_job_updates(model, entity)

    async def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[Job]:
        stmt = (
            select(JobModel)
            .order_by(JobModel.started_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [job_from_model(m) for m in rows]

    async def find_by_connector(self, connector: str, *, limit: int = 50) -> Sequence[Job]:
        stmt = (
            select(JobModel)
            .where(JobModel.connector == connector)
            .order_by(JobModel.started_at.desc())
            .limit(limit)
        )
        rows = (await self._session.execute(stmt)).scalars().all()
        return [job_from_model(m) for m in rows]
