"""
SQLAlchemy Repository Adapters.

Concrete implementations of the repository ports using SQLAlchemy 2.0.
These adapters translate between domain entities and database models.

Supports:
    - SQLite (development, testing, small deployments)
    - PostgreSQL (production, large deployments)

Architecture:
    - Adapters implement domain ports (AbstractFindingRepository, etc.)
    - All DB-specific code is isolated here — domain never sees SQLAlchemy
    - Async session management via SQLAlchemy 2.0 async API
    - Mapper functions handle domain ↔ model translation

Design Pattern:
    - Repository Pattern: domain objects, not DB models, are the API
    - Adapter Pattern: maps between two incompatible interfaces
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.domain.entities.finding import (
    Artifact,
    Finding,
    FindingStatus,
    Relationship,
    TimelineEvent,
)
from ...core.domain.entities.indicator import Indicator, IndicatorType, IndicatorStatus
from ...core.domain.repositories import (
    EntityNotFoundError,
    FilterSpec,
    Page,
    PageSpec,
    SortSpec,
)
from ...core.domain.repositories.finding_repository import AbstractFindingRepository
from ...core.domain.repositories.indicator_repository import AbstractIndicatorRepository
from ...core.domain.value_objects import Score, Severity, ThreatCategory
from ...core.domain.value_objects.source_type import SourceType
from ...database.models.finding_model import FindingModel, IndicatorModel


def _finding_to_model(finding: Finding) -> FindingModel:
    """Map a domain Finding to its SQLAlchemy model."""
    return FindingModel(
        id=finding.id,
        title=finding.title,
        description=finding.description,
        source=finding.source,
        source_type=finding.source_type.value if isinstance(finding.source_type, SourceType) else finding.source_type,
        connector=finding.connector,
        category=finding.category.value,
        status=finding.status.value,
        score_value=finding.score.value,
        score_confidence=finding.score.confidence,
        severity=finding.severity.level.name.lower(),
        confidence=finding.confidence,
        raw_data=finding.raw_data,
        normalized_data=finding.normalized_data,
        metadata_=finding.metadata,
        tags=finding.tags,
        tlp=finding.tlp,
        language=finding.language,
        fingerprint=finding.fingerprint,
        source_url=finding.source_url,
        source_id=finding.source_id,
        misp_event_id=finding.misp_event_id,
        opencti_id=finding.opencti_id,
        threat_actor=finding.threat_actor,
        campaign=finding.campaign,
        malware_family=finding.malware_family,
        affected_brands=finding.affected_brands,
        affected_domains=finding.affected_domains,
        country=finding.country,
        indicator_ids=finding.indicator_ids,
        artifact_ids=finding.artifact_ids,
        artifacts=[a.model_dump() for a in finding.artifacts],
        relationships=[r.model_dump() for r in finding.relationships],
        timeline=[t.model_dump() for t in finding.timeline],
        created_at=finding.created_at.replace(tzinfo=None),
        updated_at=finding.updated_at.replace(tzinfo=None),
    )


def _model_to_finding(model: FindingModel) -> Finding:
    """Map a SQLAlchemy model back to a domain Finding."""
    from ...core.domain.value_objects.severity import SeverityLevel

    sev_level = SeverityLevel[model.severity.upper()] if model.severity else SeverityLevel.INFO

    f = Finding(
        id=model.id,
        title=model.title,
        description=model.description,
        source=model.source,
        source_type=SourceType(model.source_type) if model.source_type else SourceType.UNKNOWN,
        connector=model.connector,
        category=ThreatCategory(model.category) if model.category else ThreatCategory.UNKNOWN,
        status=FindingStatus(model.status) if model.status else FindingStatus.NEW,
        score=Score(value=model.score_value, confidence=model.score_confidence),
        severity=Severity(level=sev_level),
        confidence=model.confidence,
        raw_data=model.raw_data,
        normalized_data=model.normalized_data or {},
        metadata=model.metadata_ or {},
        tags=model.tags or [],
        tlp=model.tlp,
        language=model.language,
        fingerprint=model.fingerprint,
        source_url=model.source_url,
        source_id=model.source_id,
        misp_event_id=model.misp_event_id,
        opencti_id=model.opencti_id,
        threat_actor=model.threat_actor,
        campaign=model.campaign,
        malware_family=model.malware_family,
        affected_brands=model.affected_brands or [],
        affected_domains=model.affected_domains or [],
        country=model.country,
        indicator_ids=model.indicator_ids or [],
        artifact_ids=model.artifact_ids or [],
        created_at=model.created_at.replace(tzinfo=timezone.utc),
        updated_at=model.updated_at.replace(tzinfo=timezone.utc),
    )
    return f


class SQLAlchemyFindingRepository(AbstractFindingRepository):
    """
    SQLAlchemy implementation of the Finding repository.
    Supports SQLite and PostgreSQL.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, entity_id: str) -> Finding | None:
        result = await self._session.get(FindingModel, entity_id)
        return _model_to_finding(result) if result else None

    async def get_by_id_or_raise(self, entity_id: str) -> Finding:
        finding = await self.get_by_id(entity_id)
        if not finding:
            raise EntityNotFoundError("Finding", entity_id)
        return finding

    async def save(self, entity: Finding) -> Finding:
        model = _finding_to_model(entity)
        self._session.add(model)
        await self._session.flush()
        return entity

    async def update(self, entity: Finding) -> Finding:
        model = await self._session.get(FindingModel, entity.id)
        if not model:
            raise EntityNotFoundError("Finding", entity.id)
        updated = _finding_to_model(entity)
        for col in FindingModel.__table__.columns:
            setattr(model, col.name, getattr(updated, col.name))
        await self._session.flush()
        return entity

    async def save_or_update(self, entity: Finding) -> Finding:
        existing = await self._session.get(FindingModel, entity.id)
        if existing:
            return await self.update(entity)
        return await self.save(entity)

    async def delete(self, entity_id: str) -> None:
        model = await self._session.get(FindingModel, entity_id)
        if model:
            await self._session.delete(model)
            await self._session.flush()

    async def list(
        self,
        filters: FilterSpec | None = None,
        sort: SortSpec | None = None,
        page: PageSpec | None = None,
    ) -> Page[Finding]:
        q = select(FindingModel)
        if filters:
            q = self._apply_filters(q, filters)
        if sort:
            col = getattr(FindingModel, sort.field, None)
            if col is not None:
                q = q.order_by(col.asc() if sort.ascending else col.desc())

        count_q = select(func.count()).select_from(q.subquery())
        total = (await self._session.execute(count_q)).scalar_one()

        if page:
            q = q.offset(page.offset).limit(page.limit)

        rows = (await self._session.execute(q)).scalars().all()
        return Page(
            items=[_model_to_finding(r) for r in rows],
            total=total,
            spec=page or PageSpec(),
        )

    async def count(self, filters: FilterSpec | None = None) -> int:
        q = select(func.count(FindingModel.id))
        if filters:
            q = self._apply_filters(select(FindingModel), filters)
            q = select(func.count()).select_from(q.subquery())
        return (await self._session.execute(q)).scalar_one()

    async def exists(self, entity_id: str) -> bool:
        result = await self._session.get(FindingModel, entity_id)
        return result is not None

    async def get_by_fingerprint(self, fingerprint: str) -> Finding | None:
        q = select(FindingModel).where(FindingModel.fingerprint == fingerprint).limit(1)
        result = (await self._session.execute(q)).scalar_one_or_none()
        return _model_to_finding(result) if result else None

    async def find_by_connector(self, connector_id: str, since: datetime | None = None, page: PageSpec | None = None) -> Page[Finding]:
        q = select(FindingModel).where(FindingModel.connector == connector_id)
        if since:
            q = q.where(FindingModel.created_at >= since.replace(tzinfo=None))
        total = (await self._session.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
        if page:
            q = q.offset(page.offset).limit(page.limit)
        rows = (await self._session.execute(q)).scalars().all()
        return Page(items=[_model_to_finding(r) for r in rows], total=total, spec=page or PageSpec())

    async def find_by_category(self, category: ThreatCategory, page: PageSpec | None = None) -> Page[Finding]:
        q = select(FindingModel).where(FindingModel.category == category.value)
        total = (await self._session.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
        if page:
            q = q.offset(page.offset).limit(page.limit)
        rows = (await self._session.execute(q)).scalars().all()
        return Page(items=[_model_to_finding(r) for r in rows], total=total, spec=page or PageSpec())

    async def find_by_status(self, status: FindingStatus, page: PageSpec | None = None) -> Page[Finding]:
        q = select(FindingModel).where(FindingModel.status == status.value)
        total = (await self._session.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
        if page:
            q = q.offset(page.offset).limit(page.limit)
        rows = (await self._session.execute(q)).scalars().all()
        return Page(items=[_model_to_finding(r) for r in rows], total=total, spec=page or PageSpec())

    async def find_by_indicator(self, indicator_id: str) -> list[Finding]:
        q = select(FindingModel)
        rows = (await self._session.execute(q)).scalars().all()
        return [_model_to_finding(r) for r in rows if indicator_id in (r.indicator_ids or [])]

    async def find_by_score_range(self, min_score: float, max_score: float = 10.0, page: PageSpec | None = None) -> Page[Finding]:
        q = select(FindingModel).where(
            FindingModel.score_value >= min_score,
            FindingModel.score_value <= max_score,
        ).order_by(FindingModel.score_value.desc())
        total = (await self._session.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
        if page:
            q = q.offset(page.offset).limit(page.limit)
        rows = (await self._session.execute(q)).scalars().all()
        return Page(items=[_model_to_finding(r) for r in rows], total=total, spec=page or PageSpec())

    async def find_for_export(self, min_score: float, exclude_exported: bool = True) -> list[Finding]:
        q = select(FindingModel).where(FindingModel.score_value >= min_score)
        if exclude_exported:
            q = q.where(FindingModel.status != FindingStatus.EXPORTED.value)
        rows = (await self._session.execute(q)).scalars().all()
        return [_model_to_finding(r) for r in rows]

    async def find_by_tag(self, tag: str, page: PageSpec | None = None) -> Page[Finding]:
        q = select(FindingModel)
        rows = (await self._session.execute(q)).scalars().all()
        filtered = [r for r in rows if tag in (r.tags or [])]
        total = len(filtered)
        if page:
            filtered = filtered[page.offset:page.offset + page.limit]
        return Page(items=[_model_to_finding(r) for r in filtered], total=total, spec=page or PageSpec())

    async def search(self, query: str, filters: FilterSpec | None = None, page: PageSpec | None = None) -> Page[Finding]:
        q = select(FindingModel).where(
            FindingModel.title.ilike(f"%{query}%")
        )
        total = (await self._session.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
        if page:
            q = q.offset(page.offset).limit(page.limit)
        rows = (await self._session.execute(q)).scalars().all()
        return Page(items=[_model_to_finding(r) for r in rows], total=total, spec=page or PageSpec())

    async def get_stats(self) -> dict[str, int]:
        total = (await self._session.execute(select(func.count(FindingModel.id)))).scalar_one()
        return {"total": total}

    def _apply_filters(self, q: Any, filters: FilterSpec) -> Any:
        for key, value in filters.items():
            if hasattr(FindingModel, key):
                q = q.where(getattr(FindingModel, key) == value)
        return q
