"""
FindingRepository — SQLAlchemy Implementation
==============================================

Implements IFindingRepository using async SQLAlchemy.
Translates between FindingModel (ORM) and Finding (domain entity).

Architecture:
    - All queries are async.
    - Domain entities are never leaked to the ORM layer.
    - JSON serialization/deserialization handles complex fields.
    - The repository never manages transactions — that is the UoW's job.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from threat_hunting.core.domain.entities.finding import (
    Artifact,
    DetectionResult,
    Finding,
    FindingStatus,
    Relationship,
    TimelineEntry,
)
from threat_hunting.core.domain.ports.repositories import IFindingRepository
from threat_hunting.core.domain.value_objects.category import Category
from threat_hunting.core.domain.value_objects.score import Score
from threat_hunting.core.domain.value_objects.severity import Severity
from threat_hunting.core.domain.value_objects.source import SourceType
from threat_hunting.infrastructure.database.models import FindingModel

import xxhash


class SQLAlchemyFindingRepository(IFindingRepository):
    """SQLAlchemy async implementation of IFindingRepository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, finding: Finding) -> None:
        """Insert or update a Finding in the database."""
        existing = await self._session.get(FindingModel, finding.id)
        content_hash = xxhash.xxh64_hexdigest(
            f"{finding.connector}:{finding.source_id or ''}:{finding.title.lower()}"
        )

        if existing:
            self._update_model(existing, finding, content_hash)
        else:
            model = self._to_model(finding, content_hash)
            self._session.add(model)

    async def get_by_id(self, finding_id: str) -> Finding | None:
        """Return a Finding by its ID."""
        model = await self._session.get(FindingModel, finding_id)
        return self._to_entity(model) if model else None

    async def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        connector: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        tags: list[str] | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> list[Finding]:
        """Return paginated Findings matching criteria."""
        query = select(FindingModel)
        filters = []

        if connector:
            filters.append(FindingModel.connector == connector)
        if severity:
            filters.append(FindingModel.severity == severity)
        if category:
            filters.append(FindingModel.category == category)
        if since:
            filters.append(FindingModel.created_at >= since)
        if until:
            filters.append(FindingModel.created_at <= until)
        if status:
            filters.append(FindingModel.status == status)
        if search:
            like = f"%{search}%"
            filters.append(
                or_(
                    FindingModel.title.ilike(like),
                    FindingModel.description.ilike(like),
                )
            )

        if filters:
            query = query.where(and_(*filters))

        query = query.order_by(FindingModel.created_at.desc()).limit(limit).offset(offset)
        result = await self._session.execute(query)
        return [self._to_entity(m) for m in result.scalars().all()]

    async def count(self, criteria: dict[str, Any] | None = None) -> int:
        """Return total count of Findings matching criteria."""
        query = select(func.count()).select_from(FindingModel)
        result = await self._session.execute(query)
        return result.scalar_one()

    async def delete(self, finding_id: str) -> None:
        """Delete a Finding by ID."""
        model = await self._session.get(FindingModel, finding_id)
        if model:
            await self._session.delete(model)

    async def exists_by_hash(self, content_hash: str) -> bool:
        """Check for a Finding with the given content hash."""
        query = select(func.count()).select_from(FindingModel).where(
            FindingModel.content_hash == content_hash
        )
        result = await self._session.execute(query)
        return result.scalar_one() > 0

    async def find_similar(self, finding: Finding, threshold: float) -> list[Finding]:
        """Return Findings with title similar to the given Finding (simplified)."""
        # Full fuzzy similarity requires RapidFuzz — here we do a LIKE approximation
        # for the repository. The DeduplicationEngine applies the fuzzy check on top.
        words = finding.title.split()[:4]
        if not words:
            return []
        like = f"%{words[0]}%"
        query = (
            select(FindingModel)
            .where(
                and_(
                    FindingModel.title.ilike(like),
                    FindingModel.id != finding.id,
                    FindingModel.connector == finding.connector,
                )
            )
            .limit(20)
        )
        result = await self._session.execute(query)
        return [self._to_entity(m) for m in result.scalars().all()]

    # ── Private helpers ────────────────────────────────────────────────────────

    def _to_model(self, finding: Finding, content_hash: str) -> FindingModel:
        return FindingModel(
            id=finding.id,
            title=finding.title,
            description=finding.description,
            source=finding.source.value,
            connector=finding.connector,
            category=finding.category.value,
            status=finding.status.value,
            severity=finding.severity.value,
            score_value=finding.score.value,
            score_confidence=finding.score.confidence,
            confidence=finding.confidence,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
            source_published_at=finding.source_published_at,
            raw_data=str(finding.raw_data) if finding.raw_data else None,
            normalized_data_json=json.dumps(finding.normalized_data),
            metadata_json=json.dumps(finding.metadata),
            tags_json=json.dumps(finding.tags),
            indicators_json=json.dumps(finding.indicators),
            relationships_json=json.dumps([r.model_dump() for r in finding.relationships]),
            detection_results_json=json.dumps([d.model_dump() for d in finding.detection_results]),
            artifacts_json=json.dumps([a.model_dump() for a in finding.artifacts]),
            export_log_json=json.dumps({k: v.isoformat() for k, v in finding.export_log.items()}),
            timeline_json=json.dumps([t.model_dump(mode="json") for t in finding.timeline]),
            source_url=finding.source_url,
            source_id=finding.source_id,
            duplicate_of=finding.duplicate_of,
            correlation_group=finding.correlation_group,
            content_hash=content_hash,
        )

    def _update_model(self, model: FindingModel, finding: Finding, content_hash: str) -> None:
        model.title = finding.title
        model.status = finding.status.value
        model.severity = finding.severity.value
        model.score_value = finding.score.value
        model.score_confidence = finding.score.confidence
        model.confidence = finding.confidence
        model.updated_at = finding.updated_at
        model.normalized_data_json = json.dumps(finding.normalized_data)
        model.metadata_json = json.dumps(finding.metadata)
        model.tags_json = json.dumps(finding.tags)
        model.indicators_json = json.dumps(finding.indicators)
        model.relationships_json = json.dumps([r.model_dump() for r in finding.relationships])
        model.detection_results_json = json.dumps([d.model_dump() for d in finding.detection_results])
        model.export_log_json = json.dumps({k: v.isoformat() for k, v in finding.export_log.items()})
        model.timeline_json = json.dumps([t.model_dump(mode="json") for t in finding.timeline])
        model.duplicate_of = finding.duplicate_of
        model.correlation_group = finding.correlation_group
        model.content_hash = content_hash

    def _to_entity(self, model: FindingModel) -> Finding:
        return Finding(
            id=model.id,
            title=model.title,
            description=model.description,
            source=SourceType(model.source),
            connector=model.connector,
            category=Category(model.category),
            status=FindingStatus(model.status),
            severity=Severity(model.severity),
            score=Score(value=model.score_value, confidence=model.score_confidence),
            confidence=model.confidence,
            created_at=model.created_at,
            updated_at=model.updated_at,
            source_published_at=model.source_published_at,
            raw_data=model.raw_data,
            normalized_data=json.loads(model.normalized_data_json or "{}"),
            metadata=json.loads(model.metadata_json or "{}"),
            tags=json.loads(model.tags_json or "[]"),
            indicators=json.loads(model.indicators_json or "[]"),
            relationships=[
                Relationship(**r) for r in json.loads(model.relationships_json or "[]")
            ],
            detection_results=[
                DetectionResult(**d) for d in json.loads(model.detection_results_json or "[]")
            ],
            artifacts=[
                Artifact(**a) for a in json.loads(model.artifacts_json or "[]")
            ],
            export_log={},
            timeline=[
                TimelineEntry(**t) for t in json.loads(model.timeline_json or "[]")
            ],
            source_url=model.source_url,
            source_id=model.source_id,
            duplicate_of=model.duplicate_of,
            correlation_group=model.correlation_group,
        )
