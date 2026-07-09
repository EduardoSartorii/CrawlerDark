"""SQLAlchemy 2 async persistence (SQLite / PostgreSQL).

Responsibility
--------------
Concrete StorageBackendPort + repository adapters using SQLAlchemy 2.
Schema is intentionally simple (JSON columns) to remain portable and
Django-mappable later.
"""

from __future__ import annotations

import json
from typing import Any, Sequence

from sqlalchemy import String, Text, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from threat_hunting.core.application.ports import StorageBackendPort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import FindingCategory, HealthState, Severity
from threat_hunting.core.domain.repositories import FindingRepositoryPort
from threat_hunting.core.domain.value_objects import (
    Confidence,
    FindingId,
    FindingMetadata,
    HealthStatus,
    Indicator,
    Score,
    Tag,
    utc_now,
)
from threat_hunting.core.domain.enums import IndicatorType


class Base(DeclarativeBase):
    pass


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(128))
    connector: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(32))
    score: Mapped[str] = mapped_column(String(32), default="0")
    confidence: Mapped[str] = mapped_column(String(32), default="0.5")
    content_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    payload: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[str] = mapped_column(String(64))


def finding_to_model(finding: Finding) -> FindingModel:
    payload = finding.model_dump(mode="json")
    return FindingModel(
        id=str(finding.id),
        title=finding.title,
        description=finding.description,
        source=finding.source,
        connector=finding.connector,
        category=finding.category.value,
        severity=finding.severity.value,
        score=str(float(finding.score)),
        confidence=str(float(finding.confidence)),
        content_hash=finding.content_hash,
        payload=json.dumps(payload),
        created_at=finding.created_at.isoformat(),
        updated_at=finding.updated_at.isoformat(),
    )


def model_to_finding(row: FindingModel) -> Finding:
    data = json.loads(row.payload)
    # Reconstruct via model_validate for nested VOs
    return Finding.model_validate(data)


class SqlAlchemyFindingRepository(FindingRepositoryPort):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, finding: Finding) -> Finding:
        existing = await self._session.get(FindingModel, str(finding.id))
        model = finding_to_model(finding)
        if existing:
            for col in (
                "title",
                "description",
                "source",
                "connector",
                "category",
                "severity",
                "score",
                "confidence",
                "content_hash",
                "payload",
                "updated_at",
            ):
                setattr(existing, col, getattr(model, col))
        else:
            self._session.add(model)
        await self._session.flush()
        return finding

    async def get_by_id(self, finding_id: str) -> Finding | None:
        row = await self._session.get(FindingModel, finding_id)
        return model_to_finding(row) if row else None

    async def find_by_content_hash(self, content_hash: str) -> Finding | None:
        result = await self._session.execute(
            select(FindingModel).where(FindingModel.content_hash == content_hash).limit(1)
        )
        row = result.scalar_one_or_none()
        return model_to_finding(row) if row else None

    async def find_by_indicator(self, value: str) -> Sequence[Finding]:
        # JSON payload scan — acceptable for SQLite; use GIN in Postgres later
        result = await self._session.execute(select(FindingModel))
        rows = result.scalars().all()
        value_l = value.lower()
        out: list[Finding] = []
        for row in rows:
            f = model_to_finding(row)
            if any(i.value.lower() == value_l for i in f.indicators):
                out.append(f)
        return out

    async def list_recent(self, *, limit: int = 100) -> Sequence[Finding]:
        result = await self._session.execute(
            select(FindingModel).order_by(FindingModel.created_at.desc()).limit(limit)
        )
        return [model_to_finding(r) for r in result.scalars().all()]

    async def list_by_connector(self, connector: str, *, limit: int = 100) -> Sequence[Finding]:
        result = await self._session.execute(
            select(FindingModel)
            .where(FindingModel.connector == connector)
            .order_by(FindingModel.created_at.desc())
            .limit(limit)
        )
        return [model_to_finding(r) for r in result.scalars().all()]

    async def delete(self, finding_id: str) -> bool:
        row = await self._session.get(FindingModel, finding_id)
        if row is None:
            return False
        await self._session.delete(row)
        await self._session.flush()
        return True


class SqlAlchemyStorageBackend(StorageBackendPort):
    name = "sqlalchemy"

    def __init__(self, database_url: str = "sqlite+aiosqlite:///./data/threat_hunting.db") -> None:
        self._url = database_url
        self._engine = create_async_engine(database_url, echo=False)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    async def initialize(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def persist_finding(self, finding: Finding) -> None:
        async with self._session_factory() as session:
            repo = SqlAlchemyFindingRepository(session)
            await repo.save(finding)
            await session.commit()

    async def fetch_finding(self, finding_id: str) -> Finding | None:
        async with self._session_factory() as session:
            repo = SqlAlchemyFindingRepository(session)
            return await repo.get_by_id(finding_id)

    async def query_findings(self, **filters: Any) -> Sequence[Finding]:
        async with self._session_factory() as session:
            repo = SqlAlchemyFindingRepository(session)
            limit = int(filters.get("limit", 100))
            connector = filters.get("connector")
            if connector:
                return await repo.list_by_connector(str(connector), limit=limit)
            return await repo.list_recent(limit=limit)

    async def health(self) -> HealthStatus:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(select(1))
            return HealthStatus(
                component="storage:sqlalchemy",
                state=HealthState.HEALTHY.value,
                message=self._url.split("://")[0],
                checked_at=utc_now(),
            )
        except Exception as exc:
            return HealthStatus(
                component="storage:sqlalchemy",
                state=HealthState.UNHEALTHY.value,
                message=str(exc),
                checked_at=utc_now(),
            )

    async def close(self) -> None:
        await self._engine.dispose()

    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._session_factory


__all__ = [
    "Base",
    "FindingModel",
    "SqlAlchemyFindingRepository",
    "SqlAlchemyStorageBackend",
]
