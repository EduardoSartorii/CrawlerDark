"""Repository and Unit of Work adapters backed by SQLAlchemy."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from threat_hunting.database.models import FindingRecord
from threat_hunting.domain.entities import Finding, Severity


class SqlAlchemyFindingRepository:
    """Repository adapter for finding persistence."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add_many(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            record = FindingRecord(
                id=finding.id,
                title=finding.title,
                description=finding.description,
                source=finding.source,
                connector=finding.connector,
                category=finding.category,
                severity=finding.severity.value,
                score=finding.score,
                confidence=finding.confidence,
                created_at=finding.created_at,
                updated_at=finding.updated_at,
                raw_data=finding.raw_data,
                normalized_data=finding.normalized_data,
                metadata_json=finding.metadata,
                tags=finding.tags,
                artifacts=finding.artifacts,
                indicators=finding.indicators,
                relationships=finding.relationships,
                timeline=finding.timeline,
            )
            self._session.merge(record)

    def list_recent(self, limit: int = 100) -> list[Finding]:
        statement = select(FindingRecord).order_by(FindingRecord.updated_at.desc()).limit(limit)
        rows = self._session.execute(statement).scalars().all()
        return [
            Finding(
                id=row.id,
                title=row.title,
                description=row.description,
                source=row.source,
                connector=row.connector,
                category=row.category,
                severity=Severity(row.severity),
                score=row.score,
                confidence=row.confidence,
                created_at=row.created_at,
                updated_at=row.updated_at,
                raw_data=row.raw_data or {},
                normalized_data=row.normalized_data or {},
                metadata=row.metadata_json or {},
                tags=row.tags or [],
                artifacts=row.artifacts or [],
                indicators=row.indicators or [],
                relationships=row.relationships or [],
                timeline=row.timeline or [],
            )
            for row in rows
        ]


class SqlAlchemyUnitOfWork(AbstractContextManager):
    """Unit of Work implementation for transaction boundaries."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory
        self._session: Session | None = None
        self.findings: SqlAlchemyFindingRepository

    def __enter__(self) -> "SqlAlchemyUnitOfWork":
        self._session = self._session_factory()
        self.findings = SqlAlchemyFindingRepository(self._session)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type:
            self.rollback()
        if self._session is not None:
            self._session.close()
            self._session = None

    def commit(self) -> None:
        if self._session is None:
            msg = "UnitOfWork session is not initialized"
            raise RuntimeError(msg)
        self._session.commit()

    def rollback(self) -> None:
        if self._session is not None:
            self._session.rollback()
