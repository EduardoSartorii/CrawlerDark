"""SQLAlchemy repository adapter for SQLite and PostgreSQL."""

from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from threat_hunting.core.domain.entities import Finding
from threat_hunting.database.models import Base, FindingRecord


class SqlAlchemyFindingRepository:
    """Repository implementation backed by SQLAlchemy 2 sessions."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, finding: Finding) -> None:
        """Persist a finding as canonical JSON."""

        record = FindingRecord(
            id=finding.id,
            content_hash=finding.content_hash,
            title=finding.title,
            source=finding.source,
            connector=finding.connector,
            category=finding.category,
            severity=finding.severity.value,
            score=finding.score,
            description=finding.description,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
            payload=finding.model_dump(mode="json"),
        )
        self._session.merge(record)

    def list(self) -> list[Finding]:
        """Return all persisted findings."""

        records = self._session.scalars(select(FindingRecord)).all()
        return [Finding.model_validate(record.payload) for record in records]

    def get_by_hash(self, content_hash: str) -> Finding | None:
        """Return one finding by content hash."""

        record = self._session.scalar(select(FindingRecord).where(FindingRecord.content_hash == content_hash))
        return Finding.model_validate(record.payload) if record else None


class SqlAlchemyUnitOfWork:
    """SQLAlchemy Unit of Work for SQLite and PostgreSQL."""

    def __init__(self, url: str) -> None:
        self._engine = create_engine(url)
        Base.metadata.create_all(self._engine)
        self._session_factory = sessionmaker(bind=self._engine, expire_on_commit=False)

    def __enter__(self) -> "SqlAlchemyUnitOfWork":
        self._session = self._session_factory()
        self.findings = SqlAlchemyFindingRepository(self._session)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self._session.close()

    def commit(self) -> None:
        """Commit the active SQL transaction."""

        self._session.commit()

    def rollback(self) -> None:
        """Rollback the active SQL transaction."""

        self._session.rollback()
