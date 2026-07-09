"""SQLAlchemy repository and Unit of Work adapters."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from threat_hunting.core.domain.entities import Finding
from threat_hunting.database.models import Base, FindingRecord


class SqlAlchemyFindingRepository:
    """Finding repository backed by SQLAlchemy 2."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def save(self, finding: Finding) -> Finding:
        """Persist or update a finding record."""

        payload = finding.model_dump(mode="json")
        record = FindingRecord.from_payload(
            finding_id=str(finding.id),
            fingerprint=finding.fingerprint_payload(),
            created_at=finding.created_at,
            updated_at=finding.updated_at,
            payload=payload,
        )
        self.session.merge(record)
        return finding

    def get(self, finding_id: UUID) -> Finding | None:
        """Return finding by id."""

        record = self.session.get(FindingRecord, str(finding_id))
        return Finding.model_validate(record.payload) if record else None

    def list(self) -> list[Finding]:
        """Return all findings."""

        records = self.session.scalars(select(FindingRecord)).all()
        return [Finding.model_validate(record.payload) for record in records]

    def find_by_fingerprint(self, fingerprint: str) -> Finding | None:
        """Return finding by fingerprint."""

        record = self.session.scalar(select(FindingRecord).where(FindingRecord.fingerprint == fingerprint))
        return Finding.model_validate(record.payload) if record else None


class SqlAlchemyUnitOfWork:
    """Transactional SQLAlchemy Unit of Work."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self.session_factory = session_factory

    @classmethod
    def from_url(cls, database_url: str, create_schema: bool = True) -> "SqlAlchemyUnitOfWork":
        """Build a Unit of Work from a SQLAlchemy database URL."""

        engine: Engine = create_engine(database_url)
        if create_schema:
            Base.metadata.create_all(engine)
        return cls(sessionmaker(bind=engine, expire_on_commit=False))

    def __enter__(self) -> "SqlAlchemyUnitOfWork":
        """Open session and repository scope."""

        self.session = self.session_factory()
        self.findings = SqlAlchemyFindingRepository(self.session)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Commit or rollback session."""

        if exc:
            self.rollback()
        else:
            self.commit()
        self.session.close()

    def commit(self) -> None:
        """Commit session changes."""

        self.session.commit()

    def rollback(self) -> None:
        """Rollback session changes."""

        self.session.rollback()
