"""SQLAlchemy 2.0 Repository + Unit of Work (SQLite / PostgreSQL).

Responsibility
--------------
Provide a transactional, database-backed implementation of the persistence
ports. The Unit of Work owns a session and commits/rolls back atomically; the
repository maps between :class:`FindingRow` and the domain :class:`Finding`
(full round-trip through Pydantic), so the ORM never leaks into the core.

Swapping SQLite for PostgreSQL is only a DSN change — no business rule moves.
"""

from __future__ import annotations

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from threat_hunting.core.application.ports.repository import (
    FindingRepositoryPort,
    UnitOfWorkPort,
)
from threat_hunting.core.domain.entities import Finding
from threat_hunting.infrastructure.storage.models import Base, FindingRow


def build_engine(dsn: str, *, echo: bool = False) -> Engine:
    """Create an engine and ensure the schema exists (dev convenience)."""
    connect_args = {"check_same_thread": False} if dsn.startswith("sqlite") else {}
    engine = create_engine(dsn, echo=echo, future=True, connect_args=connect_args)
    Base.metadata.create_all(engine)
    return engine


def _to_row(finding: Finding) -> FindingRow:
    """Map a domain finding to an ORM row (nested data as JSON document)."""
    return FindingRow(
        id=finding.id,
        title=finding.title,
        description=finding.description,
        source=finding.source,
        connector=finding.connector,
        category=finding.category.value,
        severity=finding.severity.value,
        score=finding.score,
        confidence=finding.confidence.value,
        fingerprint=finding.metadata.get("fingerprint"),
        created_at=finding.created_at,
        updated_at=finding.updated_at,
        document=finding.model_dump(mode="json"),
    )


def _to_domain(row: FindingRow) -> Finding:
    """Rebuild a domain finding from its stored JSON document."""
    return Finding.model_validate(row.document)


class SqlAlchemyFindingRepository(FindingRepositoryPort):
    """Repository backed by a SQLAlchemy session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, finding: Finding) -> None:
        self._session.merge(_to_row(finding))

    def get(self, finding_id: str) -> Finding | None:
        row = self._session.get(FindingRow, finding_id)
        return _to_domain(row) if row else None

    def list(self, *, limit: int | None = None) -> list[Finding]:
        stmt = select(FindingRow).order_by(FindingRow.created_at.desc())
        if limit is not None:
            stmt = stmt.limit(limit)
        return [_to_domain(r) for r in self._session.scalars(stmt)]

    def find_by_fingerprint(self, fingerprint: str) -> Finding | None:
        stmt = select(FindingRow).where(FindingRow.fingerprint == fingerprint)
        row = self._session.scalars(stmt).first()
        return _to_domain(row) if row else None

    def recent(self, limit: int = 500) -> list[Finding]:
        return self.list(limit=limit)


class _ReadOnlyRepository(FindingRepositoryPort):
    """Repository that opens a short-lived session per read.

    Bound as the UoW's ``findings`` outside an explicit transaction so callers
    (the pipeline seeding context, exporters) can read without a ``with`` block.
    Write methods are unavailable here by design — writes must go through a
    transactional Unit of Work.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def _read(self, fn):
        session = self._session_factory()
        try:
            return fn(SqlAlchemyFindingRepository(session))
        finally:
            session.close()

    def add(self, finding: Finding) -> None:  # pragma: no cover - guarded
        raise RuntimeError("writes require an active Unit of Work (use `with uow:`)")

    def get(self, finding_id: str) -> Finding | None:
        return self._read(lambda r: r.get(finding_id))

    def list(self, *, limit: int | None = None) -> list[Finding]:
        return self._read(lambda r: r.list(limit=limit))

    def find_by_fingerprint(self, fingerprint: str) -> Finding | None:
        return self._read(lambda r: r.find_by_fingerprint(fingerprint))

    def recent(self, limit: int = 500) -> list[Finding]:
        return self._read(lambda r: r.recent(limit))


class SqlAlchemyUnitOfWork(UnitOfWorkPort):
    """Session-per-unit-of-work transactional boundary."""

    def __init__(self, engine: Engine) -> None:
        self._session_factory = sessionmaker(bind=engine, expire_on_commit=False)
        self._session: Session | None = None
        self._read_repo = _ReadOnlyRepository(self._session_factory)
        self.findings: FindingRepositoryPort = self._read_repo

    def __enter__(self) -> "SqlAlchemyUnitOfWork":
        self._session = self._session_factory()
        self.findings = SqlAlchemyFindingRepository(self._session)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        try:
            super().__exit__(exc_type, exc, tb)
        finally:
            if self._session is not None:
                self._session.close()
                self._session = None
            self.findings = self._read_repo

    def commit(self) -> None:
        if self._session is not None:
            self._session.commit()

    def rollback(self) -> None:
        if self._session is not None:
            self._session.rollback()
