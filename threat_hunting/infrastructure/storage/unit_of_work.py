"""
SQLAlchemyUnitOfWork
====================

Implements IUnitOfWork using SQLAlchemy async sessions.
Provides transactional consistency across all repositories.

Usage:
    async with uow as u:
        finding = await u.findings.get_by_id(...)
        finding.set_score(...)
        await u.findings.save(finding)
        await u.commit()

Architecture:
    - A new session is created per UoW context (not per request).
    - All repositories share the same session within the context.
    - rollback() is called automatically on exception via __aexit__.
    - The session is closed when the context exits.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from threat_hunting.core.domain.ports.storage import IUnitOfWork
from threat_hunting.infrastructure.database.session import DatabaseSession
from threat_hunting.infrastructure.storage.repositories.finding_repository import (
    SQLAlchemyFindingRepository,
)
from threat_hunting.infrastructure.storage.repositories.simple_repositories import (
    SQLAlchemyConnectorConfigRepository,
    SQLAlchemyIndicatorRepository,
    SQLAlchemyKeywordRepository,
    SQLAlchemyRuleRepository,
    SQLAlchemyThreatActorRepository,
    SQLAlchemyVIPRepository,
)


class SQLAlchemyUnitOfWork(IUnitOfWork):
    """
    SQLAlchemy Unit of Work.

    Wraps a single database session and exposes typed repositories.
    """

    def __init__(self, db: DatabaseSession) -> None:
        self._db = db
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> "SQLAlchemyUnitOfWork":
        self._session = self._db._session_factory()
        self.findings = SQLAlchemyFindingRepository(self._session)
        self.indicators = SQLAlchemyIndicatorRepository(self._session)
        self.keywords = SQLAlchemyKeywordRepository(self._session)
        self.vips = SQLAlchemyVIPRepository(self._session)
        self.threat_actors = SQLAlchemyThreatActorRepository(self._session)
        self.rules = SQLAlchemyRuleRepository(self._session)
        self.connector_configs = SQLAlchemyConnectorConfigRepository(self._session)
        return self

    async def __aexit__(
        self, exc_type: type | None, exc: Exception | None, tb: object
    ) -> None:
        if exc_type:
            await self.rollback()
        if self._session:
            await self._session.close()

    async def commit(self) -> None:
        """Persist all pending changes in the current session."""
        if self._session:
            await self._session.commit()

    async def rollback(self) -> None:
        """Discard all pending changes."""
        if self._session:
            await self._session.rollback()
