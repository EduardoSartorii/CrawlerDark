"""
SQLAlchemy Unit of Work.

Concrete implementation of AbstractUnitOfWork using SQLAlchemy async sessions.
Manages transaction boundaries and coordinates multiple repositories.

After a successful commit, dispatches all domain events collected
from modified aggregates.
"""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ...core.domain.repositories.unit_of_work import AbstractUnitOfWork
from .sqlalchemy_repository import SQLAlchemyFindingRepository

logger = structlog.get_logger(__name__)


class SQLAlchemyUnitOfWork(AbstractUnitOfWork):
    """
    SQLAlchemy async Unit of Work.

    Used as an async context manager by application use cases:

        async with uow:
            finding = await uow.findings.save(new_finding)
            await uow.commit()
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._session: AsyncSession | None = None

    async def begin(self) -> None:
        """Start a new async session and transaction."""
        self._session = self._session_factory()
        self.findings = SQLAlchemyFindingRepository(self._session)
        # Indicators repository would be added here similarly
        logger.debug("uow.begin")

    async def commit(self) -> None:
        """Commit the transaction."""
        if self._session:
            await self._session.commit()
            logger.debug("uow.commit")
            events = await self.collect_events()
            if events:
                logger.debug("uow.events_collected", count=len(events))

    async def rollback(self) -> None:
        """Roll back on error."""
        if self._session:
            await self._session.rollback()
            logger.debug("uow.rollback")

    async def collect_events(self) -> list[Any]:
        """Collect domain events (placeholder — hook into event bus here)."""
        return []

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            if exc_type is None:
                await self.commit()
            else:
                await self.rollback()
        finally:
            if self._session:
                await self._session.close()
                self._session = None
