"""UnitOfWork SQLAlchemy — abre sessão, expõe repositórios, commit/rollback."""

from __future__ import annotations

from types import TracebackType
from typing import Self

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .repositories import (
    SqlAlchemyDetectionRuleRepository,
    SqlAlchemyFindingRepository,
    SqlAlchemyIndicatorRepository,
    SqlAlchemyJobRepository,
    SqlAlchemyThreatActorRepository,
    SqlAlchemyWatchlistRepository,
)


class SqlAlchemyUnitOfWork:
    """Implementa ``UnitOfWorkPort`` via async context manager."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> Self:
        self._session = self._session_factory()
        self.findings = SqlAlchemyFindingRepository(self._session)
        self.indicators = SqlAlchemyIndicatorRepository(self._session)
        self.threat_actors = SqlAlchemyThreatActorRepository(self._session)
        self.watchlists = SqlAlchemyWatchlistRepository(self._session)
        self.rules = SqlAlchemyDetectionRuleRepository(self._session)
        self.jobs = SqlAlchemyJobRepository(self._session)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            if exc is not None:
                await self.rollback()
            elif self._session is not None:
                await self._session.commit()
        finally:
            if self._session is not None:
                await self._session.close()
                self._session = None

    async def commit(self) -> None:
        if self._session is not None:
            await self._session.commit()

    async def rollback(self) -> None:
        if self._session is not None:
            await self._session.rollback()
