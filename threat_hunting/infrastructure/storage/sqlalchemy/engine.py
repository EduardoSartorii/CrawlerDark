"""Engine + session factory SQLAlchemy 2 async."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ...config.schemas import SQLAlchemyStorage


class EngineFactory:
    """Constrói ``AsyncEngine`` + session factory a partir da config.

    Pool desabilitado para SQLite (limitação do driver). Para Postgres/MySQL
    respeita ``pool_size``/``max_overflow``.
    """

    def __init__(self, config: SQLAlchemyStorage) -> None:
        self._config = config
        kwargs: dict[str, object] = {"echo": config.echo}
        if not config.url.startswith("sqlite"):
            kwargs["pool_size"] = config.pool_size
            kwargs["max_overflow"] = config.max_overflow
        self._engine: AsyncEngine = create_async_engine(config.url, **kwargs)
        self._session_factory = async_sessionmaker(
            bind=self._engine, expire_on_commit=False, class_=AsyncSession
        )

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._session_factory

    async def dispose(self) -> None:
        await self._engine.dispose()
