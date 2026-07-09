"""
Database Connection Manager.

Manages SQLAlchemy async engine lifecycle and session factory creation.
Supports both SQLite (dev/test) and PostgreSQL (production).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ...database.models.finding_model import Base


class DatabaseManager:
    """
    Manages the async database engine and session factory.

    Usage:
        db = DatabaseManager.sqlite("./data/threat_hunting.db")
        await db.create_tables()
        async with db.session() as session:
            ...
    """

    def __init__(self, url: str, echo: bool = False) -> None:
        self._url = url
        self._engine: AsyncEngine = create_async_engine(url, echo=echo)
        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    @classmethod
    def sqlite(cls, path: str = "./data/threat_hunting.db", echo: bool = False) -> "DatabaseManager":
        """Create a SQLite database manager."""
        url = f"sqlite+aiosqlite:///{path}"
        return cls(url=url, echo=echo)

    @classmethod
    def postgresql(cls, dsn: str, echo: bool = False) -> "DatabaseManager":
        """Create a PostgreSQL database manager (asyncpg driver)."""
        # Convert psycopg2 DSN to asyncpg if needed
        url = dsn.replace("postgresql://", "postgresql+asyncpg://")
        return cls(url=url, echo=echo)

    async def create_tables(self) -> None:
        """Create all tables (idempotent)."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_tables(self) -> None:
        """Drop all tables (use in tests only)."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        return self._session_factory

    async def dispose(self) -> None:
        """Dispose the engine and release all connections."""
        await self._engine.dispose()
