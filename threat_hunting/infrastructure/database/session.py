"""
Database Session Management
============================

Provides async SQLAlchemy session factory.
Supports SQLite (development) and PostgreSQL (production).
The URL is configured via DATABASE_URL environment variable.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class DatabaseSession:
    """
    Manages the async SQLAlchemy engine and session factory.

    Registered as a singleton in the DI container.
    """

    def __init__(self, database_url: str, echo: bool = False) -> None:
        self._engine: AsyncEngine = create_async_engine(
            database_url,
            echo=echo,
            pool_pre_ping=True,
        )
        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

    async def create_all(self) -> None:
        """Create all tables (development convenience method)."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_all(self) -> None:
        """Drop all tables (test teardown)."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Provide a transactional session context."""
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def close(self) -> None:
        """Dispose of the engine connection pool."""
        await self._engine.dispose()


async def get_async_session(db: DatabaseSession) -> AsyncIterator[AsyncSession]:
    """FastAPI / dependency injection compatible session provider."""
    async with db.session() as session:
        yield session
