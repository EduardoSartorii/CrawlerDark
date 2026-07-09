"""
Unit of Work Interface (Port).

The Unit of Work coordinates multiple repository operations within a single
atomic transaction. It ensures consistency: either all operations succeed
or all are rolled back.

Architectural Role:
    - Application use cases receive a UoW instance via DI
    - Use cases access repositories ONLY through the UoW
    - Transaction boundaries are managed by the UoW, not by repositories
    - Domain events are dispatched AFTER the transaction commits successfully

Usage example:
    async with uow:
        finding = await uow.findings.save(finding)
        for ioc in indicators:
            await uow.indicators.save_or_update(ioc)
        await uow.commit()
        # events dispatched here

Design Pattern: Unit of Work (Martin Fowler) + Context Manager
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType
from typing import Any

from .finding_repository import AbstractFindingRepository
from .indicator_repository import AbstractIndicatorRepository


class AbstractUnitOfWork(ABC):
    """
    Abstract Unit of Work.

    Concrete implementations live in infrastructure (SQLAlchemy, in-memory, etc.).
    Application use cases depend only on this interface.
    """

    findings: AbstractFindingRepository
    indicators: AbstractIndicatorRepository

    async def __aenter__(self) -> "AbstractUnitOfWork":
        await self.begin()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            await self.rollback()
        else:
            await self.commit()

    @abstractmethod
    async def begin(self) -> None:
        """Start a new transaction."""

    @abstractmethod
    async def commit(self) -> None:
        """Commit the current transaction and dispatch pending domain events."""

    @abstractmethod
    async def rollback(self) -> None:
        """Roll back the current transaction."""

    @abstractmethod
    async def collect_events(self) -> list[Any]:
        """Collect all domain events from tracked aggregates."""
