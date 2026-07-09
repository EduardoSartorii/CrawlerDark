"""Persistence ports: FindingRepository and UnitOfWork.

Responsibility
--------------
Abstract persistence behind the Repository Pattern and coordinate atomic writes
with the Unit of Work Pattern. Swapping the backend (memory ↔ JSON ↔ SQLite ↔
Postgres ↔ OpenSearch ↔ ...) must not change a single business rule; that
guarantee lives here as a stable contract.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from threat_hunting.core.domain.entities.finding import Finding


@runtime_checkable
class FindingRepository(Protocol):
    """CRUD-style contract for persisting :class:`Finding` aggregates."""

    def add(self, finding: Finding) -> None:
        """Insert or replace a finding."""
        ...

    def get(self, finding_id: str) -> Finding | None:
        """Return a finding by id, or ``None`` if absent."""
        ...

    def list(self, limit: int | None = None) -> Sequence[Finding]:
        """Return stored findings (most recent first), optionally limited."""
        ...

    def find_by_indicator(self, indicator_key: str) -> Sequence[Finding]:
        """Return findings that contain the given indicator key."""
        ...

    def count(self) -> int:
        """Return the number of stored findings."""
        ...


@runtime_checkable
class UnitOfWork(Protocol):
    """Transactional boundary exposing repositories (Unit of Work Pattern)."""

    findings: FindingRepository

    def __enter__(self) -> "UnitOfWork":
        """Begin a transaction/session."""
        ...

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Commit on success, roll back on error, then release resources."""
        ...

    def commit(self) -> None:
        """Persist all changes made within the unit of work."""
        ...

    def rollback(self) -> None:
        """Discard all changes made within the unit of work."""
        ...
