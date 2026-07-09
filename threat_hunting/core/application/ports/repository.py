"""Persistence ports: Repository + Unit of Work.

Responsibility
--------------
Abstract *all* persistence. The application never talks to SQLAlchemy, a file or
a search index directly — it talks to these ports. Swapping SQLite for
PostgreSQL, OpenSearch or a JSON data lake therefore changes zero business rules.

Patterns
--------
* **Repository**: a collection-like interface for ``Finding`` aggregates.
* **Unit of Work**: an atomic boundary that commits or rolls back a set of
  changes and exposes the repository within a transaction/context manager.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence
from types import TracebackType

from threat_hunting.core.domain.entities import Finding


class FindingRepositoryPort(abc.ABC):
    """Collection-oriented persistence contract for findings."""

    @abc.abstractmethod
    def add(self, finding: Finding) -> None:
        """Insert or update a finding."""

    @abc.abstractmethod
    def get(self, finding_id: str) -> Finding | None:
        """Return a finding by id, or ``None`` when absent."""

    @abc.abstractmethod
    def list(self, *, limit: int | None = None) -> list[Finding]:
        """Return stored findings, most recent first."""

    @abc.abstractmethod
    def find_by_fingerprint(self, fingerprint: str) -> Finding | None:
        """Return a finding matching a dedup fingerprint, if any."""

    @abc.abstractmethod
    def recent(self, limit: int = 500) -> list[Finding]:
        """Return the most recent findings used as correlation/dedup context."""


class UnitOfWorkPort(abc.ABC):
    """Atomic transactional boundary exposing a repository.

    Usage::

        with uow:
            uow.findings.add(finding)
            uow.commit()
    """

    findings: FindingRepositoryPort

    def __enter__(self) -> "UnitOfWorkPort":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()

    @abc.abstractmethod
    def commit(self) -> None:
        """Persist all pending changes atomically."""

    @abc.abstractmethod
    def rollback(self) -> None:
        """Discard all pending changes."""

    def collect_all(self, *, limit: int | None = None) -> Sequence[Finding]:
        """Convenience read used by exporters/reporting."""
        return self.findings.list(limit=limit)
