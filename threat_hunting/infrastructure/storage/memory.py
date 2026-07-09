"""In-memory storage backend.

Responsibility
--------------
Provide a zero-dependency :class:`FindingRepository` + :class:`UnitOfWork`
implementation used by tests, demos and the offline pipeline. Data lives in a
process-local dict; ``commit``/``rollback`` operate on a staging buffer so the
transactional semantics match durable backends.
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.domain.entities.finding import Finding


class InMemoryFindingRepository:
    """Dict-backed finding repository."""

    def __init__(self, store: dict[str, Finding]) -> None:
        self._store = store
        self._staging: dict[str, Finding] = {}

    def add(self, finding: Finding) -> None:
        """Stage a finding for insertion on commit."""
        self._staging[finding.id] = finding

    def get(self, finding_id: str) -> Finding | None:
        """Return a finding by id from committed or staged data."""
        return self._staging.get(finding_id) or self._store.get(finding_id)

    def list(self, limit: int | None = None) -> Sequence[Finding]:
        """Return committed findings, newest first, optionally limited."""
        items = sorted(self._store.values(), key=lambda f: f.created_at, reverse=True)
        return items[:limit] if limit is not None else items

    def find_by_indicator(self, indicator_key: str) -> Sequence[Finding]:
        """Return committed findings containing the given indicator key."""
        return [f for f in self._store.values() if indicator_key in f.indicator_keys]

    def count(self) -> int:
        """Return the number of committed findings."""
        return len(self._store)

    def _flush(self) -> None:
        self._store.update(self._staging)
        self._staging.clear()

    def _discard(self) -> None:
        self._staging.clear()


class InMemoryUnitOfWork:
    """Unit of Work over a shared in-memory store."""

    def __init__(self, store: dict[str, Finding] | None = None) -> None:
        self._store = store if store is not None else {}
        self.findings = InMemoryFindingRepository(self._store)

    def __enter__(self) -> "InMemoryUnitOfWork":
        self.findings = InMemoryFindingRepository(self._store)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()

    def commit(self) -> None:
        """Flush staged findings into the shared store."""
        self.findings._flush()

    def rollback(self) -> None:
        """Discard staged findings."""
        self.findings._discard()
