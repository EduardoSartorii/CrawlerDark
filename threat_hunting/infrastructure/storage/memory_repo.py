"""In-memory Repository + Unit of Work.

Responsibility
--------------
A zero-dependency persistence backend used as the default for demos, unit tests
and dry runs. It fully honours the persistence ports so the rest of the platform
cannot tell it apart from a database-backed store.
"""

from __future__ import annotations

from threat_hunting.core.application.ports.repository import (
    FindingRepositoryPort,
    UnitOfWorkPort,
)
from threat_hunting.core.domain.entities import Finding


class InMemoryFindingRepository(FindingRepositoryPort):
    """Stores findings in a process-local dictionary."""

    def __init__(self) -> None:
        self._by_id: dict[str, Finding] = {}
        self._by_fingerprint: dict[str, str] = {}
        self._order: list[str] = []

    def add(self, finding: Finding) -> None:
        if finding.id not in self._by_id:
            self._order.append(finding.id)
        self._by_id[finding.id] = finding
        fingerprint = finding.metadata.get("fingerprint")
        if fingerprint:
            self._by_fingerprint[str(fingerprint)] = finding.id

    def get(self, finding_id: str) -> Finding | None:
        return self._by_id.get(finding_id)

    def list(self, *, limit: int | None = None) -> list[Finding]:
        ordered = [self._by_id[i] for i in reversed(self._order)]
        return ordered[:limit] if limit is not None else ordered

    def find_by_fingerprint(self, fingerprint: str) -> Finding | None:
        finding_id = self._by_fingerprint.get(fingerprint)
        return self._by_id.get(finding_id) if finding_id else None

    def recent(self, limit: int = 500) -> list[Finding]:
        return self.list(limit=limit)


class InMemoryUnitOfWork(UnitOfWorkPort):
    """Trivial Unit of Work: the in-memory repo is already durable in-process."""

    def __init__(self, repository: InMemoryFindingRepository | None = None) -> None:
        self.findings: FindingRepositoryPort = repository or InMemoryFindingRepository()

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None
