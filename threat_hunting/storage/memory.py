"""In-memory repository adapter for tests and local dry runs."""

from __future__ import annotations

from uuid import UUID

from threat_hunting.core.domain.entities import Finding


class InMemoryFindingRepository:
    """Repository adapter backed by a Python dictionary."""

    def __init__(self) -> None:
        self._items: dict[UUID, Finding] = {}
        self._fingerprints: dict[str, UUID] = {}

    def save(self, finding: Finding) -> Finding:
        """Persist finding in memory."""

        self._items[finding.id] = finding
        self._fingerprints[finding.fingerprint_payload()] = finding.id
        return finding

    def get(self, finding_id: UUID) -> Finding | None:
        """Return a finding by id."""

        return self._items.get(finding_id)

    def list(self) -> list[Finding]:
        """Return all findings."""

        return list(self._items.values())

    def find_by_fingerprint(self, fingerprint: str) -> Finding | None:
        """Return a finding by fingerprint payload."""

        finding_id = self._fingerprints.get(fingerprint)
        return self._items.get(finding_id) if finding_id else None


class InMemoryUnitOfWork:
    """Unit of Work adapter for in-memory repositories."""

    def __init__(self, findings: InMemoryFindingRepository | None = None) -> None:
        self.findings = findings or InMemoryFindingRepository()

    def __enter__(self) -> "InMemoryUnitOfWork":
        """Open transaction scope."""

        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Close transaction scope."""

        if exc:
            self.rollback()
        else:
            self.commit()

    def commit(self) -> None:
        """Commit no-op for in-memory adapter."""

    def rollback(self) -> None:
        """Rollback no-op for in-memory adapter."""
