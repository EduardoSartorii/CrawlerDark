"""Repository and Unit of Work adapters.

The repository contracts support SQLite/PostgreSQL through SQLAlchemy and JSON
storage for local data lake style execution. Additional OpenSearch, Splunk, S3
or Parquet adapters can implement the same methods without touching use cases.
"""

from __future__ import annotations

import json
from pathlib import Path

from threat_hunting.core.domain.entities import Finding


class InMemoryFindingRepository:
    """In-memory repository used by tests and short-lived CLI runs."""

    def __init__(self) -> None:
        self._items: list[Finding] = []

    def add(self, finding: Finding) -> None:
        """Persist a finding in memory."""

        self._items.append(finding)

    def list(self) -> list[Finding]:
        """Return stored findings."""

        return list(self._items)

    def get_by_hash(self, content_hash: str) -> Finding | None:
        """Return the first finding with the given hash."""

        return next((item for item in self._items if item.content_hash == content_hash), None)


class InMemoryUnitOfWork:
    """Unit of Work with explicit commit and rollback state."""

    def __init__(self, repository: InMemoryFindingRepository | None = None) -> None:
        self.findings = repository or InMemoryFindingRepository()
        self.committed = False

    def __enter__(self) -> "InMemoryUnitOfWork":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type:
            self.rollback()
        else:
            self.commit()

    def commit(self) -> None:
        """Mark transaction as committed."""

        self.committed = True

    def rollback(self) -> None:
        """Rollback is a no-op for memory storage."""

        self.committed = False


class JsonFindingRepository(InMemoryFindingRepository):
    """Append-safe JSON repository for portable local persistence."""

    def __init__(self, path: str | Path) -> None:
        super().__init__()
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists():
            payload = json.loads(self._path.read_text(encoding="utf-8") or "[]")
            self._items = [Finding.model_validate(item) for item in payload]

    def add(self, finding: Finding) -> None:
        """Persist a finding and flush it to disk."""

        super().add(finding)
        self._path.write_text(
            json.dumps([item.model_dump(mode="json") for item in self._items], indent=2, sort_keys=True),
            encoding="utf-8",
        )
