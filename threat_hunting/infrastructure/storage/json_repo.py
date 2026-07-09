"""JSON Lines (data-lake) Repository + Unit of Work.

Responsibility
--------------
Persist findings as newline-delimited JSON — the lingua franca of data lakes
(S3, Parquet-ingestible, Splunk/Elastic-friendly). It implements the same
persistence ports as the SQL and in-memory backends, so selecting it via
``storage.backend: json`` changes no business rule.

Design notes
------------
* Writes are buffered in memory during a Unit of Work and flushed atomically on
  ``commit`` (append to the JSONL file), giving all-or-nothing semantics per UoW.
* Reads scan the file; adequate for the append-only, batch-oriented usage here.
"""

from __future__ import annotations

import json
from pathlib import Path

from threat_hunting.core.application.ports.repository import (
    FindingRepositoryPort,
    UnitOfWorkPort,
)
from threat_hunting.core.domain.entities import Finding


class JsonFindingRepository(FindingRepositoryPort):
    """Repository over a JSON Lines file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._pending: list[Finding] = []

    def add(self, finding: Finding) -> None:
        self._pending.append(finding)

    def flush(self) -> None:
        """Append buffered findings to the JSONL file (atomic per commit)."""
        if not self._pending:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            for finding in self._pending:
                handle.write(json.dumps(finding.model_dump(mode="json")) + "\n")
        self._pending.clear()

    def discard(self) -> None:
        """Drop buffered findings (rollback)."""
        self._pending.clear()

    def _read_all(self) -> list[Finding]:
        """Read and parse all stored findings (most recent last on disk)."""
        if not self._path.exists():
            return []
        findings: list[Finding] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                findings.append(Finding.model_validate(json.loads(line)))
        return findings

    def get(self, finding_id: str) -> Finding | None:
        for finding in self._read_all():
            if finding.id == finding_id:
                return finding
        return None

    def list(self, *, limit: int | None = None) -> list[Finding]:
        findings = list(reversed(self._read_all()))
        return findings[:limit] if limit is not None else findings

    def find_by_fingerprint(self, fingerprint: str) -> Finding | None:
        for finding in reversed(self._read_all()):
            if finding.metadata.get("fingerprint") == fingerprint:
                return finding
        return None

    def recent(self, limit: int = 500) -> list[Finding]:
        return self.list(limit=limit)


class JsonUnitOfWork(UnitOfWorkPort):
    """Buffers writes and flushes them to JSONL on commit."""

    def __init__(self, path: str | Path) -> None:
        self._repo = JsonFindingRepository(path)
        self.findings: FindingRepositoryPort = self._repo

    def commit(self) -> None:
        self._repo.flush()

    def rollback(self) -> None:
        self._repo.discard()
