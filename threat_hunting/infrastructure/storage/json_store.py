"""JSON file storage backend.

Responsibility
--------------
Durable, dependency-free persistence: findings are serialised to a single JSON
document. Writes are staged and only flushed on ``commit`` (atomic replace via a
temp file), matching the transactional contract of the Unit of Work.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path

from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.exceptions import StorageError


class _JsonFindingRepository:
    """Finding repository backed by an in-memory map loaded from JSON."""

    def __init__(self, data: dict[str, Finding]) -> None:
        self._data = data
        self._staging: dict[str, Finding] = {}

    def add(self, finding: Finding) -> None:
        self._staging[finding.id] = finding

    def get(self, finding_id: str) -> Finding | None:
        return self._staging.get(finding_id) or self._data.get(finding_id)

    def list(self, limit: int | None = None) -> Sequence[Finding]:
        items = sorted(self._data.values(), key=lambda f: f.created_at, reverse=True)
        return items[:limit] if limit is not None else items

    def find_by_indicator(self, indicator_key: str) -> Sequence[Finding]:
        return [f for f in self._data.values() if indicator_key in f.indicator_keys]

    def count(self) -> int:
        return len(self._data)

    def _flush(self) -> None:
        self._data.update(self._staging)
        self._staging.clear()

    def _discard(self) -> None:
        self._staging.clear()


class JsonUnitOfWork:
    """Unit of Work persisting findings to a JSON file."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._data: dict[str, Finding] = {}
        self.findings = _JsonFindingRepository(self._data)

    def _load(self) -> None:
        self._data.clear()
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise StorageError(f"failed to read {self._path}: {exc}") from exc
        for entry in raw.get("findings", []):
            finding = Finding.model_validate(entry)
            self._data[finding.id] = finding

    def _persist(self) -> None:
        payload = {"findings": [f.model_dump(mode="json") for f in self._data.values()]}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: temp file in the same dir, then os.replace.
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
            os.replace(tmp, self._path)
        except OSError as exc:
            raise StorageError(f"failed to write {self._path}: {exc}") from exc
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def __enter__(self) -> "JsonUnitOfWork":
        self._load()
        self.findings = _JsonFindingRepository(self._data)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()

    def commit(self) -> None:
        """Flush staged findings and persist the JSON document atomically."""
        self.findings._flush()
        self._persist()

    def rollback(self) -> None:
        """Discard staged findings (file untouched)."""
        self.findings._discard()
