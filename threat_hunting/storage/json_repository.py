"""JSON repository adapter for local persistence and exports."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from threat_hunting.core.domain.entities import Finding
from threat_hunting.storage.memory import InMemoryFindingRepository, InMemoryUnitOfWork


class JsonFindingRepository(InMemoryFindingRepository):
    """Repository that stores findings in a JSON file."""

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            for record in json.loads(self.path.read_text(encoding="utf-8") or "[]"):
                self.save(Finding.model_validate(record))

    def save(self, finding: Finding) -> Finding:
        """Persist finding and flush file."""

        stored = super().save(finding)
        self.flush()
        return stored

    def get(self, finding_id: UUID) -> Finding | None:
        """Return a finding by id."""

        return super().get(finding_id)

    def flush(self) -> None:
        """Write all findings to JSON."""

        records = [finding.model_dump(mode="json") for finding in self.list()]
        self.path.write_text(json.dumps(records, indent=2, sort_keys=True), encoding="utf-8")


class JsonUnitOfWork(InMemoryUnitOfWork):
    """Unit of Work for JSON repository."""

    findings: JsonFindingRepository

    def __init__(self, path: Path) -> None:
        super().__init__(JsonFindingRepository(path))

    def commit(self) -> None:
        """Flush JSON changes."""

        self.findings.flush()
