"""Job — execução observável de um conector ou pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4


class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


@dataclass(slots=True, kw_only=True)
class Job:
    id: UUID = field(default_factory=uuid4)
    connector: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    status: JobStatus = JobStatus.PENDING
    items_collected: int = 0
    items_persisted: int = 0
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)

    def mark_running(self) -> None:
        self.status = JobStatus.RUNNING

    def mark_success(self, persisted: int, collected: int) -> None:
        self.status = JobStatus.SUCCEEDED
        self.items_persisted = persisted
        self.items_collected = collected
        self.finished_at = datetime.now(timezone.utc)

    def mark_failure(self, error: str) -> None:
        self.status = JobStatus.FAILED
        self.errors.append(error)
        self.finished_at = datetime.now(timezone.utc)

    def mark_partial(self, error: str, persisted: int, collected: int) -> None:
        self.status = JobStatus.PARTIAL
        self.errors.append(error)
        self.items_persisted = persisted
        self.items_collected = collected
        self.finished_at = datetime.now(timezone.utc)
