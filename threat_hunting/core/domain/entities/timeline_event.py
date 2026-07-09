"""TimelineEvent — histórico auditável de mudanças em um ``Finding``."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4


@dataclass(slots=True, kw_only=True)
class TimelineEvent:
    id: UUID = field(default_factory=uuid4)
    kind: str
    message: str
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    payload: dict[str, object] = field(default_factory=dict)
