"""Campaign — operação/campanha correlacionada de ameaça."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4


@dataclass(slots=True, kw_only=True)
class Campaign:
    id: UUID = field(default_factory=uuid4)
    name: str
    description: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    threat_actor_id: UUID | None = None
    tags: set[str] = field(default_factory=set)
