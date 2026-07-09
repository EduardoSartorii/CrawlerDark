"""SourceRef — referência canônica à origem de um Finding."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class SourceRef:
    """Origem de uma descoberta: fonte, connector e URL de referência."""

    source: str
    connector: str
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    url: str | None = None
    author: str | None = None

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("SourceRef.source is required")
        if not self.connector:
            raise ValueError("SourceRef.connector is required")
        if self.collected_at.tzinfo is None:
            object.__setattr__(
                self, "collected_at", self.collected_at.replace(tzinfo=timezone.utc)
            )
