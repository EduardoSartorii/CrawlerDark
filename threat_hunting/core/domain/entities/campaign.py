"""Campaign entity.

Responsibility
--------------
Represent a correlated cluster of related findings/indicators. The correlation
engine groups findings that share indicators or actors into a campaign,
providing analysts with a higher-level view of an ongoing operation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Campaign(BaseModel):
    """A cluster of correlated findings representing a single operation."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    name: str = Field(min_length=1)
    description: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    indicator_keys: list[str] = Field(default_factory=list)
    actor_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    def add_finding(self, finding_id: str) -> None:
        """Attach a finding to this campaign (idempotent)."""
        if finding_id not in self.finding_ids:
            self.finding_ids.append(finding_id)
            object.__setattr__(self, "updated_at", _utcnow())
