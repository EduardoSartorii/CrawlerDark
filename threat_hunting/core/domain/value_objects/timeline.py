"""Timeline event value object.

Responsibility
--------------
Capture an auditable step in a finding's lifecycle (collected, scored,
enriched, exported...). The timeline gives analysts a chronological trail and
supports the platform's audit requirement without coupling to any logging
backend.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


def _utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp (single source of 'now')."""
    return datetime.now(timezone.utc)


class TimelineEvent(BaseModel):
    """A single, timestamped step in a finding's processing history."""

    model_config = ConfigDict(frozen=True)

    at: datetime = Field(default_factory=_utcnow)
    stage: str = Field(description="Pipeline stage or action that occurred.")
    message: str = Field(default="")
    details: dict[str, str] = Field(default_factory=dict)
