"""RawItem entity.

Responsibility
--------------
Represent a single unit of *raw* data as emitted by a connector's ``collect()``
before any parsing/normalisation. It is deliberately loose (arbitrary payload)
because different sources return very different shapes; the parser stage is
responsible for turning it into a structured :class:`Finding`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RawItem(BaseModel):
    """Unprocessed data collected from a source."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    connector: str
    source: str
    url: str | None = None
    title: str | None = None
    content: str = Field(default="", description="Primary textual payload, if any.")
    payload: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary structured payload from the source."
    )
    collected_at: datetime = Field(default_factory=_utcnow)
