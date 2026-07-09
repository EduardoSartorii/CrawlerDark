"""ThreatActor entity.

Responsibility
--------------
Model an adversary the platform monitors or discovers. Threat actors are both a
*watchlist* concept (we search for their names/aliases) and a *correlation*
target (findings get attributed to them). Aliases are normalised to lower case
so matching is robust to source casing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ThreatActor(BaseModel):
    """A monitored/discovered adversary entity."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    name: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    motivation: str | None = Field(default=None, description="financial, hacktivism, ...")
    country: str | None = None
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)

    @field_validator("aliases")
    @classmethod
    def _normalise_aliases(cls, aliases: list[str]) -> list[str]:
        """Lower-case and de-duplicate aliases for robust matching."""
        seen: dict[str, None] = {}
        for alias in aliases:
            key = alias.strip().lower()
            if key:
                seen.setdefault(key, None)
        return list(seen.keys())

    @property
    def match_terms(self) -> set[str]:
        """All lower-cased terms (name + aliases) used for keyword matching."""
        return {self.name.lower(), *self.aliases}
