"""Relationship value object.

Responsibility
--------------
Model a typed, directed edge between two entities/indicators. The correlation
engine produces these edges to build the intelligence graph (e.g. a domain
*resolves_to* an IP, a finding is *attributed_to* a threat actor).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from threat_hunting.core.domain.enums import RelationshipType


class Relationship(BaseModel):
    """A directed, typed edge ``source -> target`` in the intelligence graph."""

    model_config = ConfigDict(frozen=True)

    source_ref: str = Field(description="Key of the source node (e.g. indicator key).")
    target_ref: str = Field(description="Key of the target node.")
    type: RelationshipType
    confidence: int = Field(default=50, ge=0, le=100)
    description: str | None = None

    @property
    def key(self) -> str:
        """Stable key used to deduplicate relationships."""
        return f"{self.source_ref}|{self.type.value}|{self.target_ref}"
