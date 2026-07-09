"""Relationship — aresta tipada entre entidades do domínio."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from uuid import UUID, uuid4


class RelationshipType(str, Enum):
    RELATED_TO = "RELATED_TO"
    ATTRIBUTED_TO = "ATTRIBUTED_TO"
    INDICATES = "INDICATES"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    HOSTS = "HOSTS"
    DERIVED_FROM = "DERIVED_FROM"
    DUPLICATE_OF = "DUPLICATE_OF"
    MENTIONS = "MENTIONS"


@dataclass(slots=True, kw_only=True)
class Relationship:
    id: UUID = field(default_factory=uuid4)
    source_id: UUID
    target_id: UUID
    type: RelationshipType
    context: dict[str, object] = field(default_factory=dict)
