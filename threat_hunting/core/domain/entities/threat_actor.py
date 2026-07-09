"""ThreatActor — ator ameaça catalogado."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID, uuid4


@dataclass(slots=True, kw_only=True)
class ThreatActor:
    id: UUID = field(default_factory=uuid4)
    name: str
    aliases: set[str] = field(default_factory=set)
    description: str = ""
    motivations: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    context: dict[str, object] = field(default_factory=dict)
