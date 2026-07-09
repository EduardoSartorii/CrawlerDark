"""Eventos de domínio. Imutáveis, serializáveis, comparados por valor."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True, kw_only=True)
class DomainEvent:
    """Evento base."""

    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def name(self) -> str:
        return self.__class__.__name__


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingCreated(DomainEvent):
    finding_id: UUID
    connector: str


@dataclass(frozen=True, slots=True, kw_only=True)
class RuleMatched(DomainEvent):
    finding_id: UUID
    rule_id: str
    matches: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class ScoreComputed(DomainEvent):
    finding_id: UUID
    score: float


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingCorrelated(DomainEvent):
    finding_id: UUID
    related_ids: tuple[UUID, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingDeduplicated(DomainEvent):
    finding_id: UUID
    duplicate_of: UUID | None
    action: str  # "kept" | "merged" | "discarded"


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingEnriched(DomainEvent):
    finding_id: UUID
    providers: tuple[str, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingPersisted(DomainEvent):
    finding_id: UUID


@dataclass(frozen=True, slots=True, kw_only=True)
class FindingExported(DomainEvent):
    finding_id: UUID
    target: str
