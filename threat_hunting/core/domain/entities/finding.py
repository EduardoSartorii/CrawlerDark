"""Finding — agregado raiz do domínio.

Todas as descobertas (leaks, IOCs, credenciais, etc.) atravessam a plataforma
como instâncias de ``Finding``. Este é o **contrato canônico** que TODOS os
conectores devem produzir.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from ..exceptions import InvalidFindingError
from ..value_objects import Category, Confidence, Score, Severity, SourceRef, TLP
from .artifact import Artifact
from .indicator import Indicator
from .relationship import Relationship
from .timeline_event import TimelineEvent


@dataclass(slots=True, kw_only=True)
class Finding:
    """Agregado raiz.

    Invariantes:
    * ``title`` obrigatório;
    * ``source`` obrigatório e imutável;
    * ``created_at`` <= ``updated_at``;
    * mudanças de estado devem passar por métodos que registram Timeline.
    """

    id: UUID = field(default_factory=uuid4)
    title: str
    description: str = ""
    source: SourceRef
    connector: str
    category: Category = Category.OTHER
    severity: Severity = Severity.INFO
    score: Score = field(default_factory=Score.zero)
    confidence: Confidence = field(default_factory=Confidence.medium)
    tlp: TLP = TLP.AMBER
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: dict[str, Any] = field(default_factory=dict)
    normalized_data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    artifacts: list[Artifact] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    dedup_hash: str | None = None
    exported_to: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if not self.title or not self.title.strip():
            raise InvalidFindingError("Finding.title is required")
        if self.source is None:
            raise InvalidFindingError("Finding.source is required")
        if not self.connector:
            self.connector = self.source.connector
        if self.updated_at < self.created_at:
            raise InvalidFindingError("Finding.updated_at cannot precede created_at")

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)

    def add_indicator(self, indicator: Indicator) -> None:
        for existing in self.indicators:
            if (
                existing.type == indicator.type
                and existing.value.lower() == indicator.value.lower()
            ):
                existing.merge_from(indicator)
                self.touch()
                return
        self.indicators.append(indicator)
        self.touch()

    def add_artifact(self, artifact: Artifact) -> None:
        self.artifacts.append(artifact)
        self.touch()

    def add_relationship(self, relationship: Relationship) -> None:
        self.relationships.append(relationship)
        self.touch()

    def add_tags(self, *tags: str) -> None:
        for tag in tags:
            if tag:
                self.tags.add(tag)
        self.touch()

    def record_event(self, kind: str, message: str, payload: dict[str, Any] | None = None) -> None:
        self.timeline.append(TimelineEvent(kind=kind, message=message, payload=payload or {}))
        self.touch()

    def set_score(self, score: Score, reason: str = "") -> None:
        self.score = score
        self.record_event("score.updated", reason or f"score={score.value:.2f}", {"score": score.value})

    def set_severity(self, severity: Severity, reason: str = "") -> None:
        self.severity = severity
        self.record_event("severity.updated", reason or severity.name, {"severity": severity.name})

    def mark_exported(self, target: str) -> None:
        self.exported_to.add(target)
        self.record_event("export", f"exported to {target}", {"target": target})
