"""Mappers domínio ↔ modelos SQLAlchemy.

Isolamos aqui toda a lógica de tradução; entidades permanecem puras.
"""

from __future__ import annotations

from datetime import timezone
from typing import Any

from ....core.domain.entities import (
    Artifact,
    DetectionRule,
    Finding,
    Indicator,
    Job,
    JobStatus,
    Relationship,
    RelationshipType,
    ThreatActor,
    TimelineEvent,
    WatchlistItem,
    WatchlistKind,
)
from ....core.domain.entities.detection_rule import RuleKind
from ....core.domain.value_objects import (
    Category,
    Confidence,
    IndicatorType,
    Score,
    Severity,
    SourceRef,
    TLP,
)
from .models import (
    DetectionRuleModel,
    FindingModel,
    IndicatorModel,
    JobModel,
    ThreatActorModel,
    WatchlistItemModel,
)


def _ensure_utc(dt):  # type: ignore[no-untyped-def]
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

def finding_to_model(finding: Finding) -> FindingModel:
    return FindingModel(
        id=finding.id,
        title=finding.title,
        description=finding.description,
        source=finding.source.source,
        connector=finding.connector,
        url=finding.source.url,
        author=finding.source.author,
        category=finding.category.value,
        severity=finding.severity.name,
        score=float(finding.score),
        confidence=int(finding.confidence),
        tlp=finding.tlp.value,
        dedup_hash=finding.dedup_hash,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
        collected_at=finding.source.collected_at,
        raw_data=dict(finding.raw_data),
        normalized_data=dict(finding.normalized_data),
        metadata_=dict(finding.metadata),
        tags=sorted(finding.tags),
        artifacts=[_artifact_to_dict(a) for a in finding.artifacts],
        relationships_json=[_relationship_to_dict(r) for r in finding.relationships],
        timeline=[_timeline_to_dict(t) for t in finding.timeline],
        exported_to=sorted(finding.exported_to),
        indicators=[indicator_to_model(i) for i in finding.indicators],
    )


def apply_finding_updates(model: FindingModel, finding: Finding) -> None:
    """Aplica mudanças em um modelo persistido a partir da entidade (update)."""
    model.title = finding.title
    model.description = finding.description
    model.source = finding.source.source
    model.connector = finding.connector
    model.url = finding.source.url
    model.author = finding.source.author
    model.category = finding.category.value
    model.severity = finding.severity.name
    model.score = float(finding.score)
    model.confidence = int(finding.confidence)
    model.tlp = finding.tlp.value
    model.dedup_hash = finding.dedup_hash
    model.updated_at = finding.updated_at
    model.raw_data = dict(finding.raw_data)
    model.normalized_data = dict(finding.normalized_data)
    model.metadata_ = dict(finding.metadata)
    model.tags = sorted(finding.tags)
    model.artifacts = [_artifact_to_dict(a) for a in finding.artifacts]
    model.relationships_json = [_relationship_to_dict(r) for r in finding.relationships]
    model.timeline = [_timeline_to_dict(t) for t in finding.timeline]
    model.exported_to = sorted(finding.exported_to)


def finding_from_model(model: FindingModel) -> Finding:
    source = SourceRef(
        source=model.source,
        connector=model.connector,
        collected_at=_ensure_utc(model.collected_at),
        url=model.url,
        author=model.author,
    )
    return Finding(
        id=model.id,
        title=model.title,
        description=model.description or "",
        source=source,
        connector=model.connector,
        category=Category.coerce(model.category),
        severity=Severity.from_string(model.severity),
        score=Score(model.score),
        confidence=Confidence(int(model.confidence)),
        tlp=TLP.coerce(model.tlp),
        created_at=_ensure_utc(model.created_at),
        updated_at=_ensure_utc(model.updated_at),
        raw_data=dict(model.raw_data or {}),
        normalized_data=dict(model.normalized_data or {}),
        metadata=dict(model.metadata_ or {}),
        tags=set(model.tags or []),
        artifacts=[_artifact_from_dict(a) for a in (model.artifacts or [])],
        indicators=[indicator_from_model(i) for i in (model.indicators or [])],
        relationships=[_relationship_from_dict(r) for r in (model.relationships_json or [])],
        timeline=[_timeline_from_dict(t) for t in (model.timeline or [])],
        dedup_hash=model.dedup_hash,
        exported_to=set(model.exported_to or []),
    )


def _artifact_to_dict(a: Artifact) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "kind": a.kind,
        "filename": a.filename,
        "content_type": a.content_type,
        "sha256": a.sha256,
        "size_bytes": a.size_bytes,
        "storage_uri": a.storage_uri,
        "metadata": dict(a.metadata),
    }


def _artifact_from_dict(raw: dict[str, Any]) -> Artifact:
    from uuid import UUID
    return Artifact(
        id=UUID(raw["id"]) if raw.get("id") else UUID(int=0),
        kind=raw.get("kind", "unknown"),
        filename=raw.get("filename"),
        content_type=raw.get("content_type"),
        sha256=raw.get("sha256"),
        size_bytes=raw.get("size_bytes"),
        storage_uri=raw.get("storage_uri"),
        metadata=dict(raw.get("metadata", {})),
    )


def _relationship_to_dict(r: Relationship) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "source_id": str(r.source_id),
        "target_id": str(r.target_id),
        "type": r.type.value,
        "context": dict(r.context),
    }


def _relationship_from_dict(raw: dict[str, Any]) -> Relationship:
    from uuid import UUID
    return Relationship(
        id=UUID(raw["id"]),
        source_id=UUID(raw["source_id"]),
        target_id=UUID(raw["target_id"]),
        type=RelationshipType(raw["type"]),
        context=dict(raw.get("context", {})),
    )


def _timeline_to_dict(t: TimelineEvent) -> dict[str, Any]:
    return {
        "id": str(t.id),
        "kind": t.kind,
        "message": t.message,
        "at": t.at.isoformat(),
        "payload": dict(t.payload),
    }


def _timeline_from_dict(raw: dict[str, Any]) -> TimelineEvent:
    from datetime import datetime
    from uuid import UUID
    return TimelineEvent(
        id=UUID(raw["id"]),
        kind=raw["kind"],
        message=raw["message"],
        at=datetime.fromisoformat(raw["at"]),
        payload=dict(raw.get("payload", {})),
    )


# ---------------------------------------------------------------------------
# Indicator
# ---------------------------------------------------------------------------

def indicator_to_model(i: Indicator) -> IndicatorModel:
    return IndicatorModel(
        id=i.id,
        type=i.type.value,
        value=i.value,
        confidence=int(i.confidence),
        tags=sorted(i.tags),
        first_seen=i.first_seen,
        last_seen=i.last_seen,
        context=dict(i.context),
    )


def indicator_from_model(m: IndicatorModel) -> Indicator:
    return Indicator(
        id=m.id,
        type=IndicatorType(m.type),
        value=m.value,
        confidence=Confidence(int(m.confidence)),
        tags=set(m.tags or []),
        first_seen=_ensure_utc(m.first_seen),
        last_seen=_ensure_utc(m.last_seen),
        context=dict(m.context or {}),
    )


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------

def job_to_model(j: Job) -> JobModel:
    return JobModel(
        id=j.id,
        connector=j.connector,
        started_at=j.started_at,
        finished_at=j.finished_at,
        status=j.status.value,
        items_collected=j.items_collected,
        items_persisted=j.items_persisted,
        errors=list(j.errors),
        metadata_=dict(j.metadata),
    )


def apply_job_updates(model: JobModel, j: Job) -> None:
    model.finished_at = j.finished_at
    model.status = j.status.value
    model.items_collected = j.items_collected
    model.items_persisted = j.items_persisted
    model.errors = list(j.errors)
    model.metadata_ = dict(j.metadata)


def job_from_model(m: JobModel) -> Job:
    return Job(
        id=m.id,
        connector=m.connector,
        started_at=_ensure_utc(m.started_at),
        finished_at=_ensure_utc(m.finished_at),
        status=JobStatus(m.status),
        items_collected=m.items_collected,
        items_persisted=m.items_persisted,
        errors=list(m.errors or []),
        metadata=dict(m.metadata_ or {}),
    )


# ---------------------------------------------------------------------------
# ThreatActor / Watchlist / DetectionRule
# ---------------------------------------------------------------------------

def threat_actor_to_model(t: ThreatActor) -> ThreatActorModel:
    return ThreatActorModel(
        id=t.id,
        name=t.name,
        aliases=sorted(t.aliases),
        description=t.description,
        motivations=sorted(t.motivations),
        countries=sorted(t.countries),
        tags=sorted(t.tags),
        context=dict(t.context),
    )


def threat_actor_from_model(m: ThreatActorModel) -> ThreatActor:
    return ThreatActor(
        id=m.id,
        name=m.name,
        aliases=set(m.aliases or []),
        description=m.description or "",
        motivations=set(m.motivations or []),
        countries=set(m.countries or []),
        tags=set(m.tags or []),
        context=dict(m.context or {}),
    )


def watchlist_to_model(w: WatchlistItem) -> WatchlistItemModel:
    return WatchlistItemModel(
        id=w.id,
        kind=w.kind.value,
        value=w.value,
        aliases=sorted(w.aliases),
        tags=sorted(w.tags),
        enabled=w.enabled,
        context=dict(w.context),
    )


def watchlist_from_model(m: WatchlistItemModel) -> WatchlistItem:
    return WatchlistItem(
        id=m.id,
        kind=WatchlistKind(m.kind),
        value=m.value,
        aliases=set(m.aliases or []),
        tags=set(m.tags or []),
        enabled=bool(m.enabled),
        context=dict(m.context or {}),
    )


def rule_to_model(r: DetectionRule) -> DetectionRuleModel:
    return DetectionRuleModel(
        id=r.id,
        rule_id=r.rule_id,
        kind=r.kind.value,
        pattern=r.pattern,
        description=r.description,
        category=r.category.value,
        severity=r.severity.name,
        confidence=int(r.confidence),
        tags=sorted(r.tags),
        enabled=r.enabled,
        depends_on=list(r.depends_on),
    )


def rule_from_model(m: DetectionRuleModel) -> DetectionRule:
    return DetectionRule(
        id=m.id,
        rule_id=m.rule_id,
        kind=RuleKind(m.kind),
        pattern=m.pattern,
        description=m.description or "",
        category=Category.coerce(m.category),
        severity=Severity.from_string(m.severity),
        confidence=Confidence(int(m.confidence)),
        tags=set(m.tags or []),
        enabled=bool(m.enabled),
        depends_on=list(m.depends_on or []),
    )
