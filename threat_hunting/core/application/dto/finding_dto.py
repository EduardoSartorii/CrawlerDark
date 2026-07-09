"""DTOs Pydantic V2 para (des)serialização de findings, IOCs e artefatos."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ...domain.entities import Artifact, Finding, Indicator


class IndicatorDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    type: str
    value: str
    confidence: int
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    context: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_entity(cls, i: Indicator) -> "IndicatorDTO":
        return cls(
            id=i.id,
            type=i.type.value,
            value=i.value,
            confidence=i.confidence.value,
            tags=sorted(i.tags),
            first_seen=i.first_seen,
            last_seen=i.last_seen,
            context=dict(i.context),
        )


class ArtifactDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    kind: str
    filename: str | None
    content_type: str | None
    sha256: str | None
    size_bytes: int | None
    storage_uri: str | None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_entity(cls, a: Artifact) -> "ArtifactDTO":
        return cls(
            id=a.id,
            kind=a.kind,
            filename=a.filename,
            content_type=a.content_type,
            sha256=a.sha256,
            size_bytes=a.size_bytes,
            storage_uri=a.storage_uri,
            metadata=dict(a.metadata),
        )


class FindingDTO(BaseModel):
    """Serialização canônica de um ``Finding`` para APIs / exporters."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    description: str
    source: str
    connector: str
    url: str | None
    category: str
    severity: str
    score: float
    confidence: int
    tlp: str
    created_at: datetime
    updated_at: datetime
    tags: list[str]
    indicators: list[IndicatorDTO]
    artifacts: list[ArtifactDTO]
    metadata: dict[str, Any]
    normalized_data: dict[str, Any]
    dedup_hash: str | None
    exported_to: list[str]

    @classmethod
    def from_entity(cls, f: Finding) -> "FindingDTO":
        return cls(
            id=f.id,
            title=f.title,
            description=f.description,
            source=f.source.source,
            connector=f.connector,
            url=f.source.url,
            category=f.category.value,
            severity=f.severity.name,
            score=float(f.score),
            confidence=int(f.confidence),
            tlp=f.tlp.value,
            created_at=f.created_at,
            updated_at=f.updated_at,
            tags=sorted(f.tags),
            indicators=[IndicatorDTO.from_entity(i) for i in f.indicators],
            artifacts=[ArtifactDTO.from_entity(a) for a in f.artifacts],
            metadata=dict(f.metadata),
            normalized_data=dict(f.normalized_data),
            dedup_hash=f.dedup_hash,
            exported_to=sorted(f.exported_to),
        )
