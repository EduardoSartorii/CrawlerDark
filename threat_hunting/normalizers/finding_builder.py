"""Builder pattern for canonical Finding creation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from threat_hunting.domain.entities import Artifact, Finding, Indicator


@dataclass(slots=True)
class FindingBuilder:
    """Step-by-step builder to assemble normalized findings safely."""

    title: str = "untitled finding"
    description: str = ""
    source: str = "unknown"
    connector: str = "unknown"
    category: str = "generic"
    raw_data: dict[str, Any] = field(default_factory=dict)
    normalized_data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)

    def with_basics(
        self,
        *,
        title: str,
        description: str,
        source: str,
        connector: str,
        category: str,
    ) -> "FindingBuilder":
        self.title = title
        self.description = description
        self.source = source
        self.connector = connector
        self.category = category
        return self

    def with_payload(
        self,
        *,
        raw_data: dict[str, Any],
        normalized_data: dict[str, Any],
        metadata: dict[str, Any],
    ) -> "FindingBuilder":
        self.raw_data = raw_data
        self.normalized_data = normalized_data
        self.metadata = metadata
        return self

    def with_tags(self, tags: list[str]) -> "FindingBuilder":
        self.tags = tags
        return self

    def with_indicators(self, indicators: list[Indicator]) -> "FindingBuilder":
        self.indicators = indicators
        return self

    def with_artifacts(self, artifacts: list[Artifact]) -> "FindingBuilder":
        self.artifacts = artifacts
        return self

    def build(self) -> Finding:
        return Finding(
            title=self.title,
            description=self.description,
            source=self.source,
            connector=self.connector,
            category=self.category,
            raw_data=self.raw_data,
            normalized_data=self.normalized_data,
            metadata=self.metadata,
            tags=self.tags,
            indicators=self.indicators,
            artifacts=self.artifacts,
        )
