"""FindingBuilder — Builder Pattern.

Responsibility
--------------
Fluent construction of complex Finding aggregates ensuring invariants
(title required, content hash computed, timeline seeded).
"""

from __future__ import annotations

from typing import Any, Self

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import FindingCategory, Severity
from threat_hunting.core.domain.value_objects import (
    Artifact,
    Confidence,
    FindingMetadata,
    Indicator,
    Score,
    Tag,
    TimelineEvent,
)


class FindingBuilder:
    """Builder Pattern for Finding aggregate construction.

    Usage
    -----
    finding = (
        FindingBuilder()
        .with_title("Leak detected")
        .with_source("darkweb")
        .with_connector("ransomexx")
        .with_category(FindingCategory.LEAK)
        .add_tag("ransomware")
        .add_indicator(indicator)
        .build()
    )
    """

    def __init__(self) -> None:
        self._title: str = ""
        self._description: str = ""
        self._source: str = ""
        self._connector: str = ""
        self._category: FindingCategory = FindingCategory.OTHER
        self._severity: Severity = Severity.INFORMATIONAL
        self._score: Score = Score()
        self._confidence: Confidence = Confidence()
        self._raw_data: dict[str, Any] = {}
        self._normalized_data: dict[str, Any] = {}
        self._metadata: FindingMetadata = FindingMetadata()
        self._tags: list[Tag] = []
        self._artifacts: list[Artifact] = []
        self._indicators: list[Indicator] = []
        self._timeline: list[TimelineEvent] = []

    def with_title(self, title: str) -> Self:
        self._title = title
        return self

    def with_description(self, description: str) -> Self:
        self._description = description
        return self

    def with_source(self, source: str) -> Self:
        self._source = source
        return self

    def with_connector(self, connector: str) -> Self:
        self._connector = connector
        return self

    def with_category(self, category: FindingCategory) -> Self:
        self._category = category
        return self

    def with_severity(self, severity: Severity) -> Self:
        self._severity = severity
        return self

    def with_score(self, score: float) -> Self:
        self._score = Score(value=score)
        return self

    def with_confidence(self, confidence: float) -> Self:
        self._confidence = Confidence(value=confidence)
        return self

    def with_raw_data(self, data: dict[str, Any]) -> Self:
        self._raw_data = data
        return self

    def with_normalized_data(self, data: dict[str, Any]) -> Self:
        self._normalized_data = data
        return self

    def with_metadata(self, metadata: FindingMetadata) -> Self:
        self._metadata = metadata
        return self

    def add_tag(self, name: str) -> Self:
        self._tags.append(Tag(name=name))
        return self

    def add_artifact(self, artifact: Artifact) -> Self:
        self._artifacts.append(artifact)
        return self

    def add_indicator(self, indicator: Indicator) -> Self:
        self._indicators.append(indicator)
        return self

    def build(self) -> Finding:
        if not self._title:
            raise ValueError("FindingBuilder requires a title")
        if not self._source:
            raise ValueError("FindingBuilder requires a source")
        if not self._connector:
            raise ValueError("FindingBuilder requires a connector")

        finding = Finding(
            title=self._title,
            description=self._description,
            source=self._source,
            connector=self._connector,
            category=self._category,
            severity=self._severity,
            score=self._score,
            confidence=self._confidence,
            raw_data=self._raw_data,
            normalized_data=self._normalized_data,
            metadata=self._metadata,
            tags=self._tags,
            artifacts=self._artifacts,
            indicators=self._indicators,
            timeline=self._timeline
            or [
                TimelineEvent(
                    event_type="created",
                    description="Finding created via FindingBuilder",
                )
            ],
        )
        return finding


__all__ = ["FindingBuilder"]
