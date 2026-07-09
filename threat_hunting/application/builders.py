"""Builder pattern helpers for canonical domain entities."""

from __future__ import annotations

from typing import Any

from threat_hunting.domain.entities import Finding, Severity


class FindingBuilder:
    """Build canonical Finding objects from partial stage payloads."""

    def __init__(self) -> None:
        self._payload: dict[str, Any] = {}

    def with_base(self, *, title: str, description: str, source: str, connector: str, category: str) -> "FindingBuilder":
        """Set mandatory fields."""
        self._payload.update(
            {
                "title": title,
                "description": description,
                "source": source,
                "connector": connector,
                "category": category,
            }
        )
        return self

    def with_severity(self, severity: str) -> "FindingBuilder":
        """Set severity using safe enum conversion."""
        self._payload["severity"] = Severity(severity)
        return self

    def with_scores(self, *, score: float, confidence: float) -> "FindingBuilder":
        """Set score/confidence."""
        self._payload["score"] = score
        self._payload["confidence"] = confidence
        return self

    def with_payload(
        self,
        *,
        raw_data: dict[str, Any],
        normalized_data: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> "FindingBuilder":
        """Set raw and normalized payload sections."""
        self._payload["raw_data"] = raw_data
        self._payload["normalized_data"] = normalized_data
        self._payload["metadata"] = metadata or {}
        return self

    def with_tags(self, tags: list[str]) -> "FindingBuilder":
        """Set finding tags."""
        self._payload["tags"] = tags
        return self

    def build(self) -> Finding:
        """Produce validated Finding entity."""
        return Finding(**self._payload)
