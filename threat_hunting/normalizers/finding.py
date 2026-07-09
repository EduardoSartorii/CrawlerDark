"""Canonical finding normalizer."""

from __future__ import annotations

from typing import Any

from threat_hunting.core.domain.entities import Artifact, Finding, Indicator


class FindingNormalizer:
    """Build canonical findings from intermediate parsed data."""

    def normalize(
        self,
        payload: dict[str, Any],
        *,
        source: str,
        connector: str,
        category: str,
        artifacts: list[Artifact] | None = None,
        indicators: list[Indicator] | None = None,
    ) -> Finding:
        """Return a canonical Finding aggregate."""

        title = str(payload.get("title") or f"{connector} observation")
        description = str(payload.get("description") or payload.get("content") or title)
        return Finding(
            title=title,
            description=description,
            source=source,
            connector=connector,
            category=category,
            raw_data=dict(payload),
            normalized_data={"title": title, "description": description},
            tags=list(payload.get("tags", [])),
            artifacts=artifacts or [],
            indicators=indicators or [],
        )
