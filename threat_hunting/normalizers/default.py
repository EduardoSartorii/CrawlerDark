"""Canonical finding normalization."""

from __future__ import annotations

from datetime import UTC, datetime

from threat_hunting.core.domain.entities import Finding


class CanonicalFindingNormalizer:
    """Normalize tags, indicator values and timestamp updates."""

    def normalize(self, finding: Finding) -> Finding:
        """Return a normalized immutable copy of a finding."""

        tags = {tag.lower().strip() for tag in finding.tags if tag.strip()}
        tags.add(finding.category.lower().strip())
        indicators = [
            indicator.model_copy(update={"value": indicator.value.strip()})
            for indicator in finding.indicators
            if indicator.value.strip()
        ]
        normalized_data = dict(finding.normalized_data)
        normalized_data.setdefault("canonical_source", finding.source.lower())
        return finding.model_copy(
            update={
                "tags": sorted(tags),
                "indicators": indicators,
                "normalized_data": normalized_data,
                "updated_at": datetime.now(UTC),
            }
        )
