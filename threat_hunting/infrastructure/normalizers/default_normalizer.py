"""Default normalizer.

Responsibility
--------------
Implement :class:`NormalizerPort`: populate the finding's ``normalized_data``
with a canonical, source-independent view (clean text, language-agnostic length,
url, collection time and an indicator summary). Downstream engines read
``normalized_data`` so they never depend on connector-specific ``raw_data``.
"""

from __future__ import annotations

from collections import Counter

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.application.ports.pipeline_stages import NormalizerPort
from threat_hunting.core.domain.entities import Finding


class DefaultNormalizer(NormalizerPort):
    """Builds a canonical ``normalized_data`` payload for a finding."""

    def normalize(self, finding: Finding, record: RawRecord) -> Finding:
        """Populate ``normalized_data`` and refresh the finding."""
        indicator_counts = Counter(i.type.value for i in finding.indicators)
        finding.normalized_data = {
            "text": record.content,
            "length": len(record.content or ""),
            "url": record.url,
            "collected_at": record.collected_at.isoformat(),
            "indicator_summary": dict(indicator_counts),
            "indicator_total": sum(indicator_counts.values()),
        }
        finding.record("normalizer", "normalized_data populated")
        return finding
