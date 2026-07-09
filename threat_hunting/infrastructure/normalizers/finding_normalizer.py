"""FindingNormalizer.

Responsibility
--------------
Produce a canonical view of a finding so that all downstream engines behave
deterministically regardless of the source's formatting quirks:

* collapse redundant whitespace in title/description;
* build ``normalized_data`` with lower-cased, whitespace-collapsed text and a
  sorted list of indicator keys;
* record a timeline entry for auditability.

The normalizer never invents data — it only canonicalises what already exists.
"""

from __future__ import annotations

import re

from threat_hunting.core.domain.entities.finding import Finding

_WHITESPACE = re.compile(r"\s+")


class FindingNormalizer:
    """Canonicalises a :class:`Finding` in place and returns it."""

    def normalize(self, finding: Finding) -> Finding:
        """Return the finding with canonicalised text and ``normalized_data``."""
        title = _WHITESPACE.sub(" ", finding.title).strip()
        description = _WHITESPACE.sub(" ", finding.description).strip()
        object.__setattr__(finding, "title", title or finding.title)
        object.__setattr__(finding, "description", description)

        combined = f"{title}\n{description}".strip()
        finding.normalized_data.update(
            {
                "text": combined,
                "text_lower": combined.lower(),
                "indicator_keys": sorted(finding.indicator_keys),
            }
        )
        finding.record("normalized", "canonicalised text and indicators")
        return finding
