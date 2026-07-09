"""Deduplication strategies (Strategy Pattern).

Responsibility
--------------
Provide interchangeable ways to decide whether two findings are "the same":

* :class:`HashStrategy` -- identical normalized text (SHA-256 fingerprint).
* :class:`IndicatorStrategy` -- overlapping indicator sets above a ratio.
* :class:`SimilarityStrategy` -- Jaccard token similarity above a threshold.

Each strategy exposes :meth:`fingerprint` (fast exact key) and/or
:meth:`is_duplicate` (pairwise). The engine combines them.
"""

from __future__ import annotations

import hashlib

from threat_hunting.core.domain.entities.finding import Finding


def _tokens(finding: Finding) -> set[str]:
    text = finding.normalized_data.get("text_lower") or (
        f"{finding.title} {finding.description}".lower()
    )
    return {tok for tok in text.split() if len(tok) > 2}


class HashStrategy:
    """Exact-duplicate detection via a SHA-256 of the normalized text."""

    name = "hash"

    def fingerprint(self, finding: Finding) -> str:
        """Return a stable content fingerprint for exact-match dedup."""
        text = finding.normalized_data.get("text") or f"{finding.title}\n{finding.description}"
        return hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()

    def is_duplicate(self, a: Finding, b: Finding) -> bool:
        """Return whether two findings share the same content fingerprint."""
        return self.fingerprint(a) == self.fingerprint(b)


class IndicatorStrategy:
    """Duplicate when two findings share most of their indicators."""

    name = "indicator"

    def __init__(self, min_overlap: float = 0.8) -> None:
        self._min_overlap = min_overlap

    def is_duplicate(self, a: Finding, b: Finding) -> bool:
        """Return whether indicator-set overlap exceeds the configured ratio."""
        ka, kb = a.indicator_keys, b.indicator_keys
        if not ka or not kb:
            return False
        overlap = len(ka & kb) / len(ka | kb)
        return overlap >= self._min_overlap


class SimilarityStrategy:
    """Duplicate when Jaccard token similarity exceeds a threshold."""

    name = "similarity"

    def __init__(self, threshold: float = 0.85) -> None:
        self._threshold = threshold

    def is_duplicate(self, a: Finding, b: Finding) -> bool:
        """Return whether the two findings' texts are near-identical."""
        ta, tb = _tokens(a), _tokens(b)
        if not ta or not tb:
            return False
        similarity = len(ta & tb) / len(ta | tb)
        return similarity >= self._threshold
