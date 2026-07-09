"""The deduplication engine.

Responsibility
--------------
Implement :class:`DeduplicationEnginePort`: prevent the same intelligence from
being stored and re-exported repeatedly. It combines several strategies so
duplicates are caught even when connectors present the same leak differently:

* **Content hash** — exact-match on normalised text (fast path).
* **Strong-identity IOCs** — same credit card / CPF / CNPJ / wallet / email set.
* **Textual similarity** — token Jaccard similarity above a threshold.

A ``fingerprint`` is stored on the finding so persistence can index it.

Business rules
--------------
* The engine keeps an in-memory index of what it has seen this run, seeded from
  the persistence context, so it works across a batch and across connectors.
* Similarity threshold is configurable (default 0.9).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence

from threat_hunting.core.application.ports.pipeline_stages import (
    DeduplicationEnginePort,
)
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import IndicatorType

_TOKEN = re.compile(r"\w+")
_STRONG_TYPES = {
    IndicatorType.CREDIT_CARD,
    IndicatorType.CPF,
    IndicatorType.CNPJ,
    IndicatorType.BTC_WALLET,
    IndicatorType.ETH_WALLET,
    IndicatorType.EMAIL,
}


class DeduplicationEngine(DeduplicationEnginePort):
    """Detects duplicate findings via hashing, IOC identity and similarity."""

    def __init__(self, *, similarity_threshold: float = 0.9) -> None:
        self._threshold = similarity_threshold
        self._hashes: set[str] = set()
        self._strong_iocs: set[str] = set()
        self._token_sets: list[tuple[str, frozenset[str]]] = []

    def is_duplicate(self, finding: Finding, context: Sequence[Finding]) -> bool:
        """Return whether the finding duplicates something already seen."""
        content_hash = self._content_hash(finding)
        finding.metadata["fingerprint"] = content_hash

        if content_hash in self._hashes:
            return True

        strong = self._strong_identities(finding)
        if strong & self._strong_iocs:
            return True

        tokens = self._tokens(finding)
        for _, seen_tokens in self._token_sets:
            if self._jaccard(tokens, seen_tokens) >= self._threshold:
                return True
        return False

    def register(self, finding: Finding) -> None:
        """Remember a finding so later duplicates are detected."""
        self._hashes.add(self._content_hash(finding))
        self._strong_iocs.update(self._strong_identities(finding))
        self._token_sets.append((finding.id, self._tokens(finding)))

    def seed(self, context: Sequence[Finding]) -> None:
        """Pre-load the index from persisted context (idempotent per finding)."""
        for finding in context:
            self.register(finding)

    # -- strategies --------------------------------------------------------

    @staticmethod
    def _content_hash(finding: Finding) -> str:
        """SHA-256 of the normalised searchable text."""
        text = (finding.normalized_data.get("text") or finding.description or "").strip()
        basis = f"{finding.title.strip().lower()}|{text.lower()}"
        return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()

    @staticmethod
    def _strong_identities(finding: Finding) -> set[str]:
        """Return fingerprints of strong-identity indicators."""
        return {
            i.fingerprint() for i in finding.indicators if i.type in _STRONG_TYPES
        }

    @staticmethod
    def _tokens(finding: Finding) -> frozenset[str]:
        """Tokenise the finding text for Jaccard similarity."""
        text = (finding.normalized_data.get("text") or finding.description or "").lower()
        return frozenset(_TOKEN.findall(text))

    @staticmethod
    def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
        """Jaccard similarity between two token sets."""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)
