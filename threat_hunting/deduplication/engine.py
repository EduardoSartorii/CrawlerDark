"""Deduplication engine based on content fingerprint and key indicators."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from threat_hunting.core.contracts import DeduplicationEnginePort
from threat_hunting.domain.entities import ExecutionContext, Finding


class FingerprintDeduplicationEngine(DeduplicationEnginePort):
    """Drops duplicate findings using deterministic fingerprinting."""

    def process(self, findings: Sequence[Finding], context: ExecutionContext) -> Sequence[Finding]:
        """Return first occurrence of each fingerprint."""
        seen: set[str] = set()
        unique: list[Finding] = []
        for finding in findings:
            fingerprint = self._fingerprint(finding)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            unique.append(finding)
        return unique

    @staticmethod
    def _fingerprint(finding: Finding) -> str:
        indicators = "|".join(sorted(f"{i.type}:{i.value.lower()}" for i in finding.indicators))
        base = f"{finding.title.lower()}|{finding.description.lower()}|{indicators}"
        return hashlib.sha256(base.encode("utf-8")).hexdigest()
