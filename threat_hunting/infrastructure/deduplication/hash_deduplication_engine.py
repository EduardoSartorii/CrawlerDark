"""HashDeduplicationEngine — dedup por ``dedup_hash`` + Jaccard textual fallback."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from ...core.domain.entities import Finding


class HashDeduplicationEngine:
    """Retorna ``(finding, is_duplicate)``.

    Estratégia:
    1. Se ``dedup_hash`` idêntico existe no corpus, é duplicata definitiva.
    2. Caso contrário, aplica Jaccard-shingles no texto normalizado.
       Se >= ``similarity_threshold`` (default 0.9), é duplicata provável.
    """

    def __init__(self, *, similarity_threshold: float = 0.9, shingle_size: int = 5) -> None:
        self._threshold = similarity_threshold
        self._shingle = shingle_size

    async def deduplicate(
        self, finding: Finding, corpus: Sequence[Finding]
    ) -> tuple[Finding, bool]:
        if finding.dedup_hash is None:
            finding.dedup_hash = self._quick_hash(finding)
        for other in corpus:
            if other.id == finding.id:
                continue
            if other.dedup_hash and finding.dedup_hash == other.dedup_hash:
                return finding, True
        finding_shingles = self._shingles(f"{finding.title}\n{finding.description}")
        if not finding_shingles:
            return finding, False
        for other in corpus:
            if other.id == finding.id:
                continue
            other_shingles = self._shingles(f"{other.title}\n{other.description}")
            if not other_shingles:
                continue
            intersect = len(finding_shingles & other_shingles)
            union = len(finding_shingles | other_shingles)
            if union == 0:
                continue
            if intersect / union >= self._threshold:
                return finding, True
        return finding, False

    @staticmethod
    def _quick_hash(finding: Finding) -> str:
        return hashlib.sha256(
            (finding.title + "|" + finding.source.source).lower().encode("utf-8")
        ).hexdigest()

    def _shingles(self, text: str) -> set[str]:
        text = " ".join(text.lower().split())
        if len(text) < self._shingle:
            return set()
        return {text[i : i + self._shingle] for i in range(len(text) - self._shingle + 1)}
