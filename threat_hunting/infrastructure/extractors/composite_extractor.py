"""CompositeExtractor — compõe múltiplos extractors (Chain of Responsibility)."""

from __future__ import annotations

from collections.abc import Sequence

from ...core.domain.entities import Finding
from ...core.domain.ports import ExtractorPort


class CompositeExtractor:
    """Aplica uma lista de extractors em sequência sobre o mesmo finding."""

    def __init__(self, extractors: Sequence[ExtractorPort]) -> None:
        self._extractors = list(extractors)

    async def extract(self, finding: Finding) -> Finding:
        for extractor in self._extractors:
            finding = await extractor.extract(finding)
        return finding
