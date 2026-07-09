"""Normalizer implementations for Finding draft production."""

from __future__ import annotations

from threat_hunting.core.contracts.services import ExtractedData, INormalizer
from threat_hunting.core.domain.entities import FindingDraft, Indicator
from threat_hunting.core.domain.enums import IndicatorType, SourceType


class FindingNormalizer(INormalizer):
    """Normalizes extracted data into standardized Finding drafts."""

    def normalize(self, extracted: ExtractedData, connector: str, source_type: str) -> FindingDraft:
        parsed = extracted.parsed
        title = str(parsed.fields.get("title", f"{connector} finding"))

        draft = FindingDraft(
            title=title,
            description=parsed.content[:2000],
            source=SourceType(source_type),
            connector=connector,
            raw_data=parsed.fields,
            normalized_data={"entities": extracted.entities, "content": parsed.content},
            metadata=parsed.metadata,
        )

        for ind in extracted.indicators:
            try:
                draft.indicators.append(
                    Indicator(type=IndicatorType(ind["type"]), value=ind["value"])
                )
            except ValueError:
                continue

        return draft
