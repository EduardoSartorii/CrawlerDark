"""Shared parser / normalizer adapters used when connectors defer to pipeline ports."""

from __future__ import annotations

from typing import Any

from threat_hunting.core.application.ports import (
    NormalizerPort,
    ParsedDocument,
    ParserPort,
    RawDocument,
    ExtractedEntities,
)
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import FindingCategory, IndicatorType, Severity
from threat_hunting.core.domain.services import FindingBuilder
from threat_hunting.core.domain.value_objects import FindingMetadata, Indicator


class PassthroughParser(ParserPort):
    """Default parser — treats raw dict as already structured."""

    async def parse(self, raw: RawDocument, *, connector: str) -> ParsedDocument:
        if isinstance(raw, dict):
            return ParsedDocument(raw)
        return ParsedDocument({"content": str(raw), "connector": connector})


class DefaultNormalizer(NormalizerPort):
    """Build a Finding from parsed + extracted entities."""

    async def normalize(
        self,
        parsed: ParsedDocument,
        extracted: ExtractedEntities,
        *,
        connector: str,
        source: str,
    ) -> Finding:
        title = (
            parsed.get("title")
            or parsed.get("subject")
            or (parsed.get("content") or "")[:80]
            or f"Finding from {connector}"
        )
        description = parsed.get("description") or parsed.get("body") or parsed.get("content") or ""
        category = FindingCategory(parsed.get("category", FindingCategory.OTHER.value))
        severity = Severity(parsed.get("severity", Severity.INFORMATIONAL.value))

        builder = (
            FindingBuilder()
            .with_title(str(title)[:500])
            .with_description(str(description)[:5000])
            .with_source(source)
            .with_connector(connector)
            .with_category(category)
            .with_severity(severity)
            .with_raw_data(dict(parsed))
            .with_normalized_data({"extracted": dict(extracted)})
            .with_metadata(
                FindingMetadata(
                    url=parsed.get("url"),
                    author=parsed.get("author"),
                    language=parsed.get("language"),
                    extra={k: v for k, v in parsed.items() if k.startswith("meta_")},
                )
            )
        )
        for tag in parsed.get("tags", []) or []:
            builder.add_tag(str(tag))

        finding = builder.build()
        for item in extracted.get("indicators", []):
            try:
                finding.add_indicator(
                    Indicator(
                        type=IndicatorType(item["type"]),
                        value=item["value"],
                        context=item.get("context"),
                    )
                )
            except Exception:
                continue
        return finding


__all__ = ["PassthroughParser", "DefaultNormalizer"]
