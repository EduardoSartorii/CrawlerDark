"""Parser implementations for pipeline stage 2."""

from __future__ import annotations

from threat_hunting.core.contracts.services import IParser, ParsedData, RawPayload


class GenericParser(IParser):
    """Default parser that extracts common fields from raw payloads."""

    def parse(self, payload: RawPayload) -> ParsedData:
        data = payload.data
        content = str(data.get("content", data.get("html", data.get("body", ""))))
        return ParsedData(
            fields=data,
            content=content,
            metadata={"source_uri": payload.source_uri, **payload.metadata},
        )
