"""URLhausConnector — feed CSV público de URLs maliciosas."""

from __future__ import annotations

import csv
import io
from collections.abc import AsyncIterator
from typing import Any

from ....core.domain.builders import FindingBuilder
from ....core.domain.entities import Finding, Indicator
from ....core.domain.value_objects import Category, Confidence, IndicatorType, Severity, SourceRef
from ..base import BaseConnector
from ..registry import register_connector


@register_connector("urlhaus")
class URLhausConnector(BaseConnector):
    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        if self.http is None:
            raise RuntimeError("URLhausConnector requires HTTP client")
        url = str(self.options.get("feed_url", "https://urlhaus.abuse.ch/downloads/csv_recent/"))
        response = await self.http.get(url)
        text = response.text
        rows = self._parse_csv(text)
        for row in rows[:500]:
            yield row

    @staticmethod
    def _parse_csv(text: str) -> list[dict[str, str]]:
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        header = ["id", "dateadded", "url", "url_status", "last_online",
                  "threat", "tags", "urlhaus_link", "reporter"]
        reader = csv.reader(io.StringIO("\n".join(lines)))
        result: list[dict[str, str]] = []
        for cols in reader:
            if len(cols) < len(header):
                continue
            result.append(dict(zip(header, cols)))
        return result

    async def parse(self, payload: Any) -> dict[str, Any]:
        return payload if isinstance(payload, dict) else {}

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        url_value = parsed.get("url", "")
        threat = parsed.get("threat") or "malware_download"
        source = SourceRef(
            source="urlhaus",
            connector=self.name,
            url=parsed.get("urlhaus_link") or "https://urlhaus.abuse.ch/",
        )
        f = (
            FindingBuilder()
            .title(f"URLhaus: {threat} — {url_value[:120]}")
            .description(f"URLhaus reported {threat} activity for {url_value}")
            .source(source)
            .category(Category.MALWARE)
            .severity(Severity.HIGH)
            .confidence(Confidence(85))
            .tag("urlhaus", threat)
            .raw(parsed)
            .build()
        )
        if url_value:
            f.add_indicator(
                Indicator(
                    type=IndicatorType.URL,
                    value=url_value,
                    confidence=Confidence(90),
                    tags={"urlhaus", threat},
                    context={
                        "threat": threat,
                        "status": parsed.get("url_status"),
                        "reporter": parsed.get("reporter"),
                    },
                )
            )
        return f

    async def health(self) -> bool:
        return self.http is not None
