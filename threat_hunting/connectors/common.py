"""Shared helpers for connector implementations."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.core.application.ports import ParsedDocument, RawDocument
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import FindingCategory, HealthState, Severity
from threat_hunting.core.domain.value_objects import HealthStatus, utc_now


class SimpleConnector(BaseConnector):
    """Convenience base for connectors with dict-based documents.

    Subclasses implement `_fetch()` yielding raw dicts. parse/normalize
    use shared defaults. Ideal for feeds/APIs with homogeneous payloads.
    """

    default_category = FindingCategory.OSINT

    async def connect(self) -> None:
        self._connected = True
        self._log.info("connector.connected")

    async def _fetch(self) -> AsyncIterator[dict[str, Any]]:
        """Override to yield source documents. Default: demo sample."""
        samples = self._options.get("samples") or self._demo_samples()
        for sample in samples:
            yield sample

    def _demo_samples(self) -> list[dict[str, Any]]:
        return [
            {
                "title": f"[{self.name}] Sample intelligence item",
                "description": (
                    f"Demo finding from {self.name} connector. "
                    "Configure credentials/endpoints for live collection. "
                    "Contact: analyst@example.org IOC: 203.0.113.10 "
                    "domain evil-demo.example hash "
                    "d41d8cd98f00b204e9800998ecf8427e"
                ),
                "url": f"https://example.local/{self.name}/sample",
                "author": "demo",
                "tags": ["demo", self.category_group],
            }
        ]

    async def collect(self) -> AsyncIterator[RawDocument]:  # type: ignore[override]
        async for item in self._fetch():
            yield RawDocument(item)

    async def parse(self, raw: RawDocument) -> ParsedDocument:
        data = dict(raw)
        extracted = data.pop("_extracted", None)
        parsed = ParsedDocument(data)
        if extracted is not None:
            parsed["_extracted"] = extracted
        return parsed

    async def normalize(self, parsed: ParsedDocument) -> Finding:
        extracted = parsed.get("_extracted") if isinstance(parsed.get("_extracted"), dict) else {}
        title = str(parsed.get("title") or f"Finding from {self.name}")[:500]
        description = str(
            parsed.get("description") or parsed.get("body") or parsed.get("content") or ""
        )[:5000]
        category = self.default_category
        if "category" in parsed:
            try:
                category = FindingCategory(parsed["category"])
            except ValueError:
                pass
        severity = Severity.INFORMATIONAL
        if "severity" in parsed:
            try:
                severity = Severity(parsed["severity"])
            except ValueError:
                pass

        raw_for_builder = {k: v for k, v in parsed.items() if k != "_extracted"}
        finding = self.build_finding(
            title=title,
            description=description,
            category=category,
            severity=severity,
            raw_data=raw_for_builder,
            url=parsed.get("url"),
            author=parsed.get("author"),
            tags=list(parsed.get("tags") or []),
            normalized_data={"extracted": extracted} if extracted else {},
        )
        # Pipeline may have injected _extracted indicators via build_finding
        if extracted:
            finding.raw_data = {**finding.raw_data, "_extracted": extracted}
            # Re-add via helper path
            from threat_hunting.core.domain.enums import IndicatorType
            from threat_hunting.core.domain.value_objects import Indicator

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

    async def health(self) -> HealthStatus:
        return HealthStatus(
            component=f"connector:{self.name}",
            state=HealthState.HEALTHY.value if self._connected else HealthState.UNKNOWN.value,
            message="ok" if self._connected else "idle",
            checked_at=utc_now(),
        )
