"""Normalizer strategy that builds canonical Finding entities."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from threat_hunting.domain.entities import Artifact, Finding, Indicator
from threat_hunting.normalizers.finding_builder import FindingBuilder


class DefaultNormalizer:
    """Builds canonical findings from extracted records."""

    def process(
        self,
        extracted_items: Sequence[dict[str, Any]],
        connector_name: str,
    ) -> Sequence[Finding]:
        """Normalize arbitrary records into stable Finding schema."""
        findings: list[Finding] = []
        for item in extracted_items:
            indicators: list[Indicator] = []
            extracted = item.get("extracted", {})
            for email in extracted.get("emails", []):
                indicators.append(Indicator(type="email", value=email, confidence=0.8))
            for domain in extracted.get("domains", []):
                indicators.append(Indicator(type="domain", value=domain, confidence=0.7))

            artifacts: list[Artifact] = []
            screenshot_url = item.get("screenshot")
            if screenshot_url:
                artifacts.append(Artifact(type="screenshot", reference=screenshot_url))

            finding = (
                FindingBuilder()
                .with_basics(
                    title=str(item.get("title", "untitled finding")),
                    description=str(item.get("description", "")),
                    source=str(item.get("source", connector_name)),
                    connector=connector_name,
                    category=str(item.get("category", "generic")),
                )
                .with_payload(
                    raw_data=dict(item),
                    normalized_data={
                        "url": item.get("url"),
                        "author": item.get("author"),
                        "published_at": item.get("published_at"),
                    },
                    metadata={"origin_id": item.get("origin_id")},
                )
                .with_tags([connector_name])
                .with_artifacts(artifacts)
                .with_indicators(indicators)
                .build()
            )
            findings.append(finding)
        return findings
