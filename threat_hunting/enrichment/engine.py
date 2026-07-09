"""Enrichment Engine.

Responsibility
--------------
Enrich Findings with contextual intelligence (source metadata, IOC
classification, lightweight reputation stubs). External TI enrichers
(VirusTotal, GreyNoise, OTX) plug in via EnricherStrategy without
coupling the Core.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import structlog

from threat_hunting.core.application.ports import EnrichmentEnginePort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import IndicatorType

logger = structlog.get_logger(__name__)


class EnricherStrategy(ABC):
    """Strategy for a single enrichment source."""

    name: str

    @abstractmethod
    async def enrich(self, finding: Finding) -> dict[str, Any]:
        """Return enrichment data dict to merge into finding.normalized_data."""


class LocalContextEnricher(EnricherStrategy):
    """Always-on local enrichment — no external I/O."""

    name = "local_context"

    async def enrich(self, finding: Finding) -> dict[str, Any]:
        ioc_summary: dict[str, int] = {}
        for ind in finding.indicators:
            ioc_summary[ind.type.value] = ioc_summary.get(ind.type.value, 0) + 1

        has_pii = any(
            i.type in {IndicatorType.CPF, IndicatorType.CNPJ, IndicatorType.EMAIL, IndicatorType.CARD}
            for i in finding.indicators
        )
        has_infra = any(
            i.type in {IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.ASN, IndicatorType.URL}
            for i in finding.indicators
        )
        return {
            "enrichment": {
                "ioc_summary": ioc_summary,
                "has_pii": has_pii,
                "has_infrastructure": has_infra,
                "tag_count": len(finding.tags),
                "detection_hits": sum(1 for d in finding.detections if d.matched),
                "enricher": self.name,
            }
        }


class TagInferenceEnricher(EnricherStrategy):
    """Infer additional tags from category and IOC types."""

    name = "tag_inference"

    async def enrich(self, finding: Finding) -> dict[str, Any]:
        if finding.category.value not in {t.name for t in finding.tags}:
            finding.add_tag(finding.category.value)
        for ind in finding.indicators:
            tag = f"ioc:{ind.type.value}"
            if tag not in {t.name for t in finding.tags}:
                finding.add_tag(tag)
        if any(d.matched and d.rule_type == "threat_actor_match" for d in finding.detections):
            finding.add_tag("threat_actor_related")
        return {"enrichment_tags": [t.name for t in finding.tags]}


class EnrichmentEngine(EnrichmentEnginePort):
    """Orchestrates enricher strategies (Chain / Strategy)."""

    def __init__(self, enrichers: list[EnricherStrategy] | None = None) -> None:
        self._enrichers: list[EnricherStrategy] = enrichers or [
            LocalContextEnricher(),
            TagInferenceEnricher(),
        ]

    def register(self, enricher: EnricherStrategy) -> None:
        self._enrichers.append(enricher)

    async def enrich(self, finding: Finding) -> Finding:
        for enricher in self._enrichers:
            try:
                data = await enricher.enrich(finding)
                if data:
                    finding.enrich(data)
            except Exception as exc:
                logger.warning(
                    "enrichment.failed",
                    enricher=enricher.name,
                    error=str(exc),
                    finding_id=str(finding.id),
                )
        return finding


__all__ = [
    "EnricherStrategy",
    "LocalContextEnricher",
    "TagInferenceEnricher",
    "EnrichmentEngine",
]
