"""Pipeline orchestrator — chains all processing stages.

Flow: Connector → Parser → Extractor → Normalizer → Detection →
Scoring → Correlation → Deduplication → Enrichment → Persistence → Export
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.events import (
    ExportTriggered,
    FindingDetected,
    FindingPersisted,
    PipelineStageCompleted,
    ScoringCompleted,
)
from threat_hunting.infrastructure.connectors.base import BaseConnector

if TYPE_CHECKING:
    from threat_hunting.core.contracts.repositories import IFindingRepository, IScoreProfileRepository
    from threat_hunting.core.contracts.services import (
        ICorrelationEngine,
        IDeduplicationEngine,
        IDetectionEngine,
        IEnrichmentEngine,
        IEventBus,
        IExporter,
        IExtractor,
        INormalizer,
        IParser,
        IScoringEngine,
        IStorageBackend,
    )

logger = structlog.get_logger(__name__)


class PipelineOrchestrator:
    """Orchestrates the full collection and processing pipeline.

    Each stage is fully decoupled and communicates via domain events.
  Uses Builder pattern for pipeline context and Command pattern for stages.
    """

    def __init__(
        self,
        parser: IParser,
        extractor: IExtractor,
        normalizer: INormalizer,
        detection_engine: IDetectionEngine,
        scoring_engine: IScoringEngine,
        correlation_engine: ICorrelationEngine,
        dedup_engine: IDeduplicationEngine,
        enrichment_engine: IEnrichmentEngine,
        storage: IStorageBackend,
        finding_repo: IFindingRepository,
        event_bus: IEventBus,
        exporters: dict[str, IExporter] | None = None,
        score_profile_repo: IScoreProfileRepository | None = None,
    ) -> None:
        self._parser = parser
        self._extractor = extractor
        self._normalizer = normalizer
        self._detection = detection_engine
        self._scoring = scoring_engine
        self._correlation = correlation_engine
        self._dedup = dedup_engine
        self._enrichment = enrichment_engine
        self._storage = storage
        self._finding_repo = finding_repo
        self._event_bus = event_bus
        self._exporters = exporters or {}
        self._score_profile_repo = score_profile_repo

    async def execute(
        self,
        connector: BaseConnector,
        keywords: list[str] | None = None,
    ) -> list[Finding]:
        """Execute full pipeline for a connector."""
        from threat_hunting.core.contracts.services import CollectionContext

        findings: list[Finding] = []
        await connector.connect()

        try:
            context = CollectionContext(
                connector_name=connector.name,
                keywords=keywords or [],
            )

            async for raw_payload in connector.collect(context):
                batch = await self._process_payload(connector, raw_payload)
                findings.extend(batch)

            findings = await self._dedup.deduplicate(findings)

            for finding in findings:
                await self._persist_and_export(finding)

        finally:
            await connector.close()

        return findings

    async def _process_payload(self, connector: BaseConnector, raw_payload) -> list[Finding]:
        """Process a single raw payload through all pipeline stages."""
        start = time.monotonic()

        # Stage 1: Parse (connector.parse or generic parser)
        parsed = connector.parse(raw_payload)
        await self._emit_stage("parser", connector.name, 1, time.monotonic() - start)

        # Stage 2: Extract
        start = time.monotonic()
        extracted = self._extractor.extract(parsed)
        await self._emit_stage("extractor", connector.name, 1, time.monotonic() - start)

        # Stage 3: Normalize
        start = time.monotonic()
        draft = self._normalizer.normalize(extracted, connector.name, connector.source_type)
        finding = draft.to_finding()
        await self._emit_stage("normalizer", connector.name, 1, time.monotonic() - start)

        # Stage 4: Detection
        start = time.monotonic()
        finding, matched_rules = await self._detection.detect(finding)
        await self._event_bus.publish(FindingDetected(finding=finding, matched_rules=matched_rules))
        await self._emit_stage("detection", connector.name, 1, time.monotonic() - start)

        # Stage 5: Scoring
        start = time.monotonic()
        finding = await self._scoring.score(finding)
        await self._event_bus.publish(
            ScoringCompleted(
                finding_id=finding.id, score=finding.score, confidence=finding.confidence
            )
        )
        await self._emit_stage("scoring", connector.name, 1, time.monotonic() - start)

        # Stage 6: Correlation
        start = time.monotonic()
        finding, _ = await self._correlation.correlate(finding)
        await self._emit_stage("correlation", connector.name, 1, time.monotonic() - start)

        # Stage 7: Enrichment
        start = time.monotonic()
        finding = await self._enrichment.enrich(finding)
        await self._emit_stage("enrichment", connector.name, 1, time.monotonic() - start)

        return [finding]

    async def _persist_and_export(self, finding: Finding) -> None:
        """Persist finding and trigger auto-export if above threshold."""
        await self._storage.save_finding(finding)
        await self._finding_repo.save(finding)
        await self._event_bus.publish(
            FindingPersisted(finding_id=finding.id, connector=finding.connector)
        )

        threshold = 70.0
        if self._score_profile_repo:
            profile = await self._score_profile_repo.get_default()
            threshold = profile.threshold_auto_export

        if finding.score >= threshold and "misp" in self._exporters:
            await self._exporters["misp"].export([finding])
            await self._event_bus.publish(
                ExportTriggered(
                    finding_id=finding.id, export_format="misp", destination="auto"
                )
            )

    async def _emit_stage(self, stage: str, connector: str, count: int, duration: float) -> None:
        await self._event_bus.publish(
            PipelineStageCompleted(
                stage=stage, connector=connector, items_processed=count, duration_seconds=duration
            )
        )
