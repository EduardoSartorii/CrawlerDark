"""
Collection Pipeline.

The pipeline orchestrates the end-to-end flow from raw data to persisted, enriched Finding.

Pipeline Stages (in order):
    1. Connector.run()      → raw Finding objects (title, source, raw_data)
    2. Detection Engine     → rule matches, score contributions, tags
    3. Scoring Engine       → final weighted risk score
    4. Correlation Engine   → inter-finding relationships
    5. Deduplication        → fingerprint + similarity check
    6. Enrichment Engine    → contextual data (domains, VIPs, actors)
    7. Persistence          → UoW → storage backend
    8. Export Trigger       → if score ≥ threshold, queue for export

Each stage is fully decoupled:
    - Stages communicate only through Finding objects
    - Stages fail gracefully (errors are logged, not propagated)
    - Each stage can be independently enabled/disabled

Design Patterns:
    - Pipeline Pattern: linear chain of processing stages
    - Strategy Pattern: each engine is a pluggable strategy
    - Observer Pattern: pipeline emits events at key milestones
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog

from ...core.domain.entities.finding import Finding
from ...core.domain.entities.keyword import Keyword
from ...core.domain.entities.rule import DetectionRule
from ...core.domain.entities.threat_actor import ThreatActor
from ..connectors.base import BaseConnector
from ..correlation.engine import CorrelationEngine
from ..detections.engine import DetectionEngine
from ..enrichment.engine import EnrichmentEngine
from ..scoring.engine import ScoringEngine, ScoringWeights

logger = structlog.get_logger(__name__)


@dataclass
class PipelineConfig:
    """Configuration for a collection pipeline instance."""

    enable_detection: bool = True
    enable_scoring: bool = True
    enable_correlation: bool = True
    enable_enrichment: bool = True
    export_threshold: float = 7.0
    max_findings_per_run: int = 500
    scoring_weights: dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineRunResult:
    """Result from a single pipeline execution."""

    run_id: str
    connector_id: str
    findings_collected: int = 0
    findings_suppressed: int = 0
    findings_processed: int = 0
    correlations_found: int = 0
    export_candidates: int = 0
    errors: list[str] = field(default_factory=list)
    stage_timings: dict[str, float] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return not self.errors


class CollectionPipeline:
    """
    Orchestrates the full threat hunting collection pipeline.

    This class fulfills the CollectionPipelinePort protocol expected
    by the RunCollectionUseCase in the application layer.
    """

    def __init__(
        self,
        connector: BaseConnector,
        detection_engine: DetectionEngine,
        scoring_engine: ScoringEngine,
        correlation_engine: CorrelationEngine,
        enrichment_engine: EnrichmentEngine,
        config: PipelineConfig | None = None,
        rules: list[DetectionRule] | None = None,
        keywords: list[Keyword] | None = None,
        threat_actors: list[ThreatActor] | None = None,
    ) -> None:
        self._connector = connector
        self._detection = detection_engine
        self._scoring = scoring_engine
        self._correlation = correlation_engine
        self._enrichment = enrichment_engine
        self._config = config or PipelineConfig()

        # Load rules and context if provided
        if rules:
            self._detection.load_rules(rules)

    async def execute(
        self,
        connector_id: str,
        dry_run: bool = False,
        limit: int | None = None,
    ) -> list[Finding]:
        """
        Execute the full pipeline for this connector.
        Returns the list of processed, enriched Findings.
        """
        run_id = str(uuid.uuid4())[:8]
        log = logger.bind(run_id=run_id, connector=connector_id)
        log.info("pipeline.execute_start")

        # ── Stage 1: Collection ──────────────────────────────────────────────
        log.info("pipeline.stage", stage="collection")
        findings = await self._connector.run(
            run_id=run_id,
            dry_run=dry_run,
            limit=limit or self._config.max_findings_per_run,
        )
        log.info("pipeline.collected", count=len(findings))

        if not findings:
            return []

        # Limit
        if len(findings) > self._config.max_findings_per_run:
            findings = findings[:self._config.max_findings_per_run]

        # ── Stage 2: Detection ───────────────────────────────────────────────
        if self._config.enable_detection:
            log.info("pipeline.stage", stage="detection", count=len(findings))
            detection_results = self._detection.evaluate_batch(findings)
            suppressed = [r for r in detection_results if r.suppressed]
            if suppressed:
                suppressed_ids = {r.finding_id for r in suppressed}
                findings = [f for f in findings if f.id not in suppressed_ids]
                log.info("pipeline.suppressed", count=len(suppressed))

        # ── Stage 3: Enrichment ──────────────────────────────────────────────
        if self._config.enable_enrichment:
            log.info("pipeline.stage", stage="enrichment", count=len(findings))
            await self._enrichment.enrich_batch(findings)

        # ── Stage 4: Scoring ─────────────────────────────────────────────────
        if self._config.enable_scoring:
            log.info("pipeline.stage", stage="scoring", count=len(findings))
            for finding in findings:
                enrichment = finding.normalized_data.get("enrichment", {})
                matched_keywords = [
                    m["value"]
                    for m in enrichment.get("watchlist_matches", [])
                ]
                matched_vips = [
                    m["value"]
                    for m in enrichment.get("watchlist_matches", [])
                    if m.get("category") in ("vip", "executive")
                ]
                matched_brands = [
                    m["value"]
                    for m in enrichment.get("watchlist_matches", [])
                    if m.get("category") == "brand"
                ]
                matched_actors = enrichment.get("matched_actors", [])
                matched_actor = matched_actors[0] if matched_actors else None

                score, breakdown = self._scoring.score(
                    finding,
                    matched_keywords=matched_keywords,
                    matched_vips=matched_vips,
                    matched_brands=matched_brands,
                    matched_threat_actor=matched_actor,
                )
                finding.apply_score(score)

        # ── Stage 5: Correlation ─────────────────────────────────────────────
        if self._config.enable_correlation and len(findings) >= 2:
            log.info("pipeline.stage", stage="correlation", count=len(findings))
            corr_result = self._correlation.correlate(findings)
            log.info(
                "pipeline.correlated",
                relationships=corr_result.relationships_created,
            )

        # Identify export candidates
        export_candidates = [
            f for f in findings
            if f.should_auto_export
        ]
        log.info(
            "pipeline.complete",
            findings=len(findings),
            export_candidates=len(export_candidates),
        )
        return findings
