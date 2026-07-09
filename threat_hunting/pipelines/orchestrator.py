"""Pipeline orchestration for threat hunting findings lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime
from time import perf_counter
from typing import Any

from threat_hunting.application.builders import FindingBuilder
from threat_hunting.core.contracts import (
    ConnectorPort,
    CorrelationEnginePort,
    DeduplicationEnginePort,
    DetectionEnginePort,
    EnrichmentEnginePort,
    EventBusPort,
    ExporterPort,
    ExtractorPort,
    NormalizerPort,
    ParserPort,
    ScoringEnginePort,
    StageContext,
    UnitOfWorkPort,
)
from threat_hunting.core.events import (
    FindingsExported,
    FindingsPersisted,
    PipelineStageCompleted,
    PipelineStageFailed,
)
from threat_hunting.domain.entities import Finding, ScoringPolicy


class HuntingPipeline:
    """Runs complete threat hunting pipeline with decoupled stages."""

    def __init__(
        self,
        *,
        parser: ParserPort,
        extractor: ExtractorPort,
        normalizer: NormalizerPort,
        detection_engine: DetectionEnginePort,
        scoring_engine: ScoringEnginePort,
        correlation_engine: CorrelationEnginePort,
        dedup_engine: DeduplicationEnginePort,
        enrichment_engine: EnrichmentEnginePort,
        uow: UnitOfWorkPort,
        exporters: list[ExporterPort],
        misp_exporter: ExporterPort | None,
        scoring_policy: ScoringPolicy,
        event_bus: EventBusPort,
    ) -> None:
        self._parser = parser
        self._extractor = extractor
        self._normalizer = normalizer
        self._detection_engine = detection_engine
        self._scoring_engine = scoring_engine
        self._correlation_engine = correlation_engine
        self._dedup_engine = dedup_engine
        self._enrichment_engine = enrichment_engine
        self._uow = uow
        self._exporters = exporters
        self._misp_exporter = misp_exporter
        self._scoring_policy = scoring_policy
        self._event_bus = event_bus

    def run(self, *, connector: ConnectorPort, context: StageContext) -> list[Finding]:
        """Execute full processing lifecycle for one connector."""
        connector.connect()
        try:
            raw_items = self._run_stage("connector_collect", lambda: connector.collect(context), context)
            connector_parsed = self._run_stage(
                "connector_parse",
                lambda: connector.parse(raw_items, context),
                context,
            )
            parsed = self._run_stage("parser", lambda: self._parser.run(connector_parsed, context), context)
            extracted = self._run_stage("extractor", lambda: self._extractor.run(parsed, context), context)
            connector_normalized = self._run_stage(
                "connector_normalize",
                lambda: connector.normalize(extracted, context),
                context,
            )
            normalized = self._run_stage(
                "normalizer",
                lambda: self._normalizer.run(connector_normalized, context),
                context,
            )
            detected = self._run_stage(
                "detection",
                lambda: self._detection_engine.run(normalized, context),
                context,
            )
            scored = self._run_stage("scoring", lambda: self._scoring_engine.run(detected, context), context)
            correlated = self._run_stage(
                "correlation",
                lambda: self._correlation_engine.run(scored, context),
                context,
            )
            deduplicated = self._run_stage(
                "deduplication",
                lambda: self._dedup_engine.run(correlated, context),
                context,
            )
            enriched = self._run_stage(
                "enrichment",
                lambda: self._enrichment_engine.run(deduplicated, context),
                context,
            )
            findings = self._build_findings(enriched)
            self._persist(findings, context)
            self._export(findings, context)
            return findings
        finally:
            connector.close()

    def _run_stage(self, stage_name: str, operation: Any, context: StageContext) -> Any:
        started = perf_counter()
        try:
            result = operation()
            duration_ms = (perf_counter() - started) * 1000
            self._event_bus.publish(
                PipelineStageCompleted(
                    event_type="pipeline_stage_completed",
                    payload={
                        "stage": stage_name,
                        "duration_ms": duration_ms,
                        "connector": context.connector_name,
                        "findings_count": len(result) if isinstance(result, list) else 0,
                    },
                )
            )
            return result
        except Exception as exc:
            duration_ms = (perf_counter() - started) * 1000
            self._event_bus.publish(
                PipelineStageFailed(
                    event_type="pipeline_stage_failed",
                    payload={
                        "stage": stage_name,
                        "duration_ms": duration_ms,
                        "connector": context.connector_name,
                        "error": str(exc),
                    },
                )
            )
            raise

    def _build_findings(self, items: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        for item in items:
            builder = FindingBuilder()
            finding = (
                builder.with_base(
                    title=str(item.get("title", "")),
                    description=str(item.get("description", "")),
                    source=str(item.get("source", "")),
                    connector=str(item.get("connector", "")),
                    category=str(item.get("category", "")),
                )
                .with_severity(str(item.get("severity", "info")))
                .with_scores(score=float(item.get("score", 0.0)), confidence=float(item.get("confidence", 0.0)))
                .with_payload(
                    raw_data=dict(item.get("raw_data", {})),
                    normalized_data=dict(item.get("normalized_data", {})),
                    metadata=dict(item.get("metadata", {})),
                )
                .with_tags(list(item.get("tags", [])))
                .build()
            )
            finding.artifacts = list(item.get("artifacts", []))
            finding.indicators = list(item.get("indicators", []))
            finding.relationships = list(item.get("relationships", []))
            finding.timeline = list(item.get("timeline", []))
            finding.updated_at = datetime.now(UTC)
            findings.append(finding)
        return findings

    def _persist(self, findings: list[Finding], context: StageContext) -> None:
        if not findings:
            return
        with self._uow:
            self._uow.findings.add_many(findings)
            self._uow.commit()
        self._event_bus.publish(
            FindingsPersisted(
                event_type="findings_persisted",
                payload={"connector": context.connector_name, "findings_count": len(findings)},
            )
        )

    def _export(self, findings: list[Finding], context: StageContext) -> None:
        if not findings:
            return
        for exporter in self._exporters:
            exporter.export(findings, context)
        if self._misp_exporter:
            high_priority = [
                finding
                for finding in findings
                if finding.score >= self._scoring_policy.threshold_misp_auto_export
            ]
            if high_priority:
                self._misp_exporter.export(high_priority, context)
        self._event_bus.publish(
            FindingsExported(
                event_type="findings_exported",
                payload={"connector": context.connector_name, "findings_count": len(findings)},
            )
        )
