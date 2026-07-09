"""Concrete pipeline stages.

Responsibility
--------------
Each class adapts one collaborator (connector or engine) to the
:class:`PipelineStage` port. Stages communicate *only* through the shared
:class:`PipelineContext`; none references another stage, guaranteeing the
"cada etapa totalmente desacoplada" requirement.

The connector for the run is read from ``context.state['connector']`` (injected
by :class:`RunCollectionService`), which lets the connector-aware stages stay
generic and reusable across every connector.
"""

from __future__ import annotations

from threat_hunting.core.application.ports.event_bus import EventBus
from threat_hunting.core.application.ports.pipeline import PipelineContext
from threat_hunting.core.application.ports.repository import UnitOfWork
from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.enums import Severity
from threat_hunting.core.domain.events.finding_events import (
    FindingCollected,
    FindingPersisted,
    FindingScored,
    HighSeverityFindingDetected,
)
from threat_hunting.infrastructure.correlation.engine import CorrelationEngine
from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.extractors.indicator_extractor import IndicatorExtractor
from threat_hunting.infrastructure.normalizers.finding_normalizer import FindingNormalizer
from threat_hunting.infrastructure.scoring.engine import ScoringEngine


def _connector(context: PipelineContext):
    """Return the connector bound to this run (raises if missing)."""
    connector = context.state.get("connector")
    if connector is None:
        raise RuntimeError("no connector bound to pipeline context")
    return connector


class CollectStage:
    """Stage 1 — Connector: connect and collect raw items."""

    name = "collect"

    def process(self, context: PipelineContext) -> PipelineContext:
        connector = _connector(context)
        connector.connect()
        for item in connector.collect():
            context.raw_items.append(item)
            context.bump("collected")
        return context


class ParseStage:
    """Stage 2 — Parser: turn raw items into canonical findings."""

    name = "parse"

    def __init__(self, event_bus: EventBus | None = None) -> None:
        self._bus = event_bus

    def process(self, context: PipelineContext) -> PipelineContext:
        connector = _connector(context)
        for item in context.raw_items:
            finding = connector.parse(item)
            finding.metadata.setdefault("source_type", connector.meta.source.value)
            context.findings.append(finding)
            context.bump("parsed")
            if self._bus is not None:
                self._bus.publish(FindingCollected(finding=finding, run_id=context.run_id))
        return context


class ExtractStage:
    """Stage 3 — Extractor: extract IOCs from finding text into indicators."""

    name = "extract"

    def __init__(self, extractor: IndicatorExtractor | None = None) -> None:
        self._extractor = extractor or IndicatorExtractor()

    def process(self, context: PipelineContext) -> PipelineContext:
        for finding in context.findings:
            text = f"{finding.title}\n{finding.description}"
            for indicator in self._extractor.extract(text):
                finding.add_indicator(indicator)
            context.bump("indicators", float(len(finding.indicators)))
        return context


class NormalizeStage:
    """Stage 4 — Normalizer: canonicalise findings (connector + global)."""

    name = "normalize"

    def __init__(self, normalizer: FindingNormalizer | None = None) -> None:
        self._normalizer = normalizer or FindingNormalizer()

    def process(self, context: PipelineContext) -> PipelineContext:
        connector = _connector(context)
        normalized: list[Finding] = []
        for finding in context.findings:
            finding = connector.normalize(finding)
            finding = self._normalizer.normalize(finding)
            normalized.append(finding)
        context.findings = normalized
        return context


class DetectionStage:
    """Stage 5 — Detection: run detection rules against each finding."""

    name = "detection"

    def __init__(self, engine: DetectionEngine) -> None:
        self._engine = engine

    def process(self, context: PipelineContext) -> PipelineContext:
        for finding in context.findings:
            matches = self._engine.evaluate(finding)
            context.bump("detections", float(len(matches)))
        return context


class ScoringStage:
    """Stage 6 — Scoring: compute an explainable score per finding."""

    name = "scoring"

    def __init__(self, engine: ScoringEngine, event_bus: EventBus | None = None) -> None:
        self._engine = engine
        self._bus = event_bus

    def process(self, context: PipelineContext) -> PipelineContext:
        for finding in context.findings:
            self._engine.score(finding)
            if self._bus is not None:
                self._bus.publish(FindingScored(finding=finding, run_id=context.run_id))
        return context


class CorrelationStage:
    """Stage 7 — Correlation: link findings and form campaigns."""

    name = "correlation"

    def __init__(self, engine: CorrelationEngine | None = None) -> None:
        self._engine = engine or CorrelationEngine()

    def process(self, context: PipelineContext) -> PipelineContext:
        campaigns = self._engine.correlate(context.findings)
        context.state["campaigns"] = campaigns
        context.bump("campaigns", float(len(campaigns)))
        return context


class DeduplicationStage:
    """Stage 8 — Deduplication: collapse duplicate findings."""

    name = "deduplication"

    def __init__(self, engine: DeduplicationEngine | None = None) -> None:
        self._engine = engine or DeduplicationEngine()

    def process(self, context: PipelineContext) -> PipelineContext:
        unique, removed = self._engine.deduplicate(context.findings)
        context.findings = unique
        context.stats["duplicates_removed"] = context.stats.get("duplicates_removed", 0) + removed
        return context


class EnrichmentStage:
    """Stage 9 — Enrichment: augment findings via providers."""

    name = "enrichment"

    def __init__(self, engine: EnrichmentEngine) -> None:
        self._engine = engine

    def process(self, context: PipelineContext) -> PipelineContext:
        for finding in context.findings:
            self._engine.enrich(finding)
        return context


class PersistenceStage:
    """Stage 10 — Persistence: store findings via the unit of work."""

    name = "persistence"

    def __init__(self, uow: UnitOfWork, event_bus: EventBus | None = None) -> None:
        self._uow = uow
        self._bus = event_bus

    def process(self, context: PipelineContext) -> PipelineContext:
        with self._uow as uow:
            for finding in context.findings:
                uow.findings.add(finding)
                context.stats["persisted"] = context.stats.get("persisted", 0) + 1
                if self._bus is not None:
                    self._bus.publish(FindingPersisted(finding=finding, run_id=context.run_id))
        return context


class ExportStage:
    """Stage 11 — Export: emit high-severity events for auto-export.

    The stage does not export directly; it publishes
    :class:`HighSeverityFindingDetected` for findings above the threshold. The
    event bus (Observer) routes them to the configured auto-exporter, keeping
    the export policy fully decoupled from the pipeline.
    """

    name = "export"

    def __init__(self, threshold: float, event_bus: EventBus | None = None) -> None:
        self._threshold = threshold
        self._bus = event_bus

    def process(self, context: PipelineContext) -> PipelineContext:
        for finding in context.findings:
            if finding.score.value >= self._threshold or finding.severity in (
                Severity.HIGH,
                Severity.CRITICAL,
            ):
                context.bump("high_severity")
                if self._bus is not None:
                    self._bus.publish(
                        HighSeverityFindingDetected(
                            finding=finding,
                            threshold=self._threshold,
                            run_id=context.run_id,
                        )
                    )
        return context
