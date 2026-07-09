"""The collection pipeline orchestrator (Chain of Responsibility).

Responsibility
--------------
Run the fixed, fully-decoupled pipeline for a connector::

    Connector -> Parser -> Extractor -> Normalizer -> Detection -> Scoring
    -> Correlation -> Deduplication -> Enrichment -> Persistence -> Export

Each stage is reached through a port, so stages are independently testable and
replaceable. The pipeline owns *ordering and orchestration only*; it contains no
source-specific or storage-specific logic.

Business rules
--------------
* A finding dropped by detection (no rule matched) does not proceed.
* A finding flagged as duplicate is not persisted again but is still audited.
* Every milestone publishes a domain event on the bus and appends a timeline
  entry to the finding.
* Auto-export to a threshold destination (e.g. MISP) fires when the score meets
  the configured threshold.
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.application.dto import PipelineResult
from threat_hunting.core.application.ports.connector import ConnectorPort
from threat_hunting.core.application.ports.event_bus import EventBusPort
from threat_hunting.core.application.ports.exporter import ExporterPort
from threat_hunting.core.application.ports.pipeline_stages import (
    CorrelationEnginePort,
    DeduplicationEnginePort,
    DetectionEnginePort,
    EnrichmentEnginePort,
    ExtractorPort,
    NormalizerPort,
    ParserPort,
    ScoringEnginePort,
)
from threat_hunting.core.application.ports.repository import UnitOfWorkPort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.events import (
    FindingCollected,
    FindingCorrelated,
    FindingDeduplicated,
    FindingDetected,
    FindingEnriched,
    FindingExported,
    FindingPersisted,
    FindingScored,
)


class Pipeline:
    """Orchestrates the decoupled collection pipeline for one connector run."""

    def __init__(
        self,
        *,
        parser: ParserPort,
        extractor: ExtractorPort,
        normalizer: NormalizerPort,
        detection: DetectionEnginePort,
        scoring: ScoringEnginePort,
        correlation: CorrelationEnginePort,
        deduplication: DeduplicationEnginePort,
        enrichment: EnrichmentEnginePort,
        uow: UnitOfWorkPort,
        event_bus: EventBusPort,
        exporters: Sequence[ExporterPort] | None = None,
        auto_export_threshold: float = 80.0,
    ) -> None:
        self._parser = parser
        self._extractor = extractor
        self._normalizer = normalizer
        self._detection = detection
        self._scoring = scoring
        self._correlation = correlation
        self._deduplication = deduplication
        self._enrichment = enrichment
        self._uow = uow
        self._bus = event_bus
        self._exporters = list(exporters or [])
        self._auto_export_threshold = auto_export_threshold

    async def run(self, connector: ConnectorPort) -> PipelineResult:
        """Execute the full pipeline for one connector and return a summary."""
        result = PipelineResult(connector=connector.name)
        context: list[Finding] = list(self._uow.findings.recent())

        try:
            await connector.connect()
            records = await connector.collect()
        except Exception as exc:  # noqa: BLE001 - connectors may fail arbitrarily
            result.errors.append(f"collect: {exc}")
            await self._safe_close(connector)
            return result

        for record in records:
            try:
                finding = self._process_record(connector, record, context)
            except Exception as exc:  # noqa: BLE001 - isolate per-record failures
                result.errors.append(f"process: {exc}")
                continue

            result.collected += 1
            if finding is None:
                continue

            if self._deduplication.is_duplicate(finding, context):
                finding.record("deduplication", "flagged as duplicate")
                self._bus.publish(FindingDeduplicated(finding=finding))
                result.duplicates += 1
                continue

            self._deduplication.register(finding)
            self._persist(finding)
            context.append(finding)
            result.persisted += 1
            result.findings.append(finding)

            exported = self._auto_export(finding)
            result.exported += exported

        await self._safe_close(connector)
        return result

    # -- internal stages ----------------------------------------------------

    def _process_record(
        self, connector: ConnectorPort, record, context: Sequence[Finding]
    ) -> Finding | None:
        """Run the non-persistence stages for a single raw record."""
        parsed = self._parser.parse(connector.parse(record))
        finding = connector.normalize(parsed)
        finding = self._normalizer.normalize(finding, parsed)

        for indicator in self._extractor.extract(parsed):
            finding.add_indicator(indicator)

        finding.record("collector", f"collected from {finding.source}")
        self._bus.publish(FindingCollected(finding=finding))

        finding = self._detection.detect(finding)
        if not self._detection.matches(finding):
            return None
        self._bus.publish(FindingDetected(finding=finding))

        finding = self._scoring.score(finding)
        self._bus.publish(FindingScored(finding=finding))

        finding = self._correlation.correlate(finding, context)
        self._bus.publish(FindingCorrelated(finding=finding))

        finding = self._enrichment.enrich(finding)
        self._bus.publish(FindingEnriched(finding=finding))
        return finding

    def _persist(self, finding: Finding) -> None:
        """Persist a finding atomically through the Unit of Work."""
        with self._uow:
            self._uow.findings.add(finding)
        finding.record("persistence", "stored")
        self._bus.publish(FindingPersisted(finding=finding))

    def _auto_export(self, finding: Finding) -> int:
        """Auto-export high-score findings to threshold-enabled exporters."""
        if finding.score < self._auto_export_threshold:
            return 0
        exported = 0
        for exporter in self._exporters:
            if exporter.supports_auto_export():
                exported += exporter.export_one(finding)
        if exported:
            finding.record(
                "export", f"auto-exported (score {finding.score:.1f})"
            )
            self._bus.publish(FindingExported(finding=finding))
        return exported

    @staticmethod
    async def _safe_close(connector: ConnectorPort) -> None:
        """Close a connector without masking earlier failures."""
        try:
            await connector.close()
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass
