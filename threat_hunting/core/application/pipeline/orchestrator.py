"""Pipeline Orchestrator — Chain of Responsibility + Strategy.

Responsibility
--------------
Execute the mandatory collection pipeline in exact order:

  Connector → Parser → Extractor → Normalizer → Detection → Scoring →
  Correlation → Deduplication → Enrichment → Persistence → Export(events)

Each stage is fully decoupled via ports injected by DI.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from threat_hunting.core.application.ports import (
    ConnectorPort,
    CorrelationEnginePort,
    DeduplicationEnginePort,
    DetectionEnginePort,
    EnrichmentEnginePort,
    EventBusPort,
    ExtractorPort,
    MetricsPort,
    NormalizerPort,
    ParserPort,
    ScoringEnginePort,
    UnitOfWorkPort,
)
from threat_hunting.core.domain.entities import Finding, HuntJob
from threat_hunting.core.domain.events import (
    FindingCorrelated,
    FindingCreated,
    FindingDeduplicated,
    FindingEnriched,
    FindingPersisted,
    FindingScored,
    HuntJobCompleted,
    HuntJobFailed,
    HuntJobStarted,
    ScoreThresholdExceeded,
)
from threat_hunting.core.domain.value_objects import utc_now

logger = structlog.get_logger(__name__)


class PipelineOrchestrator:
    """Orchestrates the full hunt pipeline for a single connector run.

    Architectural notes
    -------------------
    - Stages are Strategy objects; order is fixed by business rule.
    - Domain events are published after each significant stage.
    - Persistence uses Unit of Work for atomicity.
    - Auto-export is triggered via ScoreThresholdExceeded event (Observer).
    """

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
        metrics: MetricsPort,
        score_export_threshold: float = 75.0,
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
        self._event_bus = event_bus
        self._metrics = metrics
        self._score_export_threshold = score_export_threshold

    async def run(
        self,
        connector: ConnectorPort,
        *,
        dry_run: bool = False,
        export_on_threshold: bool = True,
    ) -> HuntJob:
        """Execute full pipeline for the given connector."""
        job = HuntJob(connector=connector.name)
        job.start()
        await self._event_bus.publish(
            HuntJobStarted(
                aggregate_id=job.id,
                payload={"connector": connector.name},
            )
        )
        log = logger.bind(job_id=job.id, connector=connector.name)
        log.info("hunt_job.started")
        started = time.perf_counter()

        try:
            await connector.connect()
            async for raw in connector.collect():
                try:
                    finding = await self._process_document(
                        connector, raw, dry_run=dry_run, export_on_threshold=export_on_threshold
                    )
                    if finding is not None:
                        job.record_finding(is_duplicate=finding.is_duplicate)
                        self._metrics.incr(
                            "findings_total",
                            labels={"connector": connector.name, "duplicate": str(finding.is_duplicate)},
                        )
                except Exception as exc:
                    job.record_error()
                    log.exception("pipeline.document_error", error=str(exc))
                    self._metrics.incr(
                        "pipeline_errors_total",
                        labels={"connector": connector.name},
                    )

            job.complete(partial=job.errors_count > 0)
            elapsed = time.perf_counter() - started
            job.stats = {
                "elapsed_seconds": round(elapsed, 3),
                "findings": job.findings_count,
                "duplicates": job.duplicates_count,
                "errors": job.errors_count,
                "finished_at": utc_now().isoformat(),
            }
            self._metrics.observe(
                "hunt_job_duration_seconds",
                elapsed,
                labels={"connector": connector.name},
            )
            await self._persist_job(job, dry_run=dry_run)
            await self._event_bus.publish(
                HuntJobCompleted(
                    aggregate_id=job.id,
                    payload=job.stats,
                )
            )
            log.info("hunt_job.completed", **job.stats)
            return job

        except Exception as exc:
            job.fail(str(exc))
            await self._persist_job(job, dry_run=dry_run)
            await self._event_bus.publish(
                HuntJobFailed(
                    aggregate_id=job.id,
                    payload={"error": str(exc), "connector": connector.name},
                )
            )
            log.exception("hunt_job.failed", error=str(exc))
            raise
        finally:
            await connector.close()

    async def _process_document(
        self,
        connector: ConnectorPort,
        raw: Any,
        *,
        dry_run: bool,
        export_on_threshold: bool,
    ) -> Finding | None:
        """Run a single document through all pipeline stages."""
        # 1-3: Prefer connector's own parse/normalize when available;
        # fall back to shared parser/extractor/normalizer ports.
        parsed = await connector.parse(raw)
        extracted = await self._extractor.extract(parsed)
        # Merge extracted into parsed for connector normalize awareness
        parsed_with_entities = {**parsed, "_extracted": extracted}
        finding = await connector.normalize(parsed_with_entities)

        # Also allow shared normalizer enrichment of fields if needed
        if not finding.indicators and extracted.get("indicators"):
            from threat_hunting.core.domain.enums import IndicatorType
            from threat_hunting.core.domain.value_objects import Indicator

            for item in extracted["indicators"]:
                finding.add_indicator(
                    Indicator(
                        type=IndicatorType(item["type"]),
                        value=item["value"],
                        context=item.get("context"),
                    )
                )

        await self._event_bus.publish(
            FindingCreated(
                aggregate_id=str(finding.id),
                payload={"connector": connector.name, "title": finding.title},
            )
        )

        # 4. Detection
        matches = await self._detection.detect(finding)
        for match in matches:
            finding.apply_detection(match)

        # 5. Scoring
        finding = await self._scoring.score(finding)
        await self._event_bus.publish(
            FindingScored(
                aggregate_id=str(finding.id),
                payload={"score": float(finding.score)},
            )
        )

        # 6. Correlation
        finding = await self._correlation.correlate(finding)
        await self._event_bus.publish(
            FindingCorrelated(
                aggregate_id=str(finding.id),
                payload={"relationships": len(finding.relationships)},
            )
        )

        # 7. Deduplication
        finding = await self._deduplication.deduplicate(finding)
        if finding.is_duplicate:
            await self._event_bus.publish(
                FindingDeduplicated(
                    aggregate_id=str(finding.id),
                    payload={"duplicate_of": finding.duplicate_of},
                )
            )

        # 8. Enrichment
        finding = await self._enrichment.enrich(finding)
        await self._event_bus.publish(
            FindingEnriched(
                aggregate_id=str(finding.id),
                payload={"keys": list(finding.normalized_data.keys())},
            )
        )

        # 9. Persistence
        if not dry_run and not finding.is_duplicate:
            async with self._uow:
                await self._uow.findings.save(finding)
                await self._uow.commit()
            await self._event_bus.publish(
                FindingPersisted(
                    aggregate_id=str(finding.id),
                    payload={"connector": connector.name},
                )
            )

        # 10. Auto-export trigger (Observer via event)
        if (
            export_on_threshold
            and not finding.is_duplicate
            and finding.score.exceeds(self._score_export_threshold)
        ):
            await self._event_bus.publish(
                ScoreThresholdExceeded(
                    aggregate_id=str(finding.id),
                    payload={
                        "score": float(finding.score),
                        "threshold": self._score_export_threshold,
                        "finding": finding.to_export_dict(),
                    },
                )
            )

        for event in finding.collect_events():
            await self._event_bus.publish(event)

        return finding

    async def _persist_job(self, job: HuntJob, *, dry_run: bool) -> None:
        if dry_run:
            return
        async with self._uow:
            await self._uow.hunt_jobs.save(job)
            await self._uow.commit()


__all__ = ["PipelineOrchestrator"]
