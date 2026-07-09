"""Application use cases / command handlers.

Responsibility
--------------
Translate Commands into orchestrated domain operations.
CLI and Scheduler depend only on these handlers (Command Pattern).
"""

from __future__ import annotations

from typing import Any

import structlog

from threat_hunting.core.application.commands import (
    DisableConnectorCommand,
    EnableConnectorCommand,
    ExportFindingsCommand,
    HealthCheckCommand,
    RunHuntCommand,
    ScoreTestCommand,
)
from threat_hunting.core.application.pipeline.orchestrator import PipelineOrchestrator
from threat_hunting.core.application.ports import (
    AuditPort,
    ConnectorFactoryPort,
    EventBusPort,
    ExporterFactoryPort,
    HealthCheckPort,
    ScoringEnginePort,
    UnitOfWorkPort,
)
from threat_hunting.core.domain.entities import Finding, HuntJob
from threat_hunting.core.domain.enums import FindingCategory, Severity
from threat_hunting.core.domain.events import AuditRecorded, ExportRequested
from threat_hunting.core.domain.services import FindingBuilder
from threat_hunting.core.domain.value_objects import DetectionMatch

logger = structlog.get_logger(__name__)

# Connector group aliases for `hunt run social|darkweb|…`
CONNECTOR_GROUPS: dict[str, list[str]] = {
    "social": ["reddit", "facebook", "instagram", "x", "telegram", "discord"],
    "code": ["github", "gitlab"],
    "web": ["rss", "blogs", "sites", "news", "paste"],
    "darkweb": ["darkweb", "deepweb", "forums", "marketplaces"],
    "feeds": ["feeds", "apis"],
    "threat_intel": [
        "misp",
        "opencti",
        "threatfox",
        "greynoise",
        "virustotal",
        "abuseipdb",
        "shodan",
        "censys",
        "urlhaus",
        "alienvault_otx",
    ],
}


class RunHuntHandler:
    """Handle RunHuntCommand — resolve connectors and run pipeline."""

    def __init__(
        self,
        *,
        connector_factory: ConnectorFactoryPort,
        pipeline: PipelineOrchestrator,
        audit: AuditPort,
        event_bus: EventBusPort,
    ) -> None:
        self._factory = connector_factory
        self._pipeline = pipeline
        self._audit = audit
        self._event_bus = event_bus

    async def handle(self, command: RunHuntCommand) -> list[HuntJob]:
        names = self._resolve_connectors(command.connector)
        jobs: list[HuntJob] = []
        for name in names:
            log = logger.bind(connector=name)
            log.info("run_hunt.starting")
            try:
                connector = self._factory.create(name, **command.options)
                job = await self._pipeline.run(
                    connector,
                    dry_run=command.dry_run,
                    export_on_threshold=command.export_on_threshold,
                )
                jobs.append(job)
                await self._audit.record(
                    "hunt.run",
                    details={"connector": name, "job_id": job.id, "stats": job.stats},
                )
            except Exception as exc:
                log.exception("run_hunt.failed", error=str(exc))
                await self._audit.record(
                    "hunt.run.failed",
                    details={"connector": name, "error": str(exc)},
                )
                raise
        return jobs

    def _resolve_connectors(self, target: str) -> list[str]:
        target = target.lower().strip()
        if target == "all":
            return list(self._factory.list_available())
        if target in CONNECTOR_GROUPS:
            available = set(self._factory.list_available())
            return [n for n in CONNECTOR_GROUPS[target] if n in available]
        # Direct name or factory group
        by_group = list(self._factory.list_by_group(target))
        if by_group:
            return list(by_group)
        return [target]


class ConnectorLifecycleHandler:
    """Enable / disable connectors via governance repository."""

    def __init__(self, *, uow: UnitOfWorkPort, audit: AuditPort) -> None:
        self._uow = uow
        self._audit = audit

    async def enable(self, command: EnableConnectorCommand) -> dict[str, Any]:
        async with self._uow:
            config = await self._uow.connectors.get_by_name(command.name)
            if config is None:
                from threat_hunting.core.domain.entities import ConnectorConfig

                config = ConnectorConfig(name=command.name, enabled=True)
            else:
                config.enable()
            await self._uow.connectors.save(config)
            await self._uow.commit()
        await self._audit.record("connector.enable", details={"name": command.name})
        return {"name": command.name, "enabled": True}

    async def disable(self, command: DisableConnectorCommand) -> dict[str, Any]:
        async with self._uow:
            config = await self._uow.connectors.get_by_name(command.name)
            if config is None:
                from threat_hunting.core.domain.entities import ConnectorConfig

                config = ConnectorConfig(name=command.name, enabled=False)
            else:
                config.disable()
            await self._uow.connectors.save(config)
            await self._uow.commit()
        await self._audit.record("connector.disable", details={"name": command.name})
        return {"name": command.name, "enabled": False}


class ExportFindingsHandler:
    """Export findings via ExporterFactory (Strategy + Factory)."""

    def __init__(
        self,
        *,
        exporter_factory: ExporterFactoryPort,
        uow: UnitOfWorkPort,
        event_bus: EventBusPort,
        audit: AuditPort,
    ) -> None:
        self._factory = exporter_factory
        self._uow = uow
        self._event_bus = event_bus
        self._audit = audit

    async def handle(self, command: ExportFindingsCommand) -> dict[str, Any]:
        exporter = self._factory.create(command.format)
        async with self._uow:
            if command.finding_ids:
                findings: list[Finding] = []
                for fid in command.finding_ids:
                    f = await self._uow.findings.get_by_id(fid)
                    if f:
                        findings.append(f)
            else:
                findings = list(await self._uow.findings.list_recent(limit=command.limit))

        await self._event_bus.publish(
            ExportRequested(
                aggregate_id=command.format,
                payload={"count": len(findings), "format": command.format},
            )
        )
        result = await exporter.export(findings, **command.options)
        await self._audit.record(
            "export.run",
            details={"format": command.format, "count": len(findings)},
        )
        return result


class ScoreTestHandler:
    """Test scoring engine against a synthetic Finding."""

    def __init__(self, *, scoring: ScoringEnginePort, detection: Any) -> None:
        self._scoring = scoring
        self._detection = detection

    async def handle(self, command: ScoreTestCommand) -> dict[str, Any]:
        title = command.payload.get("title") or command.text[:80] or "Score Test Finding"
        description = command.payload.get("description") or command.text
        finding = (
            FindingBuilder()
            .with_title(title)
            .with_description(description)
            .with_source("score_test")
            .with_connector("score_test")
            .with_category(FindingCategory.THREAT_HUNTING)
            .with_severity(Severity.INFORMATIONAL)
            .with_raw_data(command.payload or {"text": command.text})
            .build()
        )
        if self._detection is not None:
            matches: list[DetectionMatch] = await self._detection.detect(finding)
            for m in matches:
                finding.apply_detection(m)
        finding = await self._scoring.score(finding)
        return {
            "score": float(finding.score),
            "confidence": float(finding.confidence),
            "severity": finding.severity.value,
            "detections": [m.model_dump() for m in finding.detections],
            "tags": [t.name for t in finding.tags],
        }


class HealthCheckHandler:
    def __init__(self, *, health: HealthCheckPort) -> None:
        self._health = health

    async def handle(self, command: HealthCheckCommand) -> dict[str, Any]:
        statuses = await self._health.check_all()
        if command.component:
            statuses = [s for s in statuses if s.component == command.component]
        overall = await self._health.overall()
        return {
            "overall": overall.value,
            "components": [s.model_dump(mode="json") for s in statuses],
        }


__all__ = [
    "CONNECTOR_GROUPS",
    "RunHuntHandler",
    "ConnectorLifecycleHandler",
    "ExportFindingsHandler",
    "ScoreTestHandler",
    "HealthCheckHandler",
]
