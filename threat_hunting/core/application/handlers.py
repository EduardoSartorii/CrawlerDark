"""Application use case handlers.

Handlers coordinate domain services and infrastructure ports
to fulfill commands from CLI, scheduler, or API.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import structlog

from threat_hunting.core.application.commands import (
    DisableConnectorCommand,
    EnableConnectorCommand,
    ExportCommand,
    RunAllConnectorsCommand,
    RunConnectorCommand,
    RunConnectorGroupCommand,
    ScoreTestCommand,
)
from threat_hunting.core.domain.entities import AuditLog, Finding
from threat_hunting.core.domain.enums import FindingCategory, Severity, SourceType
from threat_hunting.core.domain.events import ConnectorExecuted

if TYPE_CHECKING:
    from threat_hunting.core.contracts.repositories import IConnectorConfigRepository
    from threat_hunting.core.contracts.services import IEventBus, IExporter, IScoringEngine
    from threat_hunting.infrastructure.pipelines.orchestrator import PipelineOrchestrator
    from threat_hunting.infrastructure.plugins.discovery import ConnectorRegistry

logger = structlog.get_logger(__name__)

CONNECTOR_GROUPS: dict[str, list[str]] = {
    "social": ["reddit", "facebook", "instagram", "x", "telegram", "discord"],
    "darkweb": ["darkweb", "forums", "marketplaces"],
    "code": ["github", "gitlab"],
    "feeds": ["rss", "news", "blogs"],
    "threat_intel": ["misp", "threatfox", "urlhaus", "alienvault_otx"],
    "enrichment": ["virustotal", "greynoise", "abuseipdb", "shodan", "censys"],
}


class RunConnectorHandler:
    """Handler for single connector execution."""

    def __init__(
        self,
        registry: ConnectorRegistry,
        pipeline: PipelineOrchestrator,
        config_repo: IConnectorConfigRepository,
        event_bus: IEventBus,
    ) -> None:
        self._registry = registry
        self._pipeline = pipeline
        self._config_repo = config_repo
        self._event_bus = event_bus

    async def handle(self, command: RunConnectorCommand) -> dict[str, Any]:
        """Execute connector pipeline and return summary."""
        config = await self._config_repo.get(command.connector_name)
        if config and not config.enabled:
            from threat_hunting.core.domain.exceptions import ConnectorDisabledError

            raise ConnectorDisabledError(f"Connector '{command.connector_name}' is disabled")

        connector = self._registry.get(command.connector_name)
        start = time.monotonic()
        errors: list[str] = []

        try:
            findings = await self._pipeline.execute(connector, keywords=command.keywords)
        except Exception as exc:
            errors.append(str(exc))
            findings = []

        duration = time.monotonic() - start
        await self._event_bus.publish(
            ConnectorExecuted(
                connector=command.connector_name,
                findings_count=len(findings),
                duration_seconds=duration,
                errors=errors,
            )
        )
        logger.info(
            "connector.executed",
            connector=command.connector_name,
            findings=len(findings),
            duration=duration,
        )
        return {
            "connector": command.connector_name,
            "findings_count": len(findings),
            "duration_seconds": round(duration, 3),
            "errors": errors,
        }


class RunConnectorGroupHandler:
    """Handler for connector group execution."""

    def __init__(self, run_handler: RunConnectorHandler) -> None:
        self._run_handler = run_handler

    async def handle(self, command: RunConnectorGroupCommand) -> list[dict[str, Any]]:
        """Run all connectors in a named group."""
        connectors = CONNECTOR_GROUPS.get(command.group_name, [])
        if not connectors:
            return [{"group": command.group_name, "error": "Unknown group"}]

        results = []
        for name in connectors:
            try:
                result = await self._run_handler.handle(RunConnectorCommand(connector_name=name))
                results.append(result)
            except Exception as exc:
                results.append({"connector": name, "error": str(exc)})
        return results


class RunAllConnectorsHandler:
    """Handler for running all registered connectors."""

    def __init__(
        self,
        registry: ConnectorRegistry,
        run_handler: RunConnectorHandler,
    ) -> None:
        self._registry = registry
        self._run_handler = run_handler

    async def handle(self, command: RunAllConnectorsCommand) -> list[dict[str, Any]]:
        """Execute all discovered connectors."""
        results = []
        for name in self._registry.list_names():
            try:
                result = await self._run_handler.handle(RunConnectorCommand(connector_name=name))
                results.append(result)
            except Exception as exc:
                results.append({"connector": name, "error": str(exc)})
        return results


class ConnectorConfigHandler:
    """Handler for enabling/disabling connectors."""

    def __init__(self, config_repo: IConnectorConfigRepository, audit_repo: Any) -> None:
        self._config_repo = config_repo
        self._audit_repo = audit_repo

    async def enable(self, command: EnableConnectorCommand) -> dict[str, Any]:
        """Enable a connector."""
        config = await self._config_repo.set_enabled(command.connector_name, True)
        await self._audit_repo.append(
            AuditLog(action="connector.enable", resource_id=command.connector_name)
        )
        return {"connector": config.name, "enabled": config.enabled}

    async def disable(self, command: DisableConnectorCommand) -> dict[str, Any]:
        """Disable a connector."""
        config = await self._config_repo.set_enabled(command.connector_name, False)
        await self._audit_repo.append(
            AuditLog(action="connector.disable", resource_id=command.connector_name)
        )
        return {"connector": config.name, "enabled": config.enabled}


class ExportHandler:
    """Handler for exporting findings."""

    def __init__(self, exporters: dict[str, IExporter], finding_repo: Any, event_bus: IEventBus) -> None:
        self._exporters = exporters
        self._finding_repo = finding_repo
        self._event_bus = event_bus

    async def handle(self, command: ExportCommand) -> dict[str, Any]:
        """Export findings to specified format."""
        exporter = self._exporters.get(command.export_format)
        if not exporter:
            from threat_hunting.core.domain.exceptions import ExportError

            raise ExportError(f"Unknown export format: {command.export_format}")

        if command.finding_ids:
            findings = []
            for fid in command.finding_ids:
                f = await self._finding_repo.get_by_id(fid)
                if f:
                    findings.append(f)
        else:
            findings = await self._finding_repo.list_all(limit=1000)

        result = await exporter.export(findings)
        logger.info("export.completed", format=command.export_format, count=len(findings))
        return result


class ScoreTestHandler:
    """Handler for testing scoring engine."""

    def __init__(self, scoring_engine: IScoringEngine) -> None:
        self._scoring_engine = scoring_engine

    async def handle(self, command: ScoreTestCommand) -> dict[str, Any]:
        """Score a sample finding for testing."""
        sample = Finding(
            title=command.sample_data.get("title", "Test Finding"),
            description=command.sample_data.get("description", ""),
            source=SourceType(command.sample_data.get("source", "api")),
            connector=command.sample_data.get("connector", "test"),
            category=FindingCategory(command.sample_data.get("category", "general")),
            severity=Severity(command.sample_data.get("severity", "medium")),
            tags=command.sample_data.get("tags", []),
            metadata=command.sample_data.get("metadata", {}),
        )
        scored = await self._scoring_engine.score(sample)
        return {
            "score": scored.score,
            "confidence": scored.confidence,
            "severity": scored.severity.value,
        }
