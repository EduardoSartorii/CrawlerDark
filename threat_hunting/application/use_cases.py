"""Application services and command handlers.

This module keeps orchestration independent from interfaces (CLI/API/Scheduler).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from uuid import uuid4

from threat_hunting.application.commands import (
    CommandBus,
    ExportFindingsCommand,
    RunHuntCommand,
    RunSchedulerCommand,
    ScoreTestCommand,
    ToggleConnectorCommand,
)
from threat_hunting.application.factories import ConnectorFactory, ExporterFactory
from threat_hunting.core.contracts import EventBusPort, ScoringEnginePort, StageContext, UnitOfWorkPort
from threat_hunting.domain.entities import Finding
from threat_hunting.pipelines.orchestrator import HuntingPipeline
from threat_hunting.scheduler.service import SchedulerService


@dataclass(slots=True)
class HuntExecutionResult:
    """Result summary for a hunt execution."""

    run_id: str
    connectors: list[str]
    findings_count: int


class HuntApplicationService:
    """Command handlers used by CLI and scheduler."""

    def __init__(
        self,
        *,
        connector_factory: ConnectorFactory,
        pipeline: HuntingPipeline,
        exporter_factory: ExporterFactory,
        uow: UnitOfWorkPort,
        scoring_engine: ScoringEnginePort,
        scheduler: SchedulerService,
        event_bus: EventBusPort,
        runtime_config: dict,
    ) -> None:
        self._connector_factory = connector_factory
        self._pipeline = pipeline
        self._exporter_factory = exporter_factory
        self._uow = uow
        self._scoring_engine = scoring_engine
        self._scheduler = scheduler
        self._event_bus = event_bus
        self._runtime_config = runtime_config

    def run_hunt(self, command: RunHuntCommand) -> HuntExecutionResult:
        """Execute connector group or individual connector."""
        target = command.target.lower()
        connectors = self._resolve_connectors(target)
        run_id = str(uuid4())
        total_findings = 0
        for connector_name in connectors:
            context = StageContext(
                connector_name=connector_name,
                run_id=run_id,
                started_at=datetime.now(UTC),
                metadata={"target": target},
            )
            connector = self._connector_factory.create(connector_name)
            findings = self._pipeline.run(connector=connector, context=context)
            total_findings += len(findings)
        return HuntExecutionResult(run_id=run_id, connectors=connectors, findings_count=total_findings)

    def toggle_connector(self, command: ToggleConnectorCommand) -> dict[str, str]:
        """Enable/disable connector through runtime configuration."""
        connectors_cfg = self._runtime_config.setdefault("connectors", {})
        connector_cfg = connectors_cfg.setdefault(command.connector_name.lower(), {})
        connector_cfg["enabled"] = command.enabled
        status = "enabled" if command.enabled else "disabled"
        return {"connector": command.connector_name, "status": status}

    def export_findings(self, command: ExportFindingsCommand) -> dict[str, int | str]:
        """Export recent findings using selected exporter."""
        exporter = self._exporter_factory.get(command.target)
        with self._uow:
            findings = self._uow.findings.list_recent(limit=command.limit)
        context = StageContext(
            connector_name="export",
            run_id=str(uuid4()),
            started_at=datetime.now(UTC),
            metadata={"target": command.target},
        )
        exporter.export(findings=findings, context=context)
        return {"target": command.target, "count": len(findings)}

    def run_scheduler(self, _: RunSchedulerCommand) -> dict[str, str]:
        """Run scheduler cycle once."""
        self._scheduler.run_once()
        return {"status": "scheduler_executed"}

    def score_test(self, _: ScoreTestCommand) -> dict[str, float]:
        """Run deterministic synthetic score test."""
        sample = {
            "title": "VIP credential leak",
            "description": "Credential set exposed for executive account",
            "signals": ["keyword_match", "vip_match", "ioc_match", "credential_match"],
            "severity": "high",
            "source": "synthetic",
            "connector": "test",
            "category": "credential_hunting",
            "raw_data": {},
            "normalized_data": {"ioc": "198.51.100.20"},
            "metadata": {},
            "tags": ["test"],
            "artifacts": [],
            "indicators": [],
            "relationships": [],
            "timeline": [],
        }
        scored = self._scoring_engine.run(
            [sample],
            StageContext(
                connector_name="test",
                run_id=str(uuid4()),
                started_at=datetime.now(UTC),
                metadata={"mode": "score_test"},
            ),
        )[0]
        return {"score": float(scored["score"]), "confidence": float(scored["confidence"])}

    def _resolve_connectors(self, target: str) -> list[str]:
        """Resolve single connector or logical groups."""
        groups = self._runtime_config.get("connector_groups", {})
        enabled_map = self._runtime_config.get("connectors", {})
        available = set(self._connector_factory.available())
        if target == "all":
            selected = sorted(
                name for name in available if enabled_map.get(name, {}).get("enabled", True)
            )
            return selected
        if target in groups:
            selected = [
                name
                for name in groups[target]
                if name in available and enabled_map.get(name, {}).get("enabled", True)
            ]
            return sorted(selected)
        if target in available:
            if not enabled_map.get(target, {}).get("enabled", True):
                return []
            return [target]
        return []


def build_command_bus(service: HuntApplicationService) -> CommandBus:
    """Register command handlers in command bus."""
    bus = CommandBus()
    bus.register(RunHuntCommand, service.run_hunt)
    bus.register(ToggleConnectorCommand, service.toggle_connector)
    bus.register(ExportFindingsCommand, service.export_findings)
    bus.register(RunSchedulerCommand, service.run_scheduler)
    bus.register(ScoreTestCommand, service.score_test)
    return bus
