"""RunCollection use-case service.

Responsibility
--------------
Coordinate a full collection run: resolve the requested connector(s) from the
registry, execute the ordered pipeline for each, and aggregate the outcome into
a :class:`RunSummary`. This is the primary entry point invoked by the CLI, the
scheduler and (later) the API.

Design
------
* The service depends only on ports (registry, orchestrator, event bus),
  keeping it framework-free and unit-testable with in-memory adapters.
* The connector under processing is injected into ``context.state`` so the
  connector-aware pipeline stages (collect/parse/normalize) can use it without
  the orchestrator needing per-connector wiring — the stages stay generic.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

from threat_hunting.core.application.dto.run_summary import RunSummary
from threat_hunting.core.application.ports.connector import ConnectorPort, ConnectorRegistryPort
from threat_hunting.core.application.ports.event_bus import EventBus
from threat_hunting.core.application.ports.pipeline import PipelineContext
from threat_hunting.core.application.pipeline.orchestrator import PipelineOrchestrator
from threat_hunting.core.domain.exceptions import ConnectorError

# Sentinel group names understood by the CLI/service.
_ALL = "all"


class RunCollectionService:
    """Runs the collection pipeline for one connector, a group, or all."""

    def __init__(
        self,
        registry: ConnectorRegistryPort,
        orchestrator: PipelineOrchestrator,
        event_bus: EventBus | None = None,
    ) -> None:
        self._registry = registry
        self._orchestrator = orchestrator
        self._bus = event_bus

    def run(self, target: str) -> RunSummary:
        """Run the pipeline for ``target`` (a connector name, group, or 'all')."""
        connectors = self._resolve(target)
        summary = RunSummary(run_id="", connectors=[c.meta.name for c in connectors])
        started = time.perf_counter()

        for connector in connectors:
            self._run_one(connector, summary)

        summary.duration_seconds = round(time.perf_counter() - started, 4)
        if not summary.run_id:
            # Ensure a run id even when zero connectors matched.
            summary.run_id = PipelineContext(connector_name="none").run_id
        return summary

    def _run_one(self, connector: ConnectorPort, summary: RunSummary) -> None:
        """Execute the pipeline for a single connector and fold into ``summary``."""
        context = PipelineContext(connector_name=connector.meta.name)
        context.state["connector"] = connector
        summary.run_id = context.run_id
        try:
            context = self._orchestrator.run(context)
        except Exception as exc:  # aggregate, do not crash the whole run
            summary.errors.append(f"{connector.meta.name}: {exc}")
            return
        finally:
            try:
                connector.close()
            except Exception:  # closing must never mask the run outcome
                pass

        summary.findings_collected += len(context.findings)
        summary.findings_persisted += int(context.stats.get("persisted", 0))
        summary.findings_exported += int(context.stats.get("exported", 0))
        summary.duplicates_removed += int(context.stats.get("duplicates_removed", 0))
        for finding in context.findings:
            summary.register_severity(finding.severity)

    def _resolve(self, target: str) -> Sequence[ConnectorPort]:
        """Turn a target string into the connectors to run."""
        self._registry.discover()
        if target == _ALL:
            return [self._registry.get(meta.name) for meta in self._registry.all() if meta.enabled]

        group_connectors = self._registry.by_group(target)
        if group_connectors:
            return list(group_connectors)

        try:
            return [self._registry.get(target)]
        except ConnectorError:
            raise
