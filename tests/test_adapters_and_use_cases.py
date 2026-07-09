"""Adapter and use case coverage tests."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from threat_hunting.cli.app import app
from threat_hunting.connectors.registry import ConnectorRegistry
from threat_hunting.core.application.commands import ExportCommand, RunHuntCommand, ToggleConnectorCommand
from threat_hunting.core.application.event_bus import InMemoryEventBus
from threat_hunting.core.application.pipeline import CollectionPipeline
from threat_hunting.core.application.use_cases import ExportFindingsUseCase, RunHuntUseCase, ToggleConnectorUseCase
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.rules import ScoringProfile
from threat_hunting.correlation.engine import IndicatorCorrelationEngine
from threat_hunting.deduplication.engine import HashSimilarityDeduplicationEngine
from threat_hunting.detections.engine import ConfigurableDetectionEngine
from threat_hunting.enrichment.engine import MetadataEnrichmentEngine
from threat_hunting.exporters.implementations import CsvExporter, JsonExporter, StubExporter, build_exporters
from threat_hunting.infrastructure.config import OpsecProfile, PlatformSettings
from threat_hunting.infrastructure.observability import configure_tracing, pipeline_span, record_finding
from threat_hunting.infrastructure.opsec import HttpxOpsecTransport, OpsecTransportFactory, RateLimiter
from threat_hunting.normalizers.finding import FindingNormalizer
from threat_hunting.plugins.manager import PluginManager
from threat_hunting.scoring.engine import WeightedScoringEngine
from threat_hunting.storage.memory import InMemoryUnitOfWork


def test_use_cases_run_toggle_and_export() -> None:
    """Use cases should coordinate registry, pipeline, connector state, and exporters."""

    registry = ConnectorRegistry({"github": {"items": [{"title": "x", "description": "y"}]}}).discover()
    pipeline = CollectionPipeline(
        ConfigurableDetectionEngine([]),
        WeightedScoringEngine(ScoringProfile()),
        IndicatorCorrelationEngine(),
        HashSimilarityDeduplicationEngine(),
        MetadataEnrichmentEngine(),
        InMemoryUnitOfWork(),
        InMemoryEventBus(),
    )
    findings = RunHuntUseCase(registry, pipeline).execute(RunHuntCommand(target="github", export=False))
    exporter = StubExporter("stub", {})

    ToggleConnectorUseCase(registry).execute(ToggleConnectorCommand(connector_name="github", enabled=False))
    count = ExportFindingsUseCase(pipeline.unit_of_work, {"stub": exporter}).execute(ExportCommand(exporter_name="stub"))

    assert len(findings) == 1
    assert count == 1
    assert exporter.last_exported == findings
    assert registry.resolve("github") == []


def test_exporters_write_json_csv_and_build_stubs(tmp_path: Path) -> None:
    """Exporter adapters should serialize findings and build configured integrations."""

    finding = Finding(title="Leak", description="data", source="rss", connector="rss", category="news")
    json_path = tmp_path / "findings.json"
    csv_path = tmp_path / "findings.csv"

    JsonExporter(json_path).export([finding])
    CsvExporter(csv_path).export([finding])
    exporters = build_exporters(
        PlatformSettings(
            exporters={
                "json": {"enabled": True, "path": str(json_path)},
                "csv": {"enabled": True, "path": str(csv_path)},
                "webhook": {"enabled": False},
            }
        )
    )

    assert json.loads(json_path.read_text(encoding="utf-8"))[0]["title"] == "Leak"
    with csv_path.open(encoding="utf-8") as handle:
        assert next(csv.DictReader(handle))["connector"] == "rss"
    assert {"misp", "opencti", "splunk", "opensearch", "elastic"} <= set(exporters)


def test_opsec_transport_retries_and_factory(monkeypatch: pytest.MonkeyPatch) -> None:
    """OPSEC transport should apply retries and connector profile selection."""

    calls: list[str] = []

    class FakeResponse:
        text = "ok"

        def raise_for_status(self) -> None:
            return None

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

        def request(self, method: str, url: str, **kwargs: object) -> FakeResponse:
            calls.append(f"{method}:{url}")
            return FakeResponse()

    monkeypatch.setattr("threat_hunting.infrastructure.opsec.httpx.Client", FakeClient)
    monkeypatch.setattr("threat_hunting.infrastructure.opsec.time.sleep", lambda _: None)
    RateLimiter(0).wait()
    settings = PlatformSettings(
        opsec_profiles={"default": OpsecProfile(rate_limit_per_minute=0), "tor": OpsecProfile(socks_proxy="socks5://tor")},
        connector_opsec_profiles={"darkweb": "tor"},
    )
    transport = OpsecTransportFactory(settings)("darkweb", {})

    response = transport.request("GET", "https://example.test")

    assert response.text == "ok"
    assert calls == ["GET:https://example.test"]


def test_observability_helpers_execute() -> None:
    """Observability helpers should expose tracing and metrics hooks."""

    configure_tracing()
    with pipeline_span("github"):
        record_finding("github", "high")


def test_normalizer_and_plugin_facade() -> None:
    """Normalizer and plugin facade should expose extension points."""

    finding = FindingNormalizer().normalize(
        {"title": "Leak", "description": "Body"},
        source="rss",
        connector="rss",
        category="news",
    )
    registry = PluginManager(ConnectorRegistry()).load()

    assert finding.title == "Leak"
    assert "rss" in registry.names()


def test_cli_connector_export_and_help_commands(tmp_path: Path) -> None:
    """CLI should support requested connector and export command shapes."""

    config = tmp_path / "config.yml"
    config.write_text(
        """
connectors: {}
storage:
  backend: "memory"
exporters:
  json:
    enabled: true
    path: "%s"
        """
        % (tmp_path / "export.json"),
        encoding="utf-8",
    )
    runner = CliRunner()

    enable = runner.invoke(app, ["connector", "enable", "reddit", "--config", str(config)])
    disable = runner.invoke(app, ["connector", "disable", "reddit", "--config", str(config)])
    export = runner.invoke(app, ["export", "json", "--config", str(config)])

    assert enable.exit_code == 0
    assert disable.exit_code == 0
    assert export.exit_code == 0
    assert "exported=0 exporter=json" in export.stdout
