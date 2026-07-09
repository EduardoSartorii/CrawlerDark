"""Focused coverage for command, factory and strategy branches."""

from pathlib import Path

import httpx
import pytest
import typer
from typer.testing import CliRunner

from threat_hunting.cli.main import app
from threat_hunting.connectors.generic import HttpConnector, RssConnector, StaticConnector
from threat_hunting.connectors.registry import ConnectorRegistry
from threat_hunting.core.domain.entities import ConnectorDefinition, DetectionRule, Finding, Severity
from threat_hunting.deduplication.engine import HybridDeduplicationEngine
from threat_hunting.detections.engine import InMemoryDetectionRuleRepository, RuleBasedDetectionEngine
from threat_hunting.exporters.factory import ExporterFactory
from threat_hunting.exporters.integrations import MispExporter
from threat_hunting.infrastructure.config.settings import AppSettings, ExporterSettings, OpsecProfile, StorageSettings
from threat_hunting.infrastructure.container import _build_exporters, _build_unit_of_work
from threat_hunting.infrastructure.opsec.transport import HttpTransportFactory, RetryingHttpClient
from threat_hunting.parsers.default import PassthroughParser
from threat_hunting.scheduler.runner import SchedulerRunner


def _config(path: Path) -> Path:
    path.write_text(
        """
connectors:
  - name: github
    type: static
    source: github
    enabled: true
    config:
      category: credential_hunting
      items:
        - title: "CLI leak"
          description: "password for cli@example.com"
detection_rules:
  - id: cli
    name: CLI password
    kind: keyword
    pattern: password
    severity: high
    tags: ["cli"]
    weight: 2
score_policy:
  export_threshold: 5
  weights:
    detection: 5
    email: 2
    credential: 3
storage:
  backend: memory
exporters: []
""",
        encoding="utf-8",
    )
    return path


def test_cli_run_and_export_commands_execute_pipeline(tmp_path: Path) -> None:
    """CLI run/export commands execute a configured connector end to end."""

    config = _config(tmp_path / "config.yml")
    runner = CliRunner()

    run_result = runner.invoke(app, ["run", "github", "--config", str(config)])
    export_result = runner.invoke(app, ["export", "splunk", "--config", str(config)])

    assert run_result.exit_code == 0
    assert '"processed": 1' in run_result.output
    assert export_result.exit_code == 0


def test_detection_rule_kinds_and_repository() -> None:
    """Detection supports dynamic rule kinds without hardcoding source logic."""

    finding = Finding(title="Actor", description="alpha beta 10", source="x", connector="x", category="ioc", score=10)
    rules = [
        DetectionRule(id="regex", name="Regex", kind="regex", pattern="alpha", severity=Severity.LOW),
        DetectionRule(id="ioc", name="IOC", kind="ioc", pattern="beta", severity=Severity.MEDIUM),
        DetectionRule(id="whitelist", name="Whitelist", kind="whitelist", pattern="not-present", severity=Severity.LOW),
        DetectionRule(id="threshold", name="Threshold", kind="threshold", pattern="10", severity=Severity.HIGH),
        DetectionRule(id="unknown", name="Unknown", kind="unknown", pattern="alpha", enabled=False),
    ]
    repo = InMemoryDetectionRuleRepository(rules)
    detected = RuleBasedDetectionEngine(repo.list_enabled()).detect(finding)

    assert len(detected.metadata["detections"]) == 3
    assert detected.severity == Severity.HIGH


def test_factory_branches_and_misp_monkeypatch(monkeypatch, tmp_path: Path) -> None:
    """Exporter factory builds local and MISP adapters through configuration."""

    built = []

    class FakeMispObject:
        def __init__(self, name):
            self.name = name
            self.attributes = []

        def add_attribute(self, kind, value):
            self.attributes.append((kind, value))

    class FakePyMisp:
        def __init__(self, url, api_key, verify_tls):
            built.append((url, api_key, verify_tls))

        def add_object(self, event_id, misp_object):
            built.append((event_id, misp_object.name))

    import pymisp

    monkeypatch.setattr(pymisp, "ExpandedPyMISP", FakePyMisp)
    monkeypatch.setattr(pymisp, "MISPObject", FakeMispObject)

    factory = ExporterFactory()
    factory.build(ExporterSettings(name="json", type="json", config={"path": str(tmp_path / "a.ndjson")})).export(
        Finding(title="x", source="x", connector="x", category="x")
    )
    factory.build(ExporterSettings(name="csv", type="csv", config={"path": str(tmp_path / "a.csv")})).export(
        Finding(title="x", source="x", connector="x", category="x")
    )
    factory.build(ExporterSettings(name="stix", type="stix21", config={"path": str(tmp_path / "a.stix")})).export(
        Finding(title="x", source="x", connector="x", category="x")
    )
    misp = MispExporter("https://misp.example", "key", "event", verify_tls=False)
    misp.export(Finding(title="MISP", description="body", source="x", connector="x", category="x"))

    assert built[0] == ("https://misp.example", "key", False)
    assert built[-1] == ("event", "threat-hunting-finding")


def test_opsec_factory_and_retry_failure(monkeypatch) -> None:
    """Transport factory builds clients and retry wrapper raises final errors."""

    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(httpx, "Client", FakeClient)
    HttpTransportFactory().build(OpsecProfile(name="p", http_proxy="http://proxy"))
    assert captured["proxy"] == "http://proxy"

    class FailingClient:
        def get(self, url, **kwargs):
            raise httpx.HTTPError("boom")

    with pytest.raises(httpx.HTTPError):
        RetryingHttpClient(FailingClient(), retries=0, backoff_seconds=0).get("https://example.com")


def test_scheduler_start_and_shutdown() -> None:
    """Scheduler registers one job per enabled connector."""

    registry = ConnectorRegistry([ConnectorDefinition(name="github", type="static", source="github")])

    class Pipeline:
        def run(self, connector):
            return []

    scheduler = SchedulerRunner(registry, Pipeline(), interval_minutes=1).start()
    try:
        assert scheduler.get_job("hunt-github") is not None
    finally:
        scheduler.shutdown(wait=False)


def test_small_fallback_branches() -> None:
    """Fallback branches remain deterministic for scalar payloads and duplicates."""

    assert PassthroughParser().parse("raw") == {"value": "raw"}
    connector = StaticConnector("static", "static", {})
    assert connector.parse("raw")["title"] == "raw"
    http = HttpConnector("http", "http", {"urls": ["https://example.com"]})
    assert next(iter(http.collect()))["url"] == "https://example.com"
    rss = RssConnector("rss", "rss", {})
    assert rss.normalize({"title": "empty", "description": "empty"}).title == "empty"

    first = Finding(title="same", description="same text", source="x", connector="x", category="x")
    second = Finding(title="same", description="same text", source="x", connector="x", category="x")
    assert HybridDeduplicationEngine().is_duplicate(first, [second]) is True

    with pytest.raises(typer.BadParameter):
        from threat_hunting.cli.main import _set_connector_state

        _set_connector_state("missing", True, "/tmp/does-not-exist.yml")


def test_container_builds_storage_and_exporters(tmp_path: Path) -> None:
    """Container helper functions choose storage and exporter adapters from settings."""

    json_settings = AppSettings(storage=StorageSettings(backend="json", path=str(tmp_path / "findings.json")))
    sql_settings = AppSettings(storage=StorageSettings(backend="sqlite", url=f"sqlite:///{tmp_path / 'db.sqlite'}"))
    export_settings = AppSettings(
        exporters=[ExporterSettings(name="json", type="json", config={"path": str(tmp_path / "export.ndjson")})]
    )

    assert _build_unit_of_work(json_settings).findings is not None
    with _build_unit_of_work(sql_settings) as active:
        assert active.findings.list() == []
    assert _build_exporters(export_settings)[0].name == "json"
