"""Adapter coverage for storage, export, OPSEC and observability."""

import json
from pathlib import Path

import httpx
import pytest

from threat_hunting.connectors.generic import HttpConnector, RssConnector
from threat_hunting.connectors.registry import ConnectorRegistry
from threat_hunting.core.application.use_cases import HuntCommand, RunHuntUseCase
from threat_hunting.core.domain.entities import ConnectorDefinition, Finding
from threat_hunting.exporters.factory import ExporterFactory
from threat_hunting.exporters.integrations import PlaceholderExternalExporter, WebhookExporter
from threat_hunting.exporters.local import CsvExporter, JsonExporter, Stix21Exporter
from threat_hunting.infrastructure.config.settings import AppSettings, ExporterSettings, OpsecProfile, load_settings
from threat_hunting.infrastructure.events.bus import InMemoryEventBus
from threat_hunting.infrastructure.logging import configure_logging
from threat_hunting.infrastructure.observability.health import HealthService
from threat_hunting.infrastructure.observability.metrics import MetricsService
from threat_hunting.infrastructure.observability.tracing import configure_tracing
from threat_hunting.infrastructure.opsec.transport import RetryingHttpClient, SecretsProvider
from threat_hunting.scheduler.runner import SchedulerRunner
from threat_hunting.storage.repositories import InMemoryUnitOfWork, JsonFindingRepository
from threat_hunting.storage.sqlalchemy import SqlAlchemyUnitOfWork


class FakeResponse:
    """Small response object compatible with the retrying client."""

    status_code = 200
    text = "<html><title>Threat page</title><body>admin@example.com</body></html>"

    def raise_for_status(self) -> None:
        return None


class FakeHttpClient:
    """HTTP test double with deterministic responses."""

    def __init__(self) -> None:
        self.closed = False
        self.calls = 0

    def get(self, url: str, **kwargs):
        self.calls += 1
        return FakeResponse()

    def post(self, url: str, **kwargs):
        self.calls += 1
        return FakeResponse()

    def close(self) -> None:
        self.closed = True


def _finding() -> Finding:
    return Finding(
        title="Adapter finding",
        description="admin@example.com and example.com",
        source="test",
        connector="test",
        category="osint",
        score=99,
    )


def test_http_and_rss_connectors_parse_transport_payloads() -> None:
    """HTTP and RSS connectors use injected transports rather than owning OPSEC."""

    transport = RetryingHttpClient(FakeHttpClient(), retries=0, backoff_seconds=0)
    connector = HttpConnector("site", "site", {"urls": ["https://example.com"], "transport": transport})
    parsed = connector.parse(next(iter(connector.collect())))
    finding = connector.normalize(parsed)
    connector.close()

    assert finding.title == "Threat page"
    assert "admin@example.com" in finding.description

    rss_transport = RetryingHttpClient(FakeHttpClient(), retries=0, backoff_seconds=0)
    rss = RssConnector("feed", "feed", {"urls": ["https://example.com/rss"], "transport": rss_transport})
    rss_finding = rss.normalize(rss.parse(next(iter(rss.collect()))))

    assert rss_finding.connector == "feed"


def test_repositories_persist_json_and_sqlite(tmp_path: Path) -> None:
    """JSON and SQLAlchemy repositories implement the same finding contract."""

    finding = _finding()
    json_repo = JsonFindingRepository(tmp_path / "findings.json")
    json_repo.add(finding)

    assert json_repo.get_by_hash(finding.content_hash).id == finding.id
    assert json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))[0]["id"] == finding.id

    uow = SqlAlchemyUnitOfWork(f"sqlite:///{tmp_path / 'findings.db'}")
    with uow as active:
        active.findings.add(finding)

    with uow as active:
        assert active.findings.get_by_hash(finding.content_hash).id == finding.id
        assert active.findings.list()[0].title == finding.title


def test_exporters_write_local_files_and_factory_builds_placeholders(tmp_path: Path) -> None:
    """Local exporters and factory-built integrations accept canonical findings."""

    finding = _finding()
    JsonExporter(str(tmp_path / "findings.ndjson")).export(finding)
    CsvExporter(str(tmp_path / "findings.csv")).export(finding)
    Stix21Exporter(str(tmp_path / "findings.stix")).export(finding)
    placeholder = ExporterFactory().build(ExporterSettings(name="splunk", type="splunk", config={}))
    placeholder.export(finding)

    assert (tmp_path / "findings.ndjson").exists()
    assert "Adapter finding" in (tmp_path / "findings.csv").read_text(encoding="utf-8")
    assert "bundle" in (tmp_path / "findings.stix").read_text(encoding="utf-8")
    assert placeholder.exported == [finding.id]


def test_webhook_exporter_uses_httpx_post(monkeypatch) -> None:
    """Webhook exports are isolated behind an adapter and can be mocked."""

    calls = []

    def fake_post(url, json, headers, timeout):
        calls.append((url, json["id"], headers, timeout))
        return FakeResponse()

    monkeypatch.setattr(httpx, "post", fake_post)
    WebhookExporter("https://webhook.example", {"Authorization": "token"}).export(_finding())

    assert calls[0][0] == "https://webhook.example"


def test_opsec_retrying_client_and_secrets(monkeypatch) -> None:
    """OPSEC helpers resolve secrets and retry HTTP operations."""

    monkeypatch.setenv("MISP_TOKEN", "secret")
    client = FakeHttpClient()
    retrying = RetryingHttpClient(client, retries=0, backoff_seconds=0)

    assert SecretsProvider().get("MISP_TOKEN") == "secret"
    assert retrying.get("https://example.com").status_code == 200
    assert retrying.post("https://example.com").status_code == 200
    retrying.close()
    assert client.closed is True


def test_observability_event_bus_health_and_scheduler() -> None:
    """Health, metrics, tracing, event subscription and scheduler wiring work."""

    configure_logging()
    configure_tracing()
    registry = ConnectorRegistry([ConnectorDefinition(name="static", type="static", source="static")])
    health = HealthService(registry).check()
    metrics = MetricsService()
    bus = InMemoryEventBus()
    seen = []
    bus.subscribe("custom", lambda event: seen.append(event.name))
    from threat_hunting.core.domain.events import DomainEvent

    bus.publish(DomainEvent(name="custom"))
    scheduler = SchedulerRunner(registry, object(), interval_minutes=5)

    assert health["status"] == "ok"
    assert b"findings_total" in metrics.render()
    assert seen == ["custom"]
    assert scheduler._interval_minutes == 5


def test_use_case_and_settings_fallback() -> None:
    """Application command objects compose registry and pipeline contracts."""

    class Registry:
        def get(self, name):
            return name

    class Pipeline:
        def run(self, connector, export=True):
            return [connector, export]

    assert RunHuntUseCase(Registry(), Pipeline()).execute(HuntCommand("github", export=False)) == ["github", False]
    assert load_settings("/tmp/does-not-exist.yml") == AppSettings()


def test_registry_errors_are_explicit() -> None:
    """Registry failures identify missing names and unknown connector types."""

    registry = ConnectorRegistry([])
    with pytest.raises(KeyError):
        registry.get("missing")

    registry = ConnectorRegistry([ConnectorDefinition(name="bad", type="missing", source="bad")])
    with pytest.raises(KeyError):
        registry.get("bad")
