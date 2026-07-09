"""Additional tests to validate platform components and target coverage."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from threat_hunting.application.commands import (
    ExportFindingsCommand,
    RunHuntCommand,
    RunSchedulerCommand,
    ScoreTestCommand,
    ToggleConnectorCommand,
)
from threat_hunting.application.use_cases import HuntApplicationService
from threat_hunting.core.contracts import StageContext
from threat_hunting.domain.entities import Finding, Severity
from threat_hunting.exporters.implementations import (
    OpenSearchExporter,
    RestAPIExporter,
    STIX21Exporter,
    SplunkExporter,
    TAXII21Exporter,
    WebhookExporter,
)
from threat_hunting.infrastructure.observability.health import HealthCheckRegistry
from threat_hunting.infrastructure.opsec.transport import OPSECProfile, OPSECTransport
from threat_hunting.integrations.misp_adapter import MISPAdapter
from threat_hunting.integrations.opencti_adapter import OpenCTIAdapter
from threat_hunting.scheduler.service import SchedulerService
from threat_hunting.storage.backends import (
    DataLakeStorageAdapter,
    ElasticsearchStorageAdapter,
    JsonStorageAdapter,
    OpenSearchStorageAdapter,
    ParquetStorageAdapter,
    PostgreSQLStorageAdapter,
    S3StorageAdapter,
    SplunkStorageAdapter,
    SqliteStorageAdapter,
)


class FakeResponse:
    def raise_for_status(self) -> None:
        return


class FakeClient:
    def __init__(self, *args, **kwargs):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def request(self, method, url, headers=None, json=None):
        self.calls.append((method, url, headers, json))
        return FakeResponse()


class FakeConnectorFactory:
    def __init__(self):
        self._available = ["reddit"]

    def available(self):
        return self._available

    def create(self, connector_name: str):
        return object()


class FakePipeline:
    def run(self, *, connector, context):
        return [
            Finding(
                title="test",
                description="test",
                source=context.connector_name,
                connector=context.connector_name,
                category="osint",
            )
        ]


class FakeExporterFactory:
    class _Exporter:
        def export(self, findings, context):
            return None

    def get(self, name: str):
        return self._Exporter()


class FakeFindingsRepo:
    def __init__(self):
        self._findings = [
            Finding(
                title="persisted",
                description="persisted",
                source="reddit",
                connector="reddit",
                category="osint",
            )
        ]

    def list_recent(self, limit: int = 100):
        return self._findings[:limit]

    def add_many(self, findings):
        self._findings.extend(findings)


class FakeUoW:
    def __init__(self):
        self.findings = FakeFindingsRepo()
        self.committed = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


class FakeScoringEngine:
    def run(self, items, context):
        payload = items[0]
        payload["score"] = 90
        payload["confidence"] = 90
        return [payload]


def _build_service() -> HuntApplicationService:
    scheduler = SchedulerService()
    service = HuntApplicationService(
        connector_factory=FakeConnectorFactory(),
        pipeline=FakePipeline(),
        exporter_factory=FakeExporterFactory(),
        uow=FakeUoW(),
        scoring_engine=FakeScoringEngine(),
        scheduler=scheduler,
        event_bus=object(),
        runtime_config={
            "connector_groups": {"social": ["reddit"]},
            "connectors": {"reddit": {"enabled": True}},
        },
    )
    scheduler.set_run_target(lambda target: service.run_hunt(RunHuntCommand(target=target)))
    return service


def test_use_case_commands_cover_paths() -> None:
    service = _build_service()
    result = service.run_hunt(RunHuntCommand(target="social"))
    assert result.findings_count == 1
    disabled = service.toggle_connector(ToggleConnectorCommand(connector_name="reddit", enabled=False))
    assert disabled["status"] == "disabled"
    exported = service.export_findings(ExportFindingsCommand(target="json", limit=1))
    assert exported["count"] == 1
    scheduler_result = service.run_scheduler(RunSchedulerCommand())
    assert scheduler_result["status"] == "scheduler_executed"
    score_result = service.score_test(ScoreTestCommand())
    assert score_result["score"] == 90


def test_health_registry_reports_status() -> None:
    registry = HealthCheckRegistry()
    registry.register("ok_check", lambda: True)
    registry.register("error_check", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    result = registry.run()
    assert result["status"] == "degraded"
    assert not result["error_check"]["ok"]


def test_opsec_transport_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("threat_hunting.infrastructure.opsec.transport.httpx.Client", FakeClient)
    transport = OPSECTransport(profiles={"default": OPSECProfile(name="default", rate_limit_per_second=1000)})
    response = transport.get("https://example.com")
    assert isinstance(response, FakeResponse)
    response = transport.post("https://example.com", json_payload={"a": 1})
    assert isinstance(response, FakeResponse)


def test_storage_adapters_and_integrations(tmp_path: Path) -> None:
    finding = Finding(
        title="storage",
        description="storage",
        source="source",
        connector="connector",
        category="category",
        severity=Severity.info,
    )
    json_path = tmp_path / "findings.json"
    JsonStorageAdapter(str(json_path)).write_findings([finding])
    assert json_path.exists()

    SqliteStorageAdapter().write_findings([finding])
    PostgreSQLStorageAdapter().write_findings([finding])
    OpenSearchStorageAdapter().write_findings([finding])
    ElasticsearchStorageAdapter().write_findings([finding])
    SplunkStorageAdapter().write_findings([finding])
    ParquetStorageAdapter().write_findings([finding])
    DataLakeStorageAdapter().write_findings([finding])
    S3StorageAdapter().write_findings([finding])

    MISPAdapter(url="", api_key="").connect()
    MISPAdapter(url="", api_key="").export_findings([finding], event_id=None)
    OpenCTIAdapter().export_findings([finding])

    context = StageContext(
        connector_name="test",
        run_id="run",
        started_at=datetime.now(UTC),
        metadata={},
    )
    SplunkExporter().export([finding], context)
    OpenSearchExporter().export([finding], context)
    WebhookExporter().export([finding], context)
    RestAPIExporter().export([finding], context)
    STIX21Exporter().export([finding], context)
    TAXII21Exporter().export([finding], context)
