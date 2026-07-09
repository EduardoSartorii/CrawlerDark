"""Additional coverage tests for support modules and branches."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from threat_hunting.core.events import DomainEvent
from threat_hunting.detections.engine import DynamicDetectionEngine
from threat_hunting.domain.catalogs import IdentityCatalog, KeywordCatalog, ObservableCatalog, WatchlistCatalog
from threat_hunting.domain.entities import ExecutionContext, Finding, Indicator
from threat_hunting.domain.rules import DetectionRule, RuleType
from threat_hunting.infrastructure.config import OpsecProfileConfig
from threat_hunting.infrastructure.container import AppContainer
from threat_hunting.infrastructure.opsec import OpsecTransport
from threat_hunting.integrations.observers import HighScoreObserver
from threat_hunting.plugins.discovery import build_registry
from threat_hunting.scheduler.service import SchedulerService
from threat_hunting.storage.backends import (
    DataLakeBackend,
    ElasticsearchBackend,
    JsonBackend,
    OpenSearchBackend,
    ParquetBackend,
    PostgreSqlBackend,
    S3Backend,
    SplunkBackend,
    SqliteBackend,
)


class _RuleRepo:
    def __init__(self, rules: list[DetectionRule]) -> None:
        self._rules = rules

    def load_detection_rules(self) -> list[DetectionRule]:
        return self._rules


def test_detection_engine_branches() -> None:
    finding = Finding(
        title="Credential leak for ACME",
        description="darkspider shared admin@acme.com",
        source="unit",
        connector="unit",
        indicators=[Indicator(type="email", value="admin@acme.com")],
    )
    rules = [
        DetectionRule(rule_id="1", name="regex", rule_type=RuleType.REGEX, expression="credential"),
        DetectionRule(rule_id="2", name="yara", rule_type=RuleType.YARA, expression="acme"),
        DetectionRule(rule_id="3", name="sigma", rule_type=RuleType.SIGMA, expression="darkspider"),
        DetectionRule(rule_id="4", name="threshold", rule_type=RuleType.THRESHOLD, expression="x"),
        DetectionRule(
            rule_id="5",
            name="composite",
            rule_type=RuleType.COMPOSITE,
            expression="credential && darkspider",
        ),
        DetectionRule(
            rule_id="6",
            name="blacklist",
            rule_type=RuleType.BLACKLIST,
            expression="darkspider",
        ),
    ]
    engine = DynamicDetectionEngine(rule_repository=_RuleRepo(rules))
    context = ExecutionContext(command="test", connector_name="unit")
    results = engine.process([finding], context)
    assert results[0].severity.value == "critical"
    assert len(results[0].metadata["matched_rules"]) >= 5


def test_catalog_models_and_observer() -> None:
    watchlist = WatchlistCatalog(
        keywords=KeywordCatalog(keywords=["acme"], yara_rules=["rule test {}"]),
        identities=IdentityCatalog(vips=["ceo@acme.com"]),
        observables=ObservableCatalog(domains=["acme.com"], ioc_lists=["default"]),
    )
    assert watchlist.keywords.keywords == ["acme"]

    observer = HighScoreObserver()
    event = DomainEvent(name="HighScoreFinding", payload={"finding_id": "1"})
    observer(event)
    assert len(observer.events) == 1


def test_storage_backend_interfaces() -> None:
    finding = Finding(
        title="x",
        description="y",
        source="z",
        connector="w",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    backends = [
        SqliteBackend(),
        PostgreSqlBackend(),
        OpenSearchBackend(),
        ElasticsearchBackend(),
        SplunkBackend(),
        JsonBackend(),
        ParquetBackend(),
        DataLakeBackend(),
        S3Backend(),
    ]
    for backend in backends:
        backend.save_findings([finding])


class _FakeResponse:
    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def get(self, url: str, **kwargs: object) -> _FakeResponse:
        return _FakeResponse()


def test_opsec_transport_profiles(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("threat_hunting.infrastructure.opsec.httpx.Client", _FakeClient)
    monkeypatch.setattr("threat_hunting.infrastructure.opsec.time.sleep", lambda _x: None)
    transport = OpsecTransport(
        profiles={
            "default": OpsecProfileConfig(
                name="default",
                http_proxy="http://proxy.local:8080",
                rate_limit_per_minute=1,
                retries=1,
            )
        }
    )
    response = transport.get("https://example.com", profile_name="default")
    assert isinstance(response, _FakeResponse)


def test_scheduler_runs_all_once(test_config_path: object) -> None:
    container = AppContainer()
    registry = build_registry(container.settings(), container.connector_registry())
    scheduler = SchedulerService(pipeline=container.pipeline(), registry=registry)
    scheduler.register_connector_job("reddit", minutes=1)
    scheduler.run_all_once()
    persisted = list(container.finding_repository().list_all())
    assert len(persisted) >= 1
