"""Unit tests for application handlers."""

import pytest

from threat_hunting.core.application.commands import (
    DisableConnectorCommand,
    EnableConnectorCommand,
    ExportCommand,
    RunAllConnectorsCommand,
    RunConnectorCommand,
    RunConnectorGroupCommand,
    ScoreTestCommand,
)
from threat_hunting.core.application.handlers import (
    ConnectorConfigHandler,
    ExportHandler,
    RunAllConnectorsHandler,
    RunConnectorGroupHandler,
    RunConnectorHandler,
    ScoreTestHandler,
)
from threat_hunting.core.domain.entities import ConnectorConfig, Finding
from threat_hunting.core.domain.enums import SourceType
from threat_hunting.infrastructure.exporters.base import JsonExporter
from threat_hunting.infrastructure.pipelines.event_bus import InProcessEventBus
from threat_hunting.infrastructure.plugins.discovery import ConnectorRegistry


class MockConfigRepo:
    def __init__(self):
        self._configs = {}

    async def get(self, name):
        return self._configs.get(name, ConnectorConfig(name=name, enabled=True))

    async def set_enabled(self, name, enabled):
        cfg = ConnectorConfig(name=name, enabled=enabled)
        self._configs[name] = cfg
        return cfg


class MockAuditRepo:
    def __init__(self):
        self.logs = []

    async def append(self, log):
        self.logs.append(log)
        return log


class MockFindingRepo:
    def __init__(self, findings=None):
        self._findings = findings or []

    async def get_by_id(self, fid):
        return None

    async def list_all(self, limit=1000):
        return self._findings

    async def save(self, f):
        return f


class MockPipeline:
    async def execute(self, connector, keywords=None):
        return [Finding(title="test", source=SourceType.API, connector=connector.name)]


@pytest.mark.asyncio
async def test_run_connector_handler():
    registry = ConnectorRegistry()
    from threat_hunting.infrastructure.connectors.reddit import RedditConnector
    registry.register(RedditConnector)

    handler = RunConnectorHandler(
        registry, MockPipeline(), MockConfigRepo(), InProcessEventBus()
    )
    result = await handler.handle(RunConnectorCommand(connector_name="reddit"))
    assert result["connector"] == "reddit"
    assert result["findings_count"] == 1


@pytest.mark.asyncio
async def test_run_connector_disabled():
    registry = ConnectorRegistry()
    from threat_hunting.infrastructure.connectors.reddit import RedditConnector
    registry.register(RedditConnector)

    config_repo = MockConfigRepo()
    config_repo._configs["reddit"] = ConnectorConfig(name="reddit", enabled=False)

    handler = RunConnectorHandler(
        registry, MockPipeline(), config_repo, InProcessEventBus()
    )
    with pytest.raises(Exception):
        await handler.handle(RunConnectorCommand(connector_name="reddit"))


@pytest.mark.asyncio
async def test_run_group_handler():
    registry = ConnectorRegistry()
    from threat_hunting.infrastructure.connectors.reddit import RedditConnector
    registry.register(RedditConnector)

    run_handler = RunConnectorHandler(
        registry, MockPipeline(), MockConfigRepo(), InProcessEventBus()
    )
    group_handler = RunConnectorGroupHandler(run_handler)
    results = await group_handler.handle(RunConnectorGroupCommand(group_name="social"))
    assert len(results) > 0


@pytest.mark.asyncio
async def test_run_all_handler():
    registry = ConnectorRegistry()
    from threat_hunting.infrastructure.connectors.reddit import RedditConnector
    registry.register(RedditConnector)

    run_handler = RunConnectorHandler(
        registry, MockPipeline(), MockConfigRepo(), InProcessEventBus()
    )
    all_handler = RunAllConnectorsHandler(registry, run_handler)
    results = await all_handler.handle(RunAllConnectorsCommand())
    assert len(results) == 1


@pytest.mark.asyncio
async def test_connector_config_handler():
    handler = ConnectorConfigHandler(MockConfigRepo(), MockAuditRepo())
    result = await handler.enable(EnableConnectorCommand(connector_name="reddit"))
    assert result["enabled"] is True
    result = await handler.disable(DisableConnectorCommand(connector_name="reddit"))
    assert result["enabled"] is False


@pytest.mark.asyncio
async def test_export_handler():
    findings = [Finding(title="F1", source=SourceType.API, connector="test")]
    handler = ExportHandler(
        {"json": JsonExporter()}, MockFindingRepo(findings), InProcessEventBus()
    )
    result = await handler.handle(ExportCommand(export_format="json"))
    assert result["count"] == 1


@pytest.mark.asyncio
async def test_export_handler_unknown_format():
    handler = ExportHandler({}, MockFindingRepo(), InProcessEventBus())
    with pytest.raises(Exception):
        await handler.handle(ExportCommand(export_format="unknown"))


@pytest.mark.asyncio
async def test_score_test_handler():
    from threat_hunting.infrastructure.scoring.engine import ScoringEngine
    from threat_hunting.tests.conftest import InMemoryScoreRepo

    handler = ScoreTestHandler(ScoringEngine(InMemoryScoreRepo()))
    result = await handler.handle(ScoreTestCommand())
    assert "score" in result
