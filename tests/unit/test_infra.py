"""Unit tests — connectors, exporters, OPSEC, event bus, storage."""

from __future__ import annotations

import pytest

from threat_hunting.connectors.registry import ConnectorFactory, ConnectorRegistry, get_registry
from threat_hunting.core.domain.enums import ExportFormat
from threat_hunting.core.domain.events import FindingCreated, ScoreThresholdExceeded
from threat_hunting.core.domain.services import FindingBuilder
from threat_hunting.core.domain.value_objects import OpsecProfile
from threat_hunting.exporters import ExporterFactory, JsonExporter, MispExporter
from threat_hunting.infrastructure.messaging.event_bus import InMemoryEventBus
from threat_hunting.infrastructure.opsec.transport import (
    InMemoryCredentialVault,
    TokenBucketRateLimiter,
)
from threat_hunting.infrastructure.persistence.memory import InMemoryUnitOfWork
from threat_hunting.storage.backends import JsonFileStorageBackend, S3StorageBackend


def test_connector_discovery() -> None:
    registry = ConnectorRegistry()
    count = registry.discover()
    assert count >= 20
    assert "reddit" in registry.list_names()
    assert "darkweb" in registry.list_names()
    assert "misp" in registry.list_names()
    assert "github" in registry.list_by_group("code")


@pytest.mark.asyncio
async def test_connector_collect_normalize(connector_factory: ConnectorFactory) -> None:
    connector = connector_factory.create("reddit")
    await connector.connect()
    docs = []
    async for raw in connector.collect():
        parsed = await connector.parse(raw)
        finding = await connector.normalize(parsed)
        docs.append(finding)
    await connector.close()
    assert docs
    assert docs[0].connector == "reddit"
    assert docs[0].title


@pytest.mark.asyncio
async def test_all_major_connectors_instantiate(connector_factory: ConnectorFactory) -> None:
    for name in ["telegram", "github", "paste", "darkweb", "virustotal", "urlhaus"]:
        c = connector_factory.create(name)
        assert c.name == name
        health = await c.health()
        assert health.component.startswith("connector:")


@pytest.mark.asyncio
async def test_json_exporter(tmp_path, sample_finding) -> None:
    path = tmp_path / "out.json"
    result = await JsonExporter().export([sample_finding], path=str(path))
    assert path.exists()
    assert result["count"] == 1


@pytest.mark.asyncio
async def test_misp_offline_exporter(tmp_path, sample_finding) -> None:
    path = tmp_path / "misp.json"
    result = await MispExporter().export([sample_finding], path=str(path))
    assert result["mode"] == "offline"
    assert path.exists()


@pytest.mark.asyncio
async def test_exporter_factory_aliases() -> None:
    factory = ExporterFactory()
    assert factory.create("elastic").format == ExportFormat.OPENSEARCH
    assert factory.create("stix").format == ExportFormat.STIX21
    assert "misp" in factory.list_available()


@pytest.mark.asyncio
async def test_event_bus_observer() -> None:
    bus = InMemoryEventBus()
    received = []

    class H:
        async def handle(self, event):
            received.append(event)

    bus.subscribe("FindingCreated", H())
    await bus.publish(FindingCreated(aggregate_id="1", payload={"x": 1}))
    assert len(received) == 1


@pytest.mark.asyncio
async def test_rate_limiter() -> None:
    limiter = TokenBucketRateLimiter()
    await limiter.acquire("t", rps=100.0)
    await limiter.acquire("t", rps=100.0)


@pytest.mark.asyncio
async def test_vault() -> None:
    vault = InMemoryCredentialVault({"social/reddit": {"token": "abc"}})
    creds = await vault.get("vault://social/reddit")
    assert creds["token"] == "abc"


@pytest.mark.asyncio
async def test_uow_findings(uow: InMemoryUnitOfWork, sample_finding) -> None:
    async with uow:
        await uow.findings.save(sample_finding)
        await uow.commit()
    got = await uow.findings.get_by_id(str(sample_finding.id))
    assert got is not None
    assert got.title == sample_finding.title


@pytest.mark.asyncio
async def test_json_storage(tmp_path, sample_finding) -> None:
    backend = JsonFileStorageBackend(str(tmp_path / "f.json"))
    await backend.initialize()
    await backend.persist_finding(sample_finding)
    health = await backend.health()
    assert health.state == "healthy"


@pytest.mark.asyncio
async def test_s3_storage(tmp_path, sample_finding) -> None:
    backend = S3StorageBackend(str(tmp_path / "s3"))
    await backend.initialize()
    await backend.persist_finding(sample_finding)
    assert (tmp_path / "s3" / f"{sample_finding.id.value}.json").exists()


def test_opsec_profile_frozen() -> None:
    p = OpsecProfile(name="darkweb", proxy="socks5h://127.0.0.1:9050")
    assert p.proxy.startswith("socks5")
