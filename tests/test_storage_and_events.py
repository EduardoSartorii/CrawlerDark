"""Storage and event bus tests."""

from __future__ import annotations

from pathlib import Path

from threat_hunting.core.application.event_bus import InMemoryEventBus
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.events import FindingCollected
from threat_hunting.storage.backends import StorageBackend
from threat_hunting.storage.json_repository import JsonUnitOfWork


def test_json_unit_of_work_persists_findings(tmp_path: Path) -> None:
    """JSON storage should persist and reload canonical findings."""

    path = tmp_path / "findings.json"
    finding = Finding(title="Leak", description="data", source="rss", connector="rss", category="news")
    with JsonUnitOfWork(path) as uow:
        uow.findings.save(finding)

    with JsonUnitOfWork(path) as uow:
        loaded = uow.findings.get(finding.id)

    assert loaded == finding


def test_event_bus_notifies_specific_and_wildcard_handlers() -> None:
    """Event bus should implement observer behavior."""

    bus = InMemoryEventBus()
    received: list[str] = []
    finding = Finding(title="Leak", description="data", source="rss", connector="rss", category="news")

    bus.subscribe("finding.collected", lambda event: received.append(event.name))
    bus.subscribe("*", lambda event: received.append(str(event.payload["finding_id"])))
    bus.publish(FindingCollected.from_finding(finding))

    assert received == ["finding.collected", str(finding.id)]


def test_storage_backend_contract_lists_required_targets() -> None:
    """Storage backend contract should name required production targets."""

    assert {backend.value for backend in StorageBackend} >= {
        "sqlite",
        "postgresql",
        "opensearch",
        "elasticsearch",
        "splunk",
        "json",
        "parquet",
        "data_lake",
        "s3",
    }
