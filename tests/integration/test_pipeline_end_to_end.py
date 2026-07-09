"""Integration tests exercising the full pipeline through the DI container."""

from __future__ import annotations

from threat_hunting.config.container import Container
from threat_hunting.config.settings import (
    ExportSettings,
    OpsecSettings,
    Settings,
    StorageSettings,
)
from threat_hunting.core.domain.enums import EventName


def _memory_container(**export_kwargs) -> Container:
    settings = Settings(
        storage=StorageSettings(backend="memory"),
        opsec=OpsecSettings(offline=True),
        export=ExportSettings(**export_kwargs) if export_kwargs else ExportSettings(),
        watchlists_file="config/watchlists.yml",
    )
    return Container(settings)


def test_full_run_collects_scores_and_persists():
    container = _memory_container()
    summary = container.run_collection_service.run("sample_paste")

    assert summary.findings_collected == 3  # one near-duplicate removed
    assert summary.findings_persisted == 3
    assert summary.duplicates_removed == 1
    assert summary.high_severity >= 1
    assert summary.errors == []

    with container.unit_of_work as uow:
        findings = list(uow.findings.list())
    assert len(findings) == 3
    # The leak/card findings must carry indicators and a score.
    scored = [f for f in findings if f.score.value > 0]
    assert scored
    assert all(f.timeline for f in findings)


def test_detection_applies_watchlist_and_actor():
    container = _memory_container()
    container.run_collection_service.run("sample_paste")
    with container.unit_of_work as uow:
        findings = list(uow.findings.list())
    rule_types = {m.rule_type for f in findings for m in f.detections}
    assert "keyword" in rule_types      # brand/leak keywords from watchlists.yml
    assert "threat_actor" in rule_types  # LockBit
    assert "ioc" in rule_types


def test_auto_export_on_threshold_reaches_misp():
    container = _memory_container(
        auto_export_enabled=True, auto_export_target="misp", score_threshold=60.0
    )
    container.run_collection_service.run("sample_paste")
    handlers = container.event_bus._handlers[EventName.HIGH_SEVERITY_FINDING_DETECTED]
    assert handlers, "auto-export subscriber should be registered"
    subscriber = handlers[0]
    assert subscriber.exported >= 1
    # dry-run MISP payloads captured (no live server needed)
    assert subscriber._exporter.dry_run_events


def test_run_group_and_all_do_not_error():
    container = _memory_container()
    group_summary = container.run_collection_service.run("leak")
    assert "sample_paste" in group_summary.connectors
    all_summary = container.run_collection_service.run("all")
    assert all_summary.errors == []


def test_export_service_writes_json(tmp_path):
    container = _memory_container()
    container.run_collection_service.run("sample_paste")
    exporter_path = tmp_path / "out.json"
    from threat_hunting.infrastructure.exporters.json_exporter import JsonExporter
    from threat_hunting.core.application.services.export_service import ExportService

    service = ExportService(container.unit_of_work, {"json": JsonExporter(str(exporter_path))})
    result = service.export("json", min_score=0.0)
    assert result.exported == 3
    assert exporter_path.exists()
