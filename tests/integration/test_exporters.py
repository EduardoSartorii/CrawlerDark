"""Integration tests for exporters and the export use case."""

from __future__ import annotations

import json

from threat_hunting.core.application.use_cases.export_findings import (
    ExportFindingsUseCase,
)
from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.infrastructure.exporters.csv_exporter import CsvExporter
from threat_hunting.infrastructure.exporters.json_exporter import JsonExporter
from threat_hunting.infrastructure.exporters.misp_exporter import MispExporter
from threat_hunting.infrastructure.exporters.stix_exporter import StixExporter
from threat_hunting.infrastructure.storage.memory_repo import InMemoryUnitOfWork


def _finding() -> Finding:
    f = Finding(title="Leak", source="s", connector="c")
    f.add_indicator(Indicator(type=IndicatorType.IPV4, value="1.2.3.4"))
    f.add_indicator(Indicator(type=IndicatorType.DOMAIN, value="evil.com"))
    f.set_score(95)
    return f


def test_json_and_csv_exporters(tmp_path) -> None:
    findings = [_finding()]
    assert JsonExporter(tmp_path).export(findings) == 1
    assert CsvExporter(tmp_path).export(findings) == 1
    payload = json.loads((tmp_path / "findings.json").read_text())
    assert payload[0]["title"] == "Leak"
    assert (tmp_path / "findings.csv").read_text().count("\n") == 2  # header + row


def test_stix_bundle_is_valid_shape(tmp_path) -> None:
    StixExporter(tmp_path).export([_finding()])
    bundle = json.loads((tmp_path / "findings.stix.json").read_text())
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert {"indicator", "report"} <= types


def test_misp_dry_run_when_unconfigured(tmp_path) -> None:
    exporter = MispExporter(output_dir=tmp_path)  # no url/key -> dry run
    assert exporter.supports_auto_export() is True
    assert exporter.export([_finding()]) == 1
    events = json.loads((tmp_path / "misp_events.json").read_text())
    assert events[0]["info"] == "Leak"
    assert any(a["type"] == "ip-dst" for a in events[0]["Attribute"])


def test_export_use_case_filters_by_score(tmp_path) -> None:
    uow = InMemoryUnitOfWork()
    low = Finding(title="low", source="s", connector="c")
    low.set_score(10)
    with uow:
        uow.findings.add(low)
        uow.findings.add(_finding())
    use_case = ExportFindingsUseCase(uow=uow, exporters={"json": JsonExporter(tmp_path)})
    assert "json" in use_case.available()
    assert use_case.export("json", min_score=90) == 1
