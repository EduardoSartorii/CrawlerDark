"""Unit tests for exporters and the exporter factory."""

from __future__ import annotations

import json

import pytest

from threat_hunting.core.application.ports.transport import TransportResponse
from threat_hunting.core.domain.entities.finding import FindingBuilder
from threat_hunting.core.domain.enums import IndicatorType, Severity
from threat_hunting.core.domain.exceptions import ExportError
from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.core.domain.value_objects.score import Score
from threat_hunting.infrastructure.exporters.csv_exporter import CsvExporter
from threat_hunting.infrastructure.exporters.factory import ExporterFactory
from threat_hunting.infrastructure.exporters.json_exporter import JsonExporter
from threat_hunting.infrastructure.exporters.misp_exporter import MispExporter
from threat_hunting.infrastructure.exporters.stix_exporter import StixExporter
from threat_hunting.infrastructure.exporters.webhook_exporter import WebhookExporter


def _finding():
    finding = (
        FindingBuilder("Leak", "sample_paste", "s")
        .add_indicator(Indicator(type=IndicatorType.IPV4, value="1.2.3.4"))
        .add_indicator(Indicator(type=IndicatorType.SHA256, value="a" * 64))
        .add_tag("leak")
        .build()
    )
    finding.set_score(Score.zero().with_component("k", 90))
    return finding


def test_json_exporter(tmp_path):
    path = tmp_path / "f.json"
    result = JsonExporter(str(path)).export([_finding()])
    assert result.exported == 1
    data = json.loads(path.read_text())
    assert len(data["findings"]) == 1


def test_csv_exporter(tmp_path):
    path = tmp_path / "f.csv"
    result = CsvExporter(str(path)).export([_finding()])
    assert result.exported == 1
    content = path.read_text()
    assert "severity" in content and "critical" in content


def test_stix_exporter_builds_bundle(tmp_path):
    path = tmp_path / "f.stix.json"
    result = StixExporter(str(path)).export([_finding()])
    bundle = json.loads(path.read_text())
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert "indicator" in types and "report" in types
    assert result.exported == 1


def test_misp_exporter_dry_run():
    exporter = MispExporter()  # no url/key -> dry-run
    result = exporter.export([_finding()])
    assert result.detail == "mode=dry-run"
    assert exporter.dry_run_events
    assert exporter.dry_run_events[0]["attributes"]


class _FakeTransport:
    def __init__(self, ok=True):
        self._ok = ok

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def request(self, method, url, **kwargs):
        return TransportResponse(status_code=200 if self._ok else 500, url=url)


def test_webhook_exporter_posts():
    result = WebhookExporter("http://sink", transport=_FakeTransport(ok=True)).export([_finding()])
    assert result.exported == 1


def test_webhook_without_transport_is_safe():
    result = WebhookExporter("http://sink").export([_finding()])
    assert result.exported == 0


def test_factory_builds_and_rejects_unknown():
    assert isinstance(ExporterFactory.build("json"), JsonExporter)
    assert "misp" in ExporterFactory.available()
    with pytest.raises(ExportError):
        ExporterFactory.build("unknown")
