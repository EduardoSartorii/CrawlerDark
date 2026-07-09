"""Unit tests for exporters."""

import pytest

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import SourceType
from threat_hunting.infrastructure.exporters.base import JsonExporter, CsvExporter, StixExporter, MispExporter


@pytest.fixture
def findings():
    return [
        Finding(title="Test 1", source=SourceType.API, connector="test", score=50.0),
        Finding(title="Test 2", source=SourceType.DARKWEB, connector="darkweb", score=80.0),
    ]


@pytest.mark.asyncio
async def test_json_export(findings):
    exporter = JsonExporter()
    result = await exporter.export(findings)
    assert result["count"] == 2
    assert len(result["data"]) == 2


@pytest.mark.asyncio
async def test_csv_export(findings):
    exporter = CsvExporter()
    result = await exporter.export(findings)
    assert result["count"] == 2
    assert "Test 1" in result["data"]


@pytest.mark.asyncio
async def test_stix_export(findings):
    exporter = StixExporter()
    result = await exporter.export(findings)
    assert result["bundle"]["type"] == "bundle"
    assert len(result["bundle"]["objects"]) == 2


@pytest.mark.asyncio
async def test_misp_export_simulated(findings):
    exporter = MispExporter()
    result = await exporter.export(findings)
    assert result["count"] == 2
