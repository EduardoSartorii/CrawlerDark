"""Testes dos exporters locais (JSON, CSV, STIX)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from threat_hunting.core.domain.builders import FindingBuilder
from threat_hunting.core.domain.entities import Indicator
from threat_hunting.core.domain.value_objects import (
    Category,
    IndicatorType,
    Severity,
    SourceRef,
)
from threat_hunting.infrastructure.exporters import (
    CSVExporter,
    JSONExporter,
    STIXExporter,
)


def _sample():
    src = SourceRef(source="s", connector="ut", url="https://x.example/leak/1")
    f = (
        FindingBuilder()
        .title("Leak: evil.example c2")
        .description("Bad")
        .source(src)
        .category(Category.IOC)
        .severity(Severity.HIGH)
        .score(90)
        .tag("phishing")
        .build()
    )
    f.add_indicator(Indicator(type=IndicatorType.DOMAIN, value="evil.example"))
    f.add_indicator(Indicator(type=IndicatorType.IP, value="8.8.8.8"))
    return f


@pytest.mark.asyncio
async def test_json_exporter(tmp_path: Path):
    exporter = JSONExporter(path=str(tmp_path))
    n = await exporter.export([_sample()])
    assert n == 1
    files = list(tmp_path.rglob("*.json"))
    assert files
    data = json.loads(files[0].read_text(encoding="utf-8"))
    assert data["title"].startswith("Leak")
    assert len(data["indicators"]) == 2


@pytest.mark.asyncio
async def test_csv_exporter(tmp_path: Path):
    exporter = CSVExporter(path=str(tmp_path))
    n = await exporter.export([_sample()])
    assert n == 1
    files = list(tmp_path.glob("*.csv"))
    content = files[0].read_text(encoding="utf-8")
    assert "Leak: evil.example c2" in content
    assert "DOMAIN:evil.example" in content


@pytest.mark.asyncio
async def test_stix_exporter(tmp_path: Path):
    exporter = STIXExporter(path=str(tmp_path))
    n = await exporter.export([_sample()])
    assert n == 1
    files = list(tmp_path.glob("*.json"))
    bundle = json.loads(files[0].read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"
    types = {o["type"] for o in bundle["objects"]}
    assert "report" in types
    assert "indicator" in types
