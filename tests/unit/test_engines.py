"""Unit tests — detection, scoring, correlation, dedup, enrichment, extractor."""

from __future__ import annotations

import pytest

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import FindingCategory, IndicatorType
from threat_hunting.core.domain.services import FindingBuilder
from threat_hunting.core.domain.value_objects import Indicator
from threat_hunting.correlation.engine import CorrelationEngine
from threat_hunting.deduplication.engine import DeduplicationEngine
from threat_hunting.detections.engine import DetectionEngine
from threat_hunting.enrichment.engine import EnrichmentEngine
from threat_hunting.extractors.ioc_extractor import IocExtractor
from threat_hunting.scoring.engine import ScoringEngine


@pytest.mark.asyncio
async def test_detection_engine_matches(sample_finding: Finding, detection_engine: DetectionEngine) -> None:
    matches = await detection_engine.detect(sample_finding)
    assert matches
    assert any(m.matched for m in matches)
    assert any(m.rule_type == "keyword" for m in matches)


@pytest.mark.asyncio
async def test_detection_reload(detection_engine: DetectionEngine) -> None:
    count = await detection_engine.reload_rules()
    assert count >= 5


@pytest.mark.asyncio
async def test_scoring_engine(sample_finding: Finding, scoring_engine: ScoringEngine, detection_engine: DetectionEngine) -> None:
    matches = await detection_engine.detect(sample_finding)
    for m in matches:
        sample_finding.apply_detection(m)
    scored = await scoring_engine.score(sample_finding)
    assert float(scored.score) > 0
    assert "score_breakdown" in scored.normalized_data


@pytest.mark.asyncio
async def test_correlation_links_shared_ioc() -> None:
    engine = CorrelationEngine()
    a = (
        FindingBuilder()
        .with_title("A")
        .with_source("s")
        .with_connector("c")
        .build()
    )
    a.add_indicator(Indicator(type=IndicatorType.IP, value="10.0.0.1"))
    await engine.correlate(a)

    b = (
        FindingBuilder()
        .with_title("B")
        .with_source("s")
        .with_connector("c")
        .build()
    )
    b.add_indicator(Indicator(type=IndicatorType.IP, value="10.0.0.1"))
    b = await engine.correlate(b)
    assert any(r.target_id == str(a.id) for r in b.relationships)


@pytest.mark.asyncio
async def test_deduplication_by_hash() -> None:
    engine = DeduplicationEngine(similarity_threshold=0.99)
    a = (
        FindingBuilder()
        .with_title("Same Title Exact")
        .with_description("Same body")
        .with_source("s")
        .with_connector("c")
        .build()
    )
    b = (
        FindingBuilder()
        .with_title("Same Title Exact")
        .with_description("Same body")
        .with_source("s")
        .with_connector("c")
        .build()
    )
    # Force same content hash
    b.content_hash = a.content_hash
    await engine.deduplicate(a)
    b = await engine.deduplicate(b)
    assert b.is_duplicate
    assert b.duplicate_of == str(a.id)


@pytest.mark.asyncio
async def test_deduplication_by_strong_ioc() -> None:
    engine = DeduplicationEngine()
    a = FindingBuilder().with_title("A1").with_source("s").with_connector("c").build()
    a.add_indicator(Indicator(type=IndicatorType.EMAIL, value="dup@test.com"))
    await engine.deduplicate(a)
    b = FindingBuilder().with_title("Different").with_source("s").with_connector("c").build()
    b.add_indicator(Indicator(type=IndicatorType.EMAIL, value="dup@test.com"))
    b = await engine.deduplicate(b)
    assert b.is_duplicate


@pytest.mark.asyncio
async def test_enrichment_adds_context(sample_finding: Finding) -> None:
    engine = EnrichmentEngine()
    enriched = await engine.enrich(sample_finding)
    assert "enrichment" in enriched.normalized_data
    assert any(t.name.startswith("ioc:") for t in enriched.tags)


@pytest.mark.asyncio
async def test_ioc_extractor() -> None:
    extractor = IocExtractor()
    entities = await extractor.extract(
        {
            "title": "Leak",
            "description": "user@corp.com 8.8.8.8 https://evil.example/path "
            "d41d8cd98f00b204e9800998ecf8427e CVE-2024-1234",
        }
    )
    types = {i["type"] for i in entities["indicators"]}
    assert "email" in types
    assert "ip" in types
    assert "url" in types or "domain" in types


@pytest.mark.asyncio
async def test_luhn_card_filter() -> None:
    extractor = IocExtractor(extract_cards=True)
    # Valid Visa test number
    entities = await extractor.extract(
        {"content": "card 4111111111111111 invalid 1234567890123"}
    )
    cards = [i for i in entities["indicators"] if i["type"] == "card"]
    assert any("4111111111111111" in c["value"].replace(" ", "") for c in cards)
