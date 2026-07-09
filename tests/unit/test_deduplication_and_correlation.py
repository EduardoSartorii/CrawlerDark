"""Testes de dedup e correlação."""

from __future__ import annotations

from threat_hunting.core.domain.builders import FindingBuilder
from threat_hunting.core.domain.entities import Indicator
from threat_hunting.core.domain.value_objects import IndicatorType, SourceRef
from threat_hunting.infrastructure.correlation import GraphCorrelationEngine
from threat_hunting.infrastructure.deduplication import HashDeduplicationEngine
from threat_hunting.infrastructure.normalizers import CanonicalNormalizer


async def _f(title, indicators=()):
    f = (
        FindingBuilder()
        .title(title)
        .description(title)
        .source(SourceRef(source="s", connector="ut"))
        .build()
    )
    for i in indicators:
        f.add_indicator(i)
    return await CanonicalNormalizer().normalize(f)


class TestHashDedup:
    async def test_identical_hash_is_duplicate(self):
        f1 = await _f("news alert about ransomware")
        f2 = await _f("news alert about ransomware")
        engine = HashDeduplicationEngine()
        _, dup = await engine.deduplicate(f2, [f1])
        assert dup is True

    async def test_different_titles_are_not_duplicates(self):
        f1 = await _f("news alert about ransomware ABC")
        f2 = await _f("completely different content XYZ")
        engine = HashDeduplicationEngine(similarity_threshold=0.9)
        _, dup = await engine.deduplicate(f2, [f1])
        assert dup is False


class TestGraphCorrelation:
    async def test_shared_indicator_creates_relationship(self):
        shared = Indicator(type=IndicatorType.DOMAIN, value="malicious.example")
        f1 = await _f("first finding", [shared])
        f2 = await _f("second finding", [Indicator(type=IndicatorType.DOMAIN, value="malicious.example")])
        engine = GraphCorrelationEngine()
        f2 = await engine.correlate(f2, [f1])
        assert len(f2.relationships) == 1
        assert f2.relationships[0].target_id == f1.id
