"""Unit tests for detection, scoring, correlation, dedup and enrichment."""

from __future__ import annotations

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.core.domain.watchlist import Keyword, ThreatActor, Watchlist
from threat_hunting.infrastructure.config.settings import ScoringWeights
from threat_hunting.infrastructure.correlation.engine import CorrelationEngine
from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.detections.rules import KeywordRule, RegexRule
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.scoring.engine import WeightedScoringEngine


def _watchlist() -> Watchlist:
    return Watchlist(
        name="wl",
        keywords=[Keyword(term="leak", weight=15.0)],
        actors=[ThreatActor(name="LockBit3", weight=30.0)],
    )


def test_detection_matches_rules_and_watchlists() -> None:
    engine = DetectionEngine(
        rules=[KeywordRule("kw", ["dump"], 10.0), RegexRule("rx", r"\bleak\b", 10.0)],
        watchlists=[_watchlist()],
    )
    finding = Finding(
        title="t", source="s", connector="c",
        normalized_data={"text": "big leak dump by LockBit3"},
    )
    engine.detect(finding)
    assert engine.matches(finding)
    detection = finding.metadata["detection"]
    assert detection["actors"] == ["LockBit3"]
    assert detection["match_count"] >= 3


def test_detection_whitelist_suppresses() -> None:
    engine = DetectionEngine(
        rules=[KeywordRule("kw", ["leak"], 10.0)],
        whitelist=[r"training material"],
    )
    finding = Finding(
        title="t", source="s", connector="c",
        normalized_data={"text": "leak in training material sample"},
    )
    engine.detect(finding)
    assert engine.matches(finding) is False
    assert finding.metadata["detection"]["whitelisted"] is True


def test_detection_blacklist_forces_match() -> None:
    engine = DetectionEngine(rules=[], blacklist=[r"ransomware-as-a-service"])
    finding = Finding(
        title="t", source="s", connector="c",
        normalized_data={"text": "offering ransomware-as-a-service"},
    )
    engine.detect(finding)
    assert engine.matches(finding)
    assert finding.metadata["detection"]["blacklisted"] is True


def test_scoring_is_explainable_and_capped(leak_finding: Finding) -> None:
    leak_finding.metadata["detection"] = {
        "rules": [{"id": "r"}], "keywords": ["leak"], "vips": [], "actors": ["LockBit3"],
        "brands": [], "blacklisted": False,
    }
    WeightedScoringEngine(ScoringWeights()).score(leak_finding)
    contributions = leak_finding.metadata["scoring"]["contributions"]
    assert leak_finding.score >= 80.0
    assert leak_finding.severity.value in ("high", "critical")
    assert "threat_actor" in contributions
    assert "credential" in contributions


def test_correlation_links_shared_indicator() -> None:
    shared = Indicator(type=IndicatorType.IPV4, value="9.9.9.9")
    a = Finding(title="a", source="s", connector="c", indicators=[shared])
    b = Finding(title="b", source="s", connector="c",
                indicators=[Indicator(type=IndicatorType.IPV4, value="9.9.9.9")])
    CorrelationEngine().correlate(b, [a])
    assert b.relationships
    assert b.relationships[0].target_ref == a.id


def test_deduplication_detects_exact_and_similar() -> None:
    engine = DeduplicationEngine(similarity_threshold=0.8)
    f1 = Finding(title="Leak", source="s", connector="c",
                 normalized_data={"text": "acme corp database leak dump exposed"})
    assert engine.is_duplicate(f1, []) is False
    engine.register(f1)
    f2 = Finding(title="Leak", source="s", connector="c",
                 normalized_data={"text": "acme corp database leak dump exposed"})
    assert engine.is_duplicate(f2, []) is True


def test_deduplication_strong_ioc_identity() -> None:
    engine = DeduplicationEngine()
    card = Indicator(type=IndicatorType.CREDIT_CARD, value="4111111111111111")
    f1 = Finding(title="a", source="s", connector="c", indicators=[card])
    engine.register(f1)
    f2 = Finding(title="totally different text here", source="s", connector="c",
                 indicators=[Indicator(type=IndicatorType.CREDIT_CARD, value="4111111111111111")])
    assert engine.is_duplicate(f2, []) is True


def test_enrichment_defangs_and_tags() -> None:
    finding = Finding(title="t", source="s", connector="c")
    finding.add_indicator(Indicator(type=IndicatorType.URL, value="http://evil.com/x"))
    finding.add_indicator(Indicator(type=IndicatorType.CPF, value="529.982.247-25"))
    EnrichmentEngine().enrich(finding)
    url = next(i for i in finding.indicators if i.type is IndicatorType.URL)
    assert url.defanged is True
    assert "hxxp" in url.context["defanged"]
    assert "br-fraud" in finding.tags
