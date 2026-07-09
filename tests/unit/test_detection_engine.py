"""Unit tests for the detection engine and rule strategies."""

from __future__ import annotations

from threat_hunting.core.domain.entities.finding import FindingBuilder
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.infrastructure.detections.rules import (
    HeuristicRule,
    IocMatchRule,
    KeywordRule,
    RegexRule,
    ThreatActorRule,
)
from threat_hunting.infrastructure.normalizers.finding_normalizer import FindingNormalizer


def _normalized(title="ACME Corp fullz", text="database dump admin@acme.com:secret LockBit"):
    finding = FindingBuilder(title, "c", "s").description(text).build()
    return FindingNormalizer().normalize(finding)


def test_regex_rule_matches():
    finding = _normalized(text="token AKIAABCDEFGHIJKLMNOP here")
    rule = RegexRule("aws", r"AKIA[0-9A-Z]{16}", weight=30)
    matches = rule.evaluate(finding)
    assert matches and matches[0].weight == 30


def test_keyword_rule_matches(watchlists):
    finding = _normalized()
    rule = KeywordRule("wl", watchlists)
    matched_terms = {m.matched for m in rule.evaluate(finding)}
    assert "ACME Corp" in matched_terms
    assert "fullz" in matched_terms


def test_threat_actor_rule_matches(threat_actors):
    finding = _normalized()
    rule = ThreatActorRule("actor", threat_actors)
    matches = rule.evaluate(finding)
    assert matches and matches[0].matched == "LockBit"


def test_ioc_rule_weights_by_type():
    finding = FindingBuilder("t", "c", "s").build()
    finding.add_indicator(Indicator(type=IndicatorType.CREDIT_CARD, value="4111111111111111"))
    matches = IocMatchRule().evaluate(finding)
    assert matches[0].weight == 25.0


def test_heuristic_rule_requires_both_signals():
    hit = _normalized(text="database dump admin@acme.com:secret")
    miss = _normalized(text="just a normal blog post about cats")
    assert HeuristicRule().evaluate(hit)
    assert not HeuristicRule().evaluate(miss)


def test_engine_whitelist_suppresses():
    finding = _normalized(text="this is a drill, database dump admin@x.com:pw")
    engine = DetectionEngine([HeuristicRule()], whitelist=["this is a drill"])
    assert engine.evaluate(finding) == []
    assert "whitelisted" in finding.tags


def test_engine_blacklist_flags():
    finding = _normalized(text="ransomware-as-a-service offering")
    engine = DetectionEngine([], blacklist=["ransomware-as-a-service"])
    matches = engine.evaluate(finding)
    assert any(m.rule_type == "blacklist" for m in matches)


def test_engine_min_matches_threshold():
    finding = _normalized(text="nothing interesting here")
    engine = DetectionEngine([IocMatchRule()], min_matches=2)
    assert engine.evaluate(finding) == []
