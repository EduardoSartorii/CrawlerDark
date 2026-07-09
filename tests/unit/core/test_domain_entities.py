"""
Unit Tests — Domain Entities
==============================

Tests for core domain entity invariants and business rules.
No infrastructure dependencies — pure Python tests.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from threat_hunting.core.domain.entities.finding import Finding, FindingStatus, DetectionResult
from threat_hunting.core.domain.entities.indicator import Indicator
from threat_hunting.core.domain.entities.keyword import Keyword, KeywordType
from threat_hunting.core.domain.entities.rule import Rule, RuleType
from threat_hunting.core.domain.entities.vip import VIP, VIPType
from threat_hunting.core.domain.entities.threat_actor import ThreatActor
from threat_hunting.core.domain.value_objects.category import Category
from threat_hunting.core.domain.value_objects.indicator_type import IndicatorType
from threat_hunting.core.domain.value_objects.score import Score
from threat_hunting.core.domain.value_objects.severity import Severity
from threat_hunting.core.domain.value_objects.source import SourceType


class TestScore:
    """Tests for the Score value object."""

    def test_zero_score(self):
        s = Score.zero()
        assert s.value == 0.0
        assert s.confidence == 0.0
        assert not s.is_scored

    def test_valid_score(self):
        s = Score.from_raw(7.5, 0.9)
        assert s.value == 7.5
        assert s.confidence == 0.9
        assert s.is_scored

    def test_score_clamping(self):
        s = Score.from_raw(15.0, 2.0)
        assert s.value == 10.0
        assert s.confidence == 1.0

    def test_score_addition(self):
        s1 = Score.from_raw(3.0, 0.8)
        s2 = Score.from_raw(4.0, 0.6)
        combined = s1 + s2
        assert combined.value == 7.0
        assert combined.confidence == 0.7

    def test_score_addition_clamped_at_10(self):
        s1 = Score.from_raw(8.0, 1.0)
        s2 = Score.from_raw(5.0, 1.0)
        combined = s1 + s2
        assert combined.value == 10.0

    def test_invalid_score_raises(self):
        with pytest.raises(ValueError):
            Score(value=11.0)
        with pytest.raises(ValueError):
            Score(value=5.0, confidence=1.5)

    def test_score_ordering(self):
        low = Score.from_raw(2.0)
        high = Score.from_raw(8.0)
        assert low < high
        assert high > low

    def test_weighted_score(self):
        s = Score.from_raw(4.0, 1.0)
        weighted = s.weighted(1.5)
        assert weighted.value == 6.0


class TestSeverity:
    """Tests for the Severity value object."""

    def test_severity_from_score(self):
        assert Severity.from_score(9.0) == Severity.CRITICAL
        assert Severity.from_score(7.0) == Severity.HIGH
        assert Severity.from_score(5.0) == Severity.MEDIUM
        assert Severity.from_score(3.0) == Severity.LOW
        assert Severity.from_score(0.0) == Severity.INFO

    def test_severity_ordering(self):
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_severity_numeric(self):
        assert Severity.CRITICAL.numeric == 4
        assert Severity.INFO.numeric == 0

    def test_custom_thresholds(self):
        s = Severity.from_score(7.5, critical=8.0, high=6.0)
        assert s == Severity.HIGH


class TestFinding:
    """Tests for the Finding aggregate root."""

    def test_finding_creation(self, sample_finding: Finding):
        assert sample_finding.id
        assert sample_finding.title
        assert sample_finding.source == SourceType.PASTE
        assert sample_finding.connector == "paste"
        assert sample_finding.status == FindingStatus.NORMALIZED
        assert len(sample_finding.timeline) >= 1

    def test_set_score_derives_severity(self, sample_finding: Finding):
        sample_finding.set_score(Score.from_raw(8.5, 0.9))
        assert sample_finding.score.value == 8.5
        assert sample_finding.severity == Severity.CRITICAL
        assert sample_finding.confidence == 0.9

    def test_add_tag_deduplicates(self, sample_finding: Finding):
        sample_finding.add_tag("malware")
        sample_finding.add_tag("malware")
        sample_finding.add_tag("MALWARE")
        assert sample_finding.tags.count("malware") == 1

    def test_add_tag_normalizes(self, sample_finding: Finding):
        sample_finding.add_tag("Threat Actor")
        assert "threat_actor" in sample_finding.tags

    def test_advance_status(self, sample_finding: Finding):
        sample_finding.advance_status(FindingStatus.DETECTED)
        assert sample_finding.status == FindingStatus.DETECTED
        timeline_events = [t.event for t in sample_finding.timeline]
        assert "status_detected" in timeline_events

    def test_mark_duplicate(self, sample_finding: Finding):
        sample_finding.mark_duplicate("original-id-123")
        assert sample_finding.is_duplicate
        assert sample_finding.duplicate_of == "original-id-123"
        assert sample_finding.status == FindingStatus.DEDUPLICATED

    def test_mark_false_positive(self, sample_finding: Finding):
        sample_finding.mark_false_positive("Not matching our scope")
        assert sample_finding.status == FindingStatus.FALSE_POSITIVE

    def test_add_detection_result(self, sample_finding: Finding):
        result = DetectionResult(
            rule_id="rule-001",
            rule_name="Test Rule",
            rule_type=RuleType.REGEX.value,
            confidence=0.95,
        )
        sample_finding.add_detection(result)
        assert len(sample_finding.detection_results) == 1
        assert "Test Rule" in sample_finding.matched_rules

    def test_record_export(self, sample_finding: Finding):
        sample_finding.record_export("misp")
        assert "misp" in sample_finding.export_log
        assert sample_finding.is_exported

    def test_add_indicator(self, sample_finding: Finding):
        sample_finding.add_indicator("indicator-id-001")
        sample_finding.add_indicator("indicator-id-001")  # Should not duplicate
        assert sample_finding.indicators.count("indicator-id-001") == 1
        assert sample_finding.has_iocs


class TestIndicator:
    """Tests for the Indicator entity."""

    def test_indicator_creation(self):
        ind = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        assert ind.type == IndicatorType.IP
        assert ind.value == "1.2.3.4"
        assert ind.id

    def test_indicator_value_normalized(self):
        ind = Indicator(type=IndicatorType.EMAIL, value="TEST@EXAMPLE.COM")
        assert ind.value == "test@example.com"

    def test_indicator_unique_key(self):
        ind = Indicator(type=IndicatorType.DOMAIN, value="malicious.com")
        assert ind.unique_key == "domain:malicious.com"

    def test_indicator_equality(self):
        ind1 = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ind2 = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        assert ind1 == ind2

    def test_indicator_inequality_different_type(self):
        ind1 = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ind2 = Indicator(type=IndicatorType.DOMAIN, value="1.2.3.4")
        assert ind1 != ind2

    def test_add_source(self, sample_indicator: Indicator):
        sample_indicator.add_source("reddit")
        sample_indicator.add_source("reddit")  # Should not duplicate
        assert sample_indicator.sources.count("reddit") == 1

    def test_merge_enrichment(self, sample_indicator: Indicator):
        sample_indicator.merge_enrichment({"country": "US", "asn": "AS12345"})
        assert sample_indicator.enrichment.country == "US"
        assert sample_indicator.enrichment.asn == "AS12345"

    def test_merge_enrichment_does_not_overwrite(self, sample_indicator: Indicator):
        sample_indicator.merge_enrichment({"country": "US"})
        sample_indicator.merge_enrichment({"country": "BR"})  # Should not overwrite
        assert sample_indicator.enrichment.country == "US"

    def test_empty_value_raises(self):
        with pytest.raises(Exception):
            Indicator(type=IndicatorType.IP, value="")


class TestVIP:
    """Tests for the VIP entity."""

    def test_vip_creation(self, sample_vip: VIP):
        assert sample_vip.name == "John CEO"
        assert sample_vip.is_enabled

    def test_vip_matches_text(self, sample_vip: VIP):
        assert sample_vip.matches_text("CEO John Smith was mentioned")
        assert sample_vip.matches_text("email found: john.ceo@acme.com")
        assert sample_vip.matches_text("acme.com domain leaked")
        assert not sample_vip.matches_text("unrelated content here")

    def test_all_identifiers(self, sample_vip: VIP):
        ids = sample_vip.all_identifiers
        assert "john ceo" in ids
        assert "john.ceo@acme.com" in ids
        assert "john smith" in ids
        assert "acme.com" in ids

    def test_record_match(self, sample_vip: VIP):
        sample_vip.record_match()
        assert sample_vip.match_count == 1
        assert sample_vip.last_match is not None


class TestThreatActor:
    """Tests for the ThreatActor entity."""

    def test_actor_creation(self, sample_threat_actor: ThreatActor):
        assert sample_threat_actor.name == "LazarusGroup"
        assert "Hidden Cobra" in sample_threat_actor.aliases

    def test_actor_matches_text(self, sample_threat_actor: ThreatActor):
        assert sample_threat_actor.matches("The LazarusGroup was attributed to this attack")
        assert sample_threat_actor.matches("hidden cobra infrastructure identified")
        assert not sample_threat_actor.matches("unrelated threat actor here")

    def test_all_names(self, sample_threat_actor: ThreatActor):
        names = sample_threat_actor.all_names
        assert "lazarusgroup" in names
        assert "hidden cobra" in names
        assert "apt38" in names


class TestKeyword:
    """Tests for the Keyword entity."""

    def test_keyword_creation(self, sample_keyword: Keyword):
        assert sample_keyword.value == "credential leak"
        assert sample_keyword.is_enabled

    def test_normalized_value_case_insensitive(self, sample_keyword: Keyword):
        assert sample_keyword.normalized_value == "credential leak"

    def test_record_match(self, sample_keyword: Keyword):
        sample_keyword.record_match()
        sample_keyword.record_match()
        assert sample_keyword.match_count == 2
        assert sample_keyword.last_match is not None


class TestRule:
    """Tests for the Rule entity."""

    def test_rule_creation(self, sample_rule: Rule):
        assert sample_rule.name == "CPF Detection"
        assert sample_rule.type == RuleType.REGEX
        assert sample_rule.is_enabled

    def test_precision_no_matches(self, sample_rule: Rule):
        assert sample_rule.precision == 1.0

    def test_precision_with_fp(self, sample_rule: Rule):
        sample_rule.record_match(is_false_positive=False)
        sample_rule.record_match(is_false_positive=False)
        sample_rule.record_match(is_false_positive=True)
        assert sample_rule.precision == pytest.approx(2 / 3)
