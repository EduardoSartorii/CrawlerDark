"""
Unit tests for the Detection Engine.

Tests cover:
    - Regex rule evaluation
    - Keyword rule evaluation
    - Whitelist suppression
    - Score contribution calculation
    - Rule filtering by connector/category
    - Batch evaluation
"""

from __future__ import annotations

import pytest

from ....core.domain.entities.rule import DetectionRule, RuleType, RuleAction
from ....core.domain.value_objects import ThreatCategory
from ....infrastructure.detections.engine import DetectionEngine, RegexEvaluator, KeywordEvaluator
from ...fixtures.factories import make_finding, make_detection_rule


class TestRegexEvaluator:
    """Tests for the RegexEvaluator strategy."""

    def test_matches_pattern_in_title(self):
        finding = make_finding(title="Found password: hunter2")
        rule = make_detection_rule(pattern=r"password[:\s]+\w+", rule_type=RuleType.REGEX)
        evaluator = RegexEvaluator()
        result = evaluator.evaluate(rule, finding)
        assert result is not None
        assert result.matched_value != ""

    def test_no_match_returns_none(self):
        finding = make_finding(title="Nothing suspicious here")
        rule = make_detection_rule(pattern=r"BEGIN RSA PRIVATE KEY", rule_type=RuleType.REGEX)
        evaluator = RegexEvaluator()
        result = evaluator.evaluate(rule, finding)
        assert result is None

    def test_case_insensitive_by_default(self):
        finding = make_finding(title="PASSWORD EXPOSED")
        rule = make_detection_rule(pattern=r"password", rule_type=RuleType.REGEX)
        evaluator = RegexEvaluator()
        result = evaluator.evaluate(rule, finding)
        assert result is not None

    def test_invalid_regex_returns_none(self):
        finding = make_finding(title="test")
        rule = make_detection_rule(pattern=r"[invalid(", rule_type=RuleType.REGEX)
        evaluator = RegexEvaluator()
        result = evaluator.evaluate(rule, finding)
        assert result is None


class TestKeywordEvaluator:
    """Tests for the KeywordEvaluator strategy."""

    def test_exact_keyword_match(self):
        finding = make_finding(description="admin:password123 found in paste")
        rule = make_detection_rule(pattern="admin:password", rule_type=RuleType.KEYWORD)
        evaluator = KeywordEvaluator()
        result = evaluator.evaluate(rule, finding)
        assert result is not None

    def test_keyword_no_match(self):
        finding = make_finding(title="regular post")
        rule = make_detection_rule(pattern="secret_key", rule_type=RuleType.KEYWORD)
        evaluator = KeywordEvaluator()
        result = evaluator.evaluate(rule, finding)
        assert result is None


class TestDetectionEngine:
    """Integration tests for the full Detection Engine."""

    def _engine_with_rules(self, rules: list[DetectionRule]) -> DetectionEngine:
        engine = DetectionEngine(rules=rules)
        return engine

    def test_evaluate_applies_score_boost(self):
        finding = make_finding(score_value=3.0, raw_data="CVE-2024-12345 exploit active")
        rule = make_detection_rule(
            name="CVE Detection",
            pattern=r"CVE-\d{4}-\d{4,7}",
            rule_type=RuleType.REGEX,
            score_boost=3.0,
        )
        engine = self._engine_with_rules([rule])
        result = engine.evaluate(finding)
        assert result.has_matches
        assert result.total_score_contribution == pytest.approx(3.0)
        assert finding.score.value > 3.0

    def test_whitelist_rule_suppresses_finding(self):
        finding = make_finding(title="benign activity match")
        rule = DetectionRule(
            name="Whitelist: benign",
            rule_type=RuleType.KEYWORD,
            pattern="benign",
            is_whitelist=True,
            is_active=True,
            score_boost=0.0,
        )
        engine = self._engine_with_rules([rule])
        result = engine.evaluate(finding)
        assert result.suppressed is True

    def test_disabled_rule_not_evaluated(self):
        finding = make_finding(title="password exposed here")
        rule = make_detection_rule(
            pattern="password",
            rule_type=RuleType.KEYWORD,
            is_active=False,
            score_boost=5.0,
        )
        engine = self._engine_with_rules([rule])
        initial_score = finding.score.value
        engine.evaluate(finding)
        # Score should not change since rule is disabled
        assert finding.score.value == pytest.approx(initial_score)

    def test_connector_scoped_rule_only_applies_to_connector(self):
        finding = make_finding(raw_data="test_pattern")
        rule = DetectionRule(
            name="Scoped Rule",
            rule_type=RuleType.KEYWORD,
            pattern="test_pattern",
            applicable_connectors=["other_connector"],
            is_active=True,
            score_boost=5.0,
        )
        engine = self._engine_with_rules([rule])
        initial_score = finding.score.value
        engine.evaluate(finding)
        # Should not apply because finding.connector != "other_connector"
        assert finding.score.value == pytest.approx(initial_score)

    def test_evaluate_batch(self):
        findings = [make_finding(raw_data="credential dump") for _ in range(5)]
        rule = make_detection_rule(pattern="credential", rule_type=RuleType.KEYWORD, score_boost=1.0)
        engine = self._engine_with_rules([rule])
        results = engine.evaluate_batch(findings)
        assert len(results) == 5
        assert all(r.has_matches for r in results)

    def test_tags_applied_from_rule(self):
        finding = make_finding(raw_data="malware sample detected")
        rule = DetectionRule(
            name="Malware Tag Rule",
            rule_type=RuleType.KEYWORD,
            pattern="malware",
            tags=["malware-detected", "priority"],
            is_active=True,
            score_boost=1.0,
        )
        engine = self._engine_with_rules([rule])
        engine.evaluate(finding)
        assert "malware-detected" in finding.tags
