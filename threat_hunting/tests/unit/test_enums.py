"""Unit tests for domain enums."""

from threat_hunting.core.domain.enums import (
    Severity, SourceType, FindingCategory, IndicatorType, RuleType,
)


def test_severity_values():
    assert Severity.CRITICAL.value == "critical"
    assert len(Severity) == 5


def test_source_types():
    assert SourceType.DARKWEB.value == "darkweb"
    assert SourceType.SOCIAL.value == "social"


def test_indicator_types():
    assert IndicatorType.EMAIL.value == "email"
    assert IndicatorType.HASH_SHA256.value == "hash_sha256"


def test_rule_types():
    assert RuleType.COMPOSITE.value == "composite"
    assert RuleType.YARA.value == "yara"
