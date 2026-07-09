"""Unit tests for the domain model (entities, value objects, enums)."""

from __future__ import annotations

from threat_hunting.core.domain.entities import Finding, Indicator, Relationship
from threat_hunting.core.domain.enums import IndicatorType, RelationshipType, Severity
from threat_hunting.core.domain.value_objects import Score


def test_score_is_clamped_and_composed() -> None:
    assert Score(150).value == 100.0
    assert Score(-5).value == 0.0
    assert (Score(60) + Score(60)).value == 100.0
    assert Score.from_contributions({"a": 10, "b": 5}).value == 15.0
    assert Score(50).normalized == 0.5


def test_severity_from_score_bands() -> None:
    assert Severity.from_score(95) is Severity.CRITICAL
    assert Severity.from_score(75) is Severity.HIGH
    assert Severity.from_score(50) is Severity.MEDIUM
    assert Severity.from_score(20) is Severity.LOW
    assert Severity.from_score(1) is Severity.INFO
    assert Severity.CRITICAL > Severity.LOW


def test_indicator_fingerprint_normalises_value() -> None:
    a = Indicator(type=IndicatorType.DOMAIN, value="ACME-corp.COM")
    b = Indicator(type=IndicatorType.DOMAIN, value="acme-corp.com")
    assert a.fingerprint() == b.fingerprint() == "domain:acme-corp.com"


def test_finding_add_indicator_deduplicates_and_audits() -> None:
    finding = Finding(title="t", source="s", connector="c")
    first = finding.add_indicator(Indicator(type=IndicatorType.IPV4, value="1.2.3.4"))
    second = finding.add_indicator(Indicator(type=IndicatorType.IPV4, value="1.2.3.4"))
    assert first is True
    assert second is False
    assert len(finding.indicators) == 1


def test_finding_set_score_updates_severity_and_timeline() -> None:
    finding = Finding(title="t", source="s", connector="c")
    finding.set_score(92)
    assert finding.severity is Severity.CRITICAL
    assert any(e.stage == "scoring" for e in finding.timeline)


def test_finding_relationship_and_tags() -> None:
    finding = Finding(title="t", source="s", connector="c")
    finding.add_relationship(
        Relationship(type=RelationshipType.SAME_ACTOR, target_ref="other")
    )
    finding.add_tag("x")
    finding.add_tag("x")
    assert finding.tags == ["x"]
    assert len(finding.relationships) == 1
