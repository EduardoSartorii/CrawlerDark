"""Unit tests for domain entities."""

from threat_hunting.core.domain.entities import Finding, FindingDraft, Indicator
from threat_hunting.core.domain.enums import IndicatorType, SourceType


def test_finding_creation():
    finding = Finding(title="Test", source=SourceType.API, connector="test")
    assert finding.title == "Test"
    assert finding.score == 0.0


def test_finding_add_indicator():
    finding = Finding(title="Test", source=SourceType.API, connector="test")
    ind = Indicator(type=IndicatorType.IP, value="1.2.3.4")
    finding.add_indicator(ind)
    assert len(finding.indicators) == 1
    finding.add_indicator(ind)
    assert len(finding.indicators) == 1


def test_finding_add_tag():
    finding = Finding(title="Test", source=SourceType.API, connector="test")
    finding.add_tag("malware")
    assert "malware" in finding.tags


def test_finding_draft_to_finding():
    draft = FindingDraft(title="Draft", source=SourceType.SOCIAL, connector="reddit")
    finding = draft.to_finding()
    assert finding.title == "Draft"
    assert finding.connector == "reddit"
