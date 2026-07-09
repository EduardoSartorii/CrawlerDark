"""
Unit tests for the Finding aggregate root.

Tests cover:
    - Entity creation via factory method
    - Score application and severity derivation
    - Domain event emission
    - State transitions (confirm, false positive, export)
    - Tag management
    - Invariants (TLP validation, etc.)
"""

from __future__ import annotations

import pytest

from ....core.domain.entities.finding import Finding, FindingStatus
from ....core.domain.entities.base import DomainEvent
from ....core.domain.value_objects import Score, ThreatCategory
from ....core.domain.value_objects.severity import SeverityLevel
from ....core.domain.value_objects.source_type import SourceType
from ...fixtures.factories import make_finding


class TestFindingCreation:
    """Tests for Finding factory method and initial state."""

    def test_create_returns_finding_with_correct_fields(self):
        finding = Finding.create(
            title="Test credential leak",
            source="Reddit",
            connector="reddit",
            category=ThreatCategory.CREDENTIAL_LEAK,
            source_type=SourceType.SOCIAL_MEDIA,
        )
        assert finding.title == "Test credential leak"
        assert finding.source == "Reddit"
        assert finding.connector == "reddit"
        assert finding.category == ThreatCategory.CREDENTIAL_LEAK
        assert finding.status == FindingStatus.NEW

    def test_create_emits_finding_created_event(self):
        finding = Finding.create(
            title="Test",
            source="source",
            connector="test",
        )
        events = finding.pull_events()
        assert len(events) == 1
        assert events[0].event_type == "finding.created"

    def test_create_assigns_uuid(self):
        f1 = Finding.create(title="A", source="s", connector="c")
        f2 = Finding.create(title="A", source="s", connector="c")
        assert f1.id != f2.id

    def test_create_with_tags(self):
        finding = Finding.create(
            title="Test", source="s", connector="c",
            tags=["reddit", "malware"],
        )
        assert "reddit" in finding.tags
        assert "malware" in finding.tags

    def test_title_stripped_on_create(self):
        finding = Finding.create(title="  spaces  ", source="s", connector="c")
        assert finding.title == "spaces"

    def test_invalid_tlp_raises(self):
        with pytest.raises(Exception):
            Finding(
                title="x", source="s", connector="c",
                tlp="INVALID",
            )


class TestFindingScoring:
    """Tests for score application and severity derivation."""

    def test_apply_score_updates_score_field(self):
        finding = make_finding(score_value=0.0)
        finding.apply_score(Score(value=7.5, confidence=0.8))
        assert finding.score.value == 7.5
        assert finding.score.confidence == 0.8

    def test_apply_score_derives_severity(self):
        finding = make_finding(score_value=0.0)
        finding.apply_score(Score(value=9.5, confidence=1.0))
        assert finding.severity.level == SeverityLevel.CRITICAL

    def test_apply_score_emits_scored_event(self):
        finding = make_finding(score_value=0.0)
        finding.pull_events()  # Clear creation event
        finding.apply_score(Score(value=6.0, confidence=0.7))
        events = finding.pull_events()
        assert any(e.event_type == "finding.scored" for e in events)

    @pytest.mark.parametrize("score,expected_severity", [
        (0.0, SeverityLevel.INFO),
        (2.0, SeverityLevel.LOW),
        (5.0, SeverityLevel.MEDIUM),
        (7.5, SeverityLevel.HIGH),
        (9.5, SeverityLevel.CRITICAL),
    ])
    def test_score_to_severity_mapping(self, score: float, expected_severity: SeverityLevel):
        finding = make_finding(score_value=score)
        assert finding.severity.level == expected_severity

    def test_should_auto_export_when_score_above_threshold(self):
        finding = make_finding(score_value=7.5, confidence=1.0)
        assert finding.should_auto_export is True

    def test_should_not_auto_export_when_score_below_threshold(self):
        finding = make_finding(score_value=5.0, confidence=0.5)
        assert finding.should_auto_export is False


class TestFindingStateTransitions:
    """Tests for lifecycle state transitions."""

    def test_confirm_changes_status(self):
        finding = make_finding()
        finding.confirm(analyst="analyst@corp.com")
        assert finding.status == FindingStatus.CONFIRMED

    def test_confirm_adds_timeline_entry(self):
        finding = make_finding()
        finding.confirm()
        assert len(finding.timeline) >= 1

    def test_confirm_emits_confirmed_event(self):
        finding = make_finding()
        finding.pull_events()
        finding.confirm()
        events = finding.pull_events()
        assert any(e.event_type == "finding.confirmed" for e in events)

    def test_mark_false_positive_changes_status(self):
        finding = make_finding()
        finding.mark_false_positive(reason="Benign activity", analyst="analyst")
        assert finding.status == FindingStatus.FALSE_POSITIVE

    def test_mark_exported(self):
        finding = make_finding()
        finding.mark_exported("misp")
        assert finding.status == FindingStatus.EXPORTED
        assert "exported_to_misp" in finding.metadata


class TestFindingTagManagement:
    """Tests for tag management."""

    def test_add_tag_deduplicates(self):
        finding = make_finding()
        finding.add_tag("malware")
        finding.add_tag("malware")
        assert finding.tags.count("malware") == 1

    def test_add_tag_normalizes_case(self):
        finding = make_finding()
        finding.add_tag("MALWARE")
        assert "malware" in finding.tags

    def test_add_empty_tag_ignored(self):
        finding = make_finding(tags=[])
        initial_count = len(finding.tags)
        finding.add_tag("")
        finding.add_tag("  ")
        assert len(finding.tags) == initial_count


class TestFindingEquality:
    """Tests for entity identity-based equality."""

    def test_same_id_equals(self):
        f = make_finding()
        # Create a copy with same ID
        f2 = Finding(
            id=f.id,
            title="Different title",
            source="s", connector="c",
        )
        assert f == f2

    def test_different_id_not_equals(self):
        f1 = make_finding()
        f2 = make_finding()
        assert f1 != f2

    def test_hash_based_on_id(self):
        f = make_finding()
        assert hash(f) == hash(f.id)
