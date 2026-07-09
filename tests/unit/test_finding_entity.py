"""Unit tests for the Finding aggregate and its builder."""

from __future__ import annotations

from threat_hunting.core.domain.entities.finding import Finding, FindingBuilder
from threat_hunting.core.domain.enums import Category, IndicatorType, RelationshipType, Severity
from threat_hunting.core.domain.value_objects.artifact import Artifact
from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.core.domain.value_objects.relationship import Relationship
from threat_hunting.core.domain.value_objects.score import DetectionMatch, Score


def test_builder_produces_valid_finding():
    finding = (
        FindingBuilder("Leak", "sample_paste", "paste://x")
        .description("desc")
        .category(Category.DATA_LEAK)
        .confidence(80)
        .add_tag("leak")
        .add_indicator(Indicator(type=IndicatorType.DOMAIN, value="evil.com"))
        .build()
    )
    assert finding.title == "Leak"
    assert finding.category is Category.DATA_LEAK
    assert finding.confidence == 80
    assert "leak" in finding.tags
    assert finding.timeline  # 'collected' recorded


def test_add_indicator_and_artifact_deduplicate():
    finding = FindingBuilder("t", "c", "s").build()
    ind = Indicator(type=IndicatorType.IPV4, value="1.1.1.1")
    finding.add_indicator(ind)
    finding.add_indicator(Indicator(type=IndicatorType.IPV4, value="1.1.1.1"))
    assert len(finding.indicators) == 1

    art = Artifact.from_bytes("a", "file", b"x")
    finding.add_artifact(art)
    finding.add_artifact(art)
    assert len(finding.artifacts) == 1


def test_relationship_and_detection_recorded():
    finding = FindingBuilder("t", "c", "s").build()
    finding.add_relationship(
        Relationship(source_ref="a", target_ref="b", type=RelationshipType.MENTIONS)
    )
    finding.add_detection(
        DetectionMatch(rule_id="r", rule_type="regex", matched="x", weight=1.0)
    )
    assert len(finding.relationships) == 1
    assert len(finding.detections) == 1


def test_set_score_updates_severity():
    finding = FindingBuilder("t", "c", "s").build()
    finding.set_score(Score.zero().with_component("k", 90))
    assert finding.severity is Severity.CRITICAL
    assert finding.score.value == 90.0


def test_indicator_keys_property():
    finding = FindingBuilder("t", "c", "s").build()
    finding.add_indicator(Indicator(type=IndicatorType.DOMAIN, value="a.com"))
    assert finding.indicator_keys == {"domain:a.com"}


def test_finding_serialises_roundtrip():
    finding = FindingBuilder("t", "c", "s").build()
    dumped = finding.model_dump(mode="json")
    restored = Finding.model_validate(dumped)
    assert restored.id == finding.id
