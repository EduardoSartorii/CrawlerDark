"""Unit tests for domain value objects."""

from __future__ import annotations

import pytest

from threat_hunting.core.domain.enums import IndicatorType, RelationshipType, Severity
from threat_hunting.core.domain.value_objects.artifact import Artifact
from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.core.domain.value_objects.relationship import Relationship
from threat_hunting.core.domain.value_objects.score import Score
from threat_hunting.core.domain.value_objects.timeline import TimelineEvent


def test_indicator_refang_and_lowercase():
    indicator = Indicator(type=IndicatorType.DOMAIN, value="hxxps://Evil[.]COM")
    assert indicator.value == "https://evil.com"
    assert indicator.key == "domain:https://evil.com"


def test_indicator_equality_and_hash_by_key():
    a = Indicator(type=IndicatorType.IPV4, value="1.2.3.4", confidence=10)
    b = Indicator(type=IndicatorType.IPV4, value="1.2.3.4", confidence=90)
    assert a == b
    assert len({a, b}) == 1
    assert a != "not-an-indicator"


def test_artifact_from_bytes_hashes_content():
    artifact = Artifact.from_bytes("dump.txt", "file", b"hello")
    assert artifact.size_bytes == 5
    assert artifact.sha256 and len(artifact.sha256) == 64


def test_relationship_key_is_stable():
    rel = Relationship(
        source_ref="a", target_ref="b", type=RelationshipType.RESOLVES_TO
    )
    assert rel.key == "a|resolves_to|b"


def test_score_accumulates_and_clamps():
    score = Score.zero().with_component("a", 60).with_component("b", 60)
    assert score.value == 100.0
    assert score.breakdown == {"a": 60.0, "b": 60.0}


@pytest.mark.parametrize(
    "value,expected",
    [
        (5, Severity.INFO),
        (20, Severity.LOW),
        (50, Severity.MEDIUM),
        (70, Severity.HIGH),
        (90, Severity.CRITICAL),
    ],
)
def test_severity_from_score(value, expected):
    assert Severity.from_score(value) is expected


def test_timeline_event_defaults_now():
    event = TimelineEvent(stage="collected")
    assert event.at is not None
