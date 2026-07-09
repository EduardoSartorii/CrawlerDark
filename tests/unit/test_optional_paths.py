"""Tests for optional-dependency code paths (YARA no-op, MISP mapping)."""

from __future__ import annotations

from threat_hunting.core.domain.entities.finding import FindingBuilder
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.infrastructure.detections.rules.yara_rule import YaraRule
from threat_hunting.infrastructure.exporters.misp_exporter import MispExporter


def test_yara_rule_noop_without_library():
    rule = YaraRule("y", 'rule demo { strings: $a = "x" condition: $a }')
    finding = FindingBuilder("t", "c", "s").description("x").build()
    # yara-python is not installed in the base env -> safe no-op.
    if not rule.available:
        assert rule.evaluate(finding) == []


def test_misp_payload_maps_indicator_types():
    finding = (
        FindingBuilder("t", "c", "s")
        .add_indicator(Indicator(type=IndicatorType.IPV4, value="1.2.3.4"))
        .add_indicator(Indicator(type=IndicatorType.SHA256, value="a" * 64))
        .add_indicator(Indicator(type=IndicatorType.CPF, value="529.982.247-25"))
        .build()
    )
    payload = MispExporter()._event_payload(finding)
    misp_types = {a["type"] for a in payload["attributes"]}
    assert "ip-dst" in misp_types
    assert "sha256" in misp_types
    # CPF has no MISP mapping -> excluded, not crashing.
    assert payload["info"] == "t"
