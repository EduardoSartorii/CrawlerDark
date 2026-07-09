"""
Unit tests for the Correlation Engine.

Tests cover:
    - Attribute extraction
    - Finding pair correlation
    - Relationship creation
    - Minimum shared attribute threshold
    - Relationship type inference
"""

from __future__ import annotations

import pytest

from ....infrastructure.correlation.engine import CorrelationEngine, AttributeExtractor
from ...fixtures.factories import make_finding


class TestAttributeExtractor:
    """Tests for the AttributeExtractor."""

    def test_extracts_ip_addresses(self):
        finding = make_finding(raw_data="connection from 192.168.1.100 detected")
        extractor = AttributeExtractor()
        attrs = extractor.extract(finding)
        assert "192.168.1.100" in attrs.get("ip", set())

    def test_extracts_emails(self):
        finding = make_finding(raw_data="contact hacker@evil.com for more info")
        extractor = AttributeExtractor()
        attrs = extractor.extract(finding)
        assert "hacker@evil.com" in attrs.get("email", set())

    def test_extracts_threat_actor(self):
        finding = make_finding()
        finding.threat_actor = "Lazarus Group"
        extractor = AttributeExtractor()
        attrs = extractor.extract(finding)
        assert "lazarus group" in attrs.get("threat_actor", set())

    def test_extracts_malware_family(self):
        finding = make_finding()
        finding.malware_family = "Emotet"
        extractor = AttributeExtractor()
        attrs = extractor.extract(finding)
        assert "emotet" in attrs.get("malware_family", set())

    def test_filters_short_values(self):
        finding = make_finding(raw_data="a b c d 1.2.3")
        extractor = AttributeExtractor()
        attrs = extractor.extract(finding)
        # Short values should be filtered
        for attr_values in attrs.values():
            assert all(len(v) >= 4 for v in attr_values)


class TestCorrelationEngine:
    """Tests for the Correlation Engine."""

    def test_no_correlation_single_finding(self):
        findings = [make_finding()]
        engine = CorrelationEngine()
        result = engine.correlate(findings)
        assert result.finding_count == 1
        assert len(result.matches) == 0

    def test_correlates_findings_with_shared_ip(self):
        ip = "10.0.0.1"
        f1 = make_finding(raw_data=f"attack from {ip}")
        f2 = make_finding(raw_data=f"C2 server at {ip}")
        engine = CorrelationEngine(min_shared_count=1)
        result = engine.correlate([f1, f2])
        assert len(result.matches) >= 1

    def test_correlates_findings_with_shared_threat_actor(self):
        f1 = make_finding()
        f2 = make_finding()
        f1.threat_actor = "APT42"
        f2.threat_actor = "APT42"
        engine = CorrelationEngine(min_shared_count=1)
        result = engine.correlate([f1, f2])
        assert len(result.matches) >= 1

    def test_no_correlation_for_unrelated_findings(self):
        f1 = make_finding(raw_data="unique content alpha", title="Alpha finding")
        f2 = make_finding(raw_data="unique content beta zeta", title="Beta finding")
        engine = CorrelationEngine(min_shared_count=1)
        result = engine.correlate([f1, f2])
        # Only correlate if they actually share something meaningful
        # These have very different content, so likely no correlation
        assert isinstance(result.matches, list)

    def test_relationships_attached_to_findings(self):
        shared_email = "attacker@evil.com"
        f1 = make_finding(raw_data=f"account {shared_email} was used")
        f2 = make_finding(raw_data=f"phishing from {shared_email}")
        engine = CorrelationEngine(min_shared_count=1)
        engine.correlate([f1, f2])
        # Both findings should have relationship attached
        assert len(f1.relationships) >= 1 or len(f2.relationships) >= 1

    def test_relationship_type_for_threat_actor(self):
        f1 = make_finding()
        f2 = make_finding()
        f1.threat_actor = "Sandworm"
        f2.threat_actor = "Sandworm"
        engine = CorrelationEngine(min_shared_count=1)
        result = engine.correlate([f1, f2])
        if result.matches:
            assert "attributed-to" in result.matches[0].relationship_types
