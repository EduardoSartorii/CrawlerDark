"""Tests for Pydantic domain models."""

from phishing_intel.models.findings import (
    AnalysisResult,
    DOMFinding,
    ExfiltrationType,
    PhishingType,
    KitFingerprint,
)
from phishing_intel.models.campaign import CampaignAttribution, ConfidenceLevel


class TestFindingsModels:
    def test_phishing_type_enum(self):
        assert PhishingType.CREDENTIAL_HARVESTING.value == "credential_harvesting"

    def test_dom_finding_defaults(self):
        dom = DOMFinding()
        assert dom.forms == []
        assert dom.structural_hash == ""

    def test_analysis_result_creation(self):
        result = AnalysisResult(url="https://evil.com")
        assert result.url == "https://evil.com"
        assert result.phishing_type == PhishingType.GENERIC_DATA_COLLECTION

    def test_kit_fingerprint(self):
        fp = KitFingerprint(dom_hash="abc", campaign_fingerprint="def")
        assert fp.dom_hash == "abc"


class TestCampaignModels:
    def test_attribution_confidence(self):
        attr = CampaignAttribution(campaign_id="CAMP-001", score=75.0)
        assert attr.confidence == ConfidenceLevel.LOW

    def test_attribution_signals(self):
        attr = CampaignAttribution(
            campaign_id="CAMP-001",
            score=80.0,
            confidence=ConfidenceLevel.HIGH,
        )
        assert attr.confidence == ConfidenceLevel.HIGH
