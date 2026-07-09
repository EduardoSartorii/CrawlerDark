"""Tests for enrichment modules."""

from phishing_intel.enrichment.misp_client import MISPClient
from phishing_intel.enrichment.taxonomy_mapper import TaxonomyMapper
from phishing_intel.models.campaign import CampaignAttribution
from phishing_intel.models.findings import (
    AnalysisResult,
    BrandFinding,
    ConfidenceLevel,
    ExfiltrationFinding,
    ExfiltrationType,
    PhishingType,
)
from phishing_intel.utils import load_config


class TestTaxonomyMapper:
    def setup_method(self):
        self.mapper = TaxonomyMapper()

    def test_map_tags(self):
        result = AnalysisResult(
            url="https://evil.com",
            phishing_type=PhishingType.CREDENTIAL_HARVESTING,
            brand=BrandFinding(brand="itau", confidence=90.0),
            exfiltration=ExfiltrationFinding(primary_method=ExfiltrationType.API),
        )
        attribution = CampaignAttribution(
            campaign_id="CAMP-001",
            score=75.0,
            confidence=ConfidenceLevel.HIGH,
        )
        tags = self.mapper.map_tags(result, attribution)
        assert any("fraude:marca=itau" in t for t in tags)
        assert any("fraude:objetivo=credential_harvesting" in t for t in tags)
        assert any("fraude:campanha=CAMP-001" in t for t in tags)
        assert any("fraude:exfiltracao=api" in t for t in tags)

    def test_criticality_mapping(self):
        assert self.mapper._map_criticality(ConfidenceLevel.HIGH) == "alta"
        assert self.mapper._map_criticality(ConfidenceLevel.LOW) == "baixa"


class TestMISPClient:
    def setup_method(self):
        self.config = load_config()
        self.config["misp"]["api_key"] = ""  # Force mock mode
        self.client = MISPClient(self.config)

    def test_mock_event_creation(self):
        result = AnalysisResult(
            url="https://evil.com",
            phishing_type=PhishingType.OTP_HARVESTING,
            html_hash="abc123",
        )
        attribution = CampaignAttribution(
            campaign_id="CAMP-TEST",
            score=50.0,
            confidence=ConfidenceLevel.MEDIUM,
        )
        event = self.client.create_event(result, attribution, tags=["test"])
        assert event is not None
        assert "uuid" in event

    def test_mock_event_with_ssl(self):
        from phishing_intel.models.findings import SSLCertificate

        result = AnalysisResult(
            url="https://evil.com",
            ssl=SSLCertificate(
                sha1_fingerprint="aa" * 20,
                sha256_fingerprint="bb" * 32,
                serial_number="12345",
            ),
        )
        attribution = CampaignAttribution(campaign_id="CAMP-SSL")
        event = self.client.create_event(result, attribution)
        assert event is not None
