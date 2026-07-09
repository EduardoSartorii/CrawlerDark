"""Unit tests for correlators and enrichment mappers."""

from __future__ import annotations

from phishing_intel.correlators.campaign_correlator import CampaignCorrelator
from phishing_intel.correlators.infrastructure_correlator import InfrastructureCorrelator
from phishing_intel.enrichment.campaign_builder import CampaignBuilder
from phishing_intel.enrichment.taxonomy_mapper import TaxonomyMapper
from phishing_intel.models.findings import (
    BrandDetectionResult,
    ExfiltrationAnalysisResult,
    ExfiltrationDestination,
    ExfiltrationType,
    FingerprintResult,
    PhishingType,
)
from phishing_intel.models.infrastructure import InfrastructureProfile, SslMetadata


def test_campaign_correlator_confidence_levels() -> None:
    correlator = CampaignCorrelator()
    low = correlator.attribute("cmp-a", False, False, False, False, False)
    medium = correlator.attribute("cmp-b", True, False, False, False, True)
    high = correlator.attribute("cmp-c", True, True, True, False, True)

    assert low.confidence_level == "low"
    assert medium.confidence_level == "medium"
    assert high.confidence_level == "high"


def test_infrastructure_correlator_matches_ssl_and_asn() -> None:
    infra = InfrastructureProfile(domain="a.test", ip="1.1.1.1", asn="13335", provider="Cloudflare")
    historical = [InfrastructureProfile(domain="b.test", ip="2.2.2.2", asn="13335", provider="Cloudflare")]
    ssl = SslMetadata(
        subject="CN=a.test",
        issuer="CN=Issuer",
        serial_number="123",
        san=["a.test"],
        sha1_fingerprint="a",
        sha256_fingerprint="b",
        not_before="2024-01-01T00:00:00+00:00",
        not_after="2025-01-01T00:00:00+00:00",
        pem="pem",
    )
    ssl_history = [
        SslMetadata(
            subject="CN=b.test",
            issuer="CN=Issuer",
            serial_number="123",
            san=["b.test"],
            sha1_fingerprint="x",
            sha256_fingerprint="y",
            not_before="2024-01-01T00:00:00+00:00",
            not_after="2025-01-01T00:00:00+00:00",
            pem="pem",
        )
    ]

    result = InfrastructureCorrelator().correlate(infra, historical, ssl, ssl_history)
    assert result["same_asn"] is True
    assert result["same_provider"] is True
    assert result["same_certificate"] is True


def test_taxonomy_mapper_and_campaign_builder() -> None:
    exfiltration = ExfiltrationAnalysisResult(
        destinations=[ExfiltrationDestination(target="https://x.test/api", destination_type=ExfiltrationType.API, confidence=0.9)],
        score=0.9,
    )
    tags = TaxonomyMapper().build_tags(
        brand="itau",
        phishing_type=PhishingType.CREDENTIAL_HARVESTING,
        campaign_id="cmp-1",
        confidence="high",
        exfiltration=exfiltration,
    )
    payload = CampaignBuilder().build_payload(
        attribution=CampaignCorrelator().attribute("cmp-1", True, True, False, False, True),
        fingerprint=FingerprintResult(
            dom_hash="a" * 64,
            asset_hash="b" * 64,
            script_hash="c" * 64,
            campaign_fingerprint="d" * 64,
        ),
        ssl=None,
        brand=BrandDetectionResult(target_brand="itau", confidence=0.9),
        phishing_type=PhishingType.CREDENTIAL_HARVESTING,
        infrastructure=InfrastructureProfile(domain="a.test", ip="1.1.1.1", asn="13335", provider="Cloudflare"),
    )
    assert "fraude:marca=itau" in tags
    assert payload["target_brand"] == "itau"
    assert payload["campaign_id"] == "cmp-1"
