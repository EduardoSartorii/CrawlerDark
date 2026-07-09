"""Testes do mapeador de taxonomias (enrichment.taxonomy_mapper)."""

from __future__ import annotations

from enrichment.taxonomy_mapper import build_tags, derive_criticality
from models.campaign import AttributionScore, Campaign, ConfidenceLevel
from models.findings import (
    AnalysisReport,
    ClassificationResult,
    DomFinding,
    EvidenceRecord,
    ExfiltrationChannel,
    ExfiltrationDestination,
    ExfiltrationReport,
    InfrastructureFinding,
    JavaScriptFinding,
    KitFingerprint,
    BrandDetectionResult,
    PhishingType,
)


def _base_report(phishing_type: PhishingType = PhishingType.CREDENTIAL_HARVESTING) -> AnalysisReport:
    return AnalysisReport(
        url="https://phish.example/login",
        evidence=EvidenceRecord(url="https://phish.example/login", html_sha256="h", javascript_sha256="j"),
        dom=DomFinding(structural_hash="dom_hash"),
        javascript=JavaScriptFinding(script_hash="js_hash"),
        classification=ClassificationResult(phishing_type=phishing_type, confidence=0.8),
        exfiltration=ExfiltrationReport(
            destinations=[
                ExfiltrationDestination(url="https://collector.evil/api", channel=ExfiltrationChannel.API, confidence=0.9),
                ExfiltrationDestination(url="mailto:x@evil.test", channel=ExfiltrationChannel.EMAIL, confidence=0.6),
            ],
            overall_confidence=0.75,
        ),
        fingerprint=KitFingerprint(dom_sha256="d", assets_sha256="a", scripts_sha256="s", campaign_fingerprint="camp"),
        brand=BrandDetectionResult(target_brand="Itau", category="financial_institution", confidence=0.9),
        infrastructure=InfrastructureFinding(asn="AS64500", hosting_provider="Evil Hosting Ltd"),
    )


def _campaign() -> Campaign:
    return Campaign(campaign_id="CAMP-ABC123", score=80.0, confidence=ConfidenceLevel.HIGH)


def test_build_tags_includes_all_expected_namespaces() -> None:
    report = _base_report()
    attribution = AttributionScore(score=80.0, confidence=ConfidenceLevel.HIGH)
    tags = build_tags(report, _campaign(), attribution)

    assert "fraude:marca=itau" in tags
    assert "fraude:objetivo=credential_harvesting" in tags
    assert "fraude:campanha=camp-abc123" in tags
    assert "fraude:infraestrutura=as64500" in tags
    assert any(tag.startswith("fraude:criticidade=") for tag in tags)
    assert "fraude:exfiltracao=api" in tags
    assert "fraude:exfiltracao=email" in tags


def test_build_tags_deduplicates() -> None:
    report = _base_report()
    report.exfiltration.destinations.append(
        ExfiltrationDestination(url="https://collector.evil/api2", channel=ExfiltrationChannel.API, confidence=0.5)
    )
    attribution = AttributionScore(score=50.0, confidence=ConfidenceLevel.MEDIUM)
    tags = build_tags(report, _campaign(), attribution)
    assert tags.count("fraude:exfiltracao=api") == 1


def test_derive_criticality_forces_high_for_otp_regardless_of_score() -> None:
    report = _base_report(phishing_type=PhishingType.OTP_HARVESTING)
    attribution = AttributionScore(score=5.0, confidence=ConfidenceLevel.LOW)
    assert derive_criticality(report, attribution) == "alta"


def test_derive_criticality_medium_for_account_takeover() -> None:
    report = _base_report(phishing_type=PhishingType.ACCOUNT_TAKEOVER)
    attribution = AttributionScore(score=5.0, confidence=ConfidenceLevel.LOW)
    assert derive_criticality(report, attribution) == "media"


def test_derive_criticality_low_by_default() -> None:
    report = _base_report(phishing_type=PhishingType.GENERIC_DATA_COLLECTION)
    attribution = AttributionScore(score=5.0, confidence=ConfidenceLevel.LOW)
    assert derive_criticality(report, attribution) == "baixa"
