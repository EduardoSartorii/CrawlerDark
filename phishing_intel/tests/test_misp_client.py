"""Testes do cliente MISP (enrichment.misp_client), com PyMISP mockado."""

from __future__ import annotations

from unittest.mock import MagicMock

from pymisp import MISPEvent, MISPObject

from config.settings import MispSettings
from enrichment.misp_client import MispClient
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
    SslCertificateFinding,
)
from datetime import datetime, timezone


def _settings() -> MispSettings:
    return MispSettings(url="https://misp.test", api_key="TEST-KEY", verify_cert=False)


def _report_with_ssl_and_infra() -> AnalysisReport:
    return AnalysisReport(
        url="https://phish.example/login",
        evidence=EvidenceRecord(url="https://phish.example/login", html_sha256="h" * 64, javascript_sha256="j" * 64),
        dom=DomFinding(structural_hash="dom_hash"),
        javascript=JavaScriptFinding(script_hash="js_hash"),
        classification=ClassificationResult(phishing_type=PhishingType.CREDENTIAL_HARVESTING, confidence=0.8),
        exfiltration=ExfiltrationReport(
            destinations=[
                ExfiltrationDestination(url="https://collector.evil/api", channel=ExfiltrationChannel.API, confidence=0.9)
            ],
            overall_confidence=0.9,
        ),
        fingerprint=KitFingerprint(dom_sha256="d", assets_sha256="a", scripts_sha256="s", campaign_fingerprint="camp"),
        brand=BrandDetectionResult(target_brand="itau", category="financial_institution", confidence=0.9),
        ssl=SslCertificateFinding(
            subject="CN=phish.example",
            issuer="CN=Evil CA",
            serial_number="123",
            sha1_fingerprint="a" * 40,
            sha256_fingerprint="b" * 64,
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
        ),
        infrastructure=InfrastructureFinding(asn="AS64500", hosting_provider="Evil Hosting Ltd", ip="203.0.113.10"),
    )


def _mock_pymisp() -> MagicMock:
    mock_client = MagicMock()
    created_event = MISPEvent()
    created_event.uuid = "event-uuid-123"
    created_event.id = "42"
    mock_client.add_event.return_value = created_event
    mock_client.add_object.side_effect = lambda event, obj, pythonify=True: obj
    return mock_client


def test_create_event_for_report_applies_tags_and_returns_event() -> None:
    mock_client = _mock_pymisp()
    client = MispClient(_settings(), client=mock_client)

    report = _report_with_ssl_and_infra()
    event = client.create_event_for_report(report, tags=["fraude:marca=itau", "fraude:objetivo=credential_harvesting"])

    assert mock_client.add_event.called
    passed_event: MISPEvent = mock_client.add_event.call_args[0][0]
    assert "phish.example" in passed_event.info
    assert {tag.name for tag in passed_event.tags} == {"fraude:marca=itau", "fraude:objetivo=credential_harvesting"}
    assert event.uuid == "event-uuid-123"


def test_add_ioc_attributes_includes_url_domain_and_ip() -> None:
    mock_client = _mock_pymisp()
    client = MispClient(_settings(), client=mock_client)
    report = _report_with_ssl_and_infra()
    event = MISPEvent()

    client.add_ioc_attributes(event, report)

    calls = [call.args[1] for call in mock_client.add_attribute.call_args_list]
    types_and_values = {(c["type"], c["value"]) for c in calls}
    assert ("url", "https://phish.example/login") in types_and_values
    assert ("domain", "phish.example") in types_and_values
    assert ("ip-dst", "203.0.113.10") in types_and_values


def test_add_certificate_object_creates_x509_object() -> None:
    mock_client = _mock_pymisp()
    client = MispClient(_settings(), client=mock_client)
    report = _report_with_ssl_and_infra()
    event = MISPEvent()

    result = client.add_certificate_object(event, report)

    assert isinstance(result, MISPObject)
    assert result.name == "x509"
    attribute_relations = {attr.object_relation for attr in result.attributes}
    assert {"subject", "issuer", "serial-number", "x509-fingerprint-sha256"}.issubset(attribute_relations)


def test_add_phishing_campaign_object_includes_all_required_fields() -> None:
    mock_client = _mock_pymisp()
    client = MispClient(_settings(), client=mock_client)
    report = _report_with_ssl_and_infra()
    event = MISPEvent()
    campaign = Campaign(campaign_id="CAMP-XYZ", score=85.0, confidence=ConfidenceLevel.HIGH)
    attribution = AttributionScore(score=85.0, confidence=ConfidenceLevel.HIGH)

    result = client.add_phishing_campaign_object(event, report, campaign, attribution)

    relations = {attr.object_relation: attr.value for attr in result.attributes}
    assert relations["campaign_id"] == "CAMP-XYZ"
    assert relations["kit_fingerprint"] == "camp"
    assert relations["target_brand"] == "itau"
    assert relations["phishing_type"] == "credential_harvesting"
    assert relations["hosting_provider"] == "Evil Hosting Ltd"
    assert relations["asn"] == "AS64500"
    assert relations["ssl_fingerprint"] == "b" * 64


def test_enrich_event_calls_all_sub_steps() -> None:
    mock_client = _mock_pymisp()
    client = MispClient(_settings(), client=mock_client)
    report = _report_with_ssl_and_infra()
    event = MISPEvent()
    campaign = Campaign(campaign_id="CAMP-XYZ", score=85.0, confidence=ConfidenceLevel.HIGH)
    attribution = AttributionScore(score=85.0, confidence=ConfidenceLevel.HIGH)

    client.enrich_event(event, report, campaign, attribution)

    assert mock_client.add_attribute.called
    assert mock_client.add_object.call_count >= 2  # x509 + phishing-campaign (+ http-request)
