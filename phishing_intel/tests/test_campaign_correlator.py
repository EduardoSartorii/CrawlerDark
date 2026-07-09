"""Testes do motor principal de correlacao (correlators.campaign_correlator)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from analyzers.brand_detector import detect_brand
from analyzers.dom_analyzer import analyze_dom
from analyzers.exfiltration_analyzer import analyze_exfiltration
from analyzers.form_classifier import classify_phishing_type
from analyzers.javascript_analyzer import analyze_javascript
from analyzers.kit_fingerprint import generate_kit_fingerprint
from config.settings import CorrelationSettings, PhishingIntelSettings
from correlators.campaign_correlator import build_or_attach_campaign, calculate_attribution_score, correlate_incident
from database.repositories import CampaignRepository, FingerprintRepository, PhishingSiteRepository
from models.campaign import ConfidenceLevel, CorrelationSignal, CorrelationSignalType
from models.findings import AnalysisReport, EvidenceRecord


def _build_report(url: str, html: str, js: str, settings: PhishingIntelSettings) -> AnalysisReport:
    dom = analyze_dom(html, base_url=url)
    javascript = analyze_javascript(js)
    return AnalysisReport(
        url=url,
        evidence=EvidenceRecord(url=url, html_sha256="h", javascript_sha256="j"),
        dom=dom,
        javascript=javascript,
        classification=classify_phishing_type(dom),
        exfiltration=analyze_exfiltration(dom, javascript),
        fingerprint=generate_kit_fingerprint(dom, javascript),
        brand=detect_brand(html, dom, settings.brands.known_brands),
    )


def test_calculate_attribution_score_sums_unique_signal_types() -> None:
    settings = CorrelationSettings()
    signals = [
        CorrelationSignal(
            signal_type=CorrelationSignalType.SAME_FINGERPRINT, weight=0, matched_value="fp", related_site_url="https://a.example"
        ),
        CorrelationSignal(
            signal_type=CorrelationSignalType.SAME_FINGERPRINT, weight=0, matched_value="fp", related_site_url="https://b.example"
        ),
        CorrelationSignal(
            signal_type=CorrelationSignalType.SAME_CERTIFICATE, weight=0, matched_value="cert", related_site_url="https://a.example"
        ),
    ]
    attribution = calculate_attribution_score(signals, settings)

    # same_fingerprint (35) + same_certificate (25) = 60, contado uma vez por TIPO.
    assert attribution.score == 60.0
    assert attribution.confidence == ConfidenceLevel.MEDIUM
    assert set(attribution.correlated_site_urls) == {"https://a.example", "https://b.example"}


def test_calculate_attribution_score_caps_at_100() -> None:
    settings = CorrelationSettings()
    all_types = list(CorrelationSignalType)
    signals = [
        CorrelationSignal(signal_type=t, weight=0, matched_value="x", related_site_url="https://a.example")
        for t in all_types
    ]
    attribution = calculate_attribution_score(signals, settings)
    assert attribution.score == 100.0
    assert attribution.confidence == ConfidenceLevel.HIGH


def test_calculate_attribution_score_no_signals_is_low_confidence() -> None:
    settings = CorrelationSettings()
    attribution = calculate_attribution_score([], settings)
    assert attribution.score == 0.0
    assert attribution.confidence == ConfidenceLevel.LOW


def test_correlate_incident_and_build_new_campaign_when_no_history(db_session: Session) -> None:
    settings = PhishingIntelSettings.model_validate(
        {
            "database": {"url": "sqlite:///:memory:"},
            "misp": {"url": "https://misp.test", "api_key": "K"},
        }
    )
    report = _build_report(
        "https://phish.example/login",
        "<html><body><form method='POST'><input name='user'><input name='pass' type='password'></form></body></html>",
        "",
        settings,
    )

    attribution = correlate_incident(report, db_session, settings.correlation)
    assert attribution.score == 0.0

    campaign = build_or_attach_campaign(report, attribution, db_session)
    assert campaign.campaign_id.startswith("CAMP-")
    assert campaign.confidence == ConfidenceLevel.LOW


def test_build_or_attach_campaign_attaches_to_existing_campaign_on_fingerprint_match(db_session: Session) -> None:
    settings = PhishingIntelSettings.model_validate(
        {
            "database": {"url": "sqlite:///:memory:"},
            "misp": {"url": "https://misp.test", "api_key": "K"},
        }
    )
    html = "<html><body><form method='POST' action='/collect'><input name='user'><input name='pass' type='password'></form></body></html>"

    first_report = _build_report("https://site-one.example/login", html, "", settings)

    fingerprint_repo = FingerprintRepository(db_session)
    site_repo = PhishingSiteRepository(db_session)
    campaign_repo = CampaignRepository(db_session)

    fp_row = fingerprint_repo.create(
        dom_hash=first_report.fingerprint.dom_sha256,
        asset_hash=first_report.fingerprint.assets_sha256,
        script_hash=first_report.fingerprint.scripts_sha256,
        campaign_fingerprint=first_report.fingerprint.campaign_fingerprint,
    )
    campaign_row = campaign_repo.create(campaign_id="CAMP-EXISTING", score=35.0, confidence="low")
    site_repo.create(
        url=first_report.url,
        domain="site-one.example",
        html_hash="h",
        javascript_hash="j",
        phishing_type=first_report.classification.phishing_type.value,
        target_brand=first_report.brand.target_brand,
        fingerprint_id=fp_row.id,
        campaign_id=campaign_row.id,
    )

    second_report = _build_report("https://site-two.example/login", html, "", settings)
    attribution = correlate_incident(second_report, db_session, settings.correlation)
    assert attribution.score >= settings.correlation.weights.same_fingerprint

    campaign = build_or_attach_campaign(second_report, attribution, db_session)
    assert campaign.campaign_id == "CAMP-EXISTING"
    assert campaign.score >= 35.0
