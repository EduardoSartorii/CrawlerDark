"""Analyzer unit tests."""

from __future__ import annotations

from phishing_intel.analyzers.brand_detector import BrandDetector
from phishing_intel.analyzers.dom_analyzer import DomAnalyzer
from phishing_intel.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from phishing_intel.analyzers.form_classifier import FormClassifier
from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.analyzers.kit_fingerprint import KitFingerprinter


def test_dom_analyzer_extracts_forms_assets_and_hash(phishing_html: str) -> None:
    """DOM analyzer extracts normalized evidence and structural hash."""

    dom = DomAnalyzer().analyze(phishing_html, "https://phish.example/login")
    assert dom.forms[0].method == "post"
    assert dom.forms[0].action == "https://collector.example/api/submit"
    assert any(field.hidden for field in dom.forms[0].fields)
    assert "capture" in dom.css_classes
    assert "login.css" in dom.file_names
    assert len(dom.dom_hash) == 64


def test_javascript_analyzer_extracts_network_apis_tokens_and_strings(phishing_js: str) -> None:
    """JavaScript analyzer identifies exfil APIs and exposed secrets."""

    finding = JavaScriptAnalyzer().analyze(phishing_js)
    assert "https://collector.example/api/submit" in finding.fetch_urls
    assert "https://api.telegram.org/bot123/sendMessage" in finding.axios_urls
    assert "https://collector.example/webhook.json" in finding.jquery_ajax_urls
    assert finding.exposed_tokens == ["abcdef1234567890"]
    assert "telegram" in finding.suspicious_strings


def test_classifier_brand_exfiltration_and_fingerprint(phishing_html: str, phishing_js: str) -> None:
    """Analyzers classify objective, brand, exfiltration, and kit fingerprint."""

    dom = DomAnalyzer().analyze(phishing_html, "https://phish.example/login")
    js = JavaScriptAnalyzer().analyze(phishing_js)
    classification = FormClassifier().classify(dom)
    brand = BrandDetector().detect(dom, js, phishing_html)
    destinations = ExfiltrationAnalyzer().analyze(dom, js)
    fingerprint = KitFingerprinter().fingerprint(dom, js)
    assert classification.phishing_type in {"otp_harvesting", "credential_harvesting", "identity_theft"}
    assert classification.confidence >= 70
    assert brand.target_brand == "itau"
    assert destinations[0].confidence >= 85
    assert any(item.destination_type == "messaging" for item in destinations)
    assert len(fingerprint.campaign_fingerprint) == 64
