"""Unit tests for DOM, JS, form and fingerprint analyzers."""

from __future__ import annotations

from phishing_intel.analyzers.brand_detector import BrandDetector
from phishing_intel.analyzers.dom_analyzer import DomAnalyzer
from phishing_intel.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from phishing_intel.analyzers.form_classifier import FormClassifier
from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.analyzers.kit_fingerprint import KitFingerprintAnalyzer
from phishing_intel.models.findings import ExfiltrationType, PhishingType


def test_dom_analyzer_extracts_core_elements(sample_html: str) -> None:
    analyzer = DomAnalyzer()
    result = analyzer.analyze(sample_html, base_url="https://phish.example")

    assert result.forms
    assert result.forms[0].method == "post"
    assert "card_number" in result.forms[0].input_names
    assert "csrf" in result.forms[0].hidden_fields
    assert result.dom_hash
    assert "description" in result.metatags
    assert result.external_urls == ["https://example.net/help"]


def test_javascript_and_exfiltration_analyzers(sample_javascript: list[str], sample_html: str) -> None:
    dom_result = DomAnalyzer().analyze(sample_html, base_url="https://phish.example")
    js_result = JavaScriptAnalyzer().analyze(sample_javascript)
    exfiltration = ExfiltrationAnalyzer().analyze(dom_result, js_result)

    assert js_result.fetch_targets == ["https://collector.test/api/v1/collect"]
    assert js_result.axios_targets == ["https://collector.test/graphql"]
    assert js_result.jquery_ajax_targets == ["https://collector.test/email/send"]
    assert exfiltration.destinations
    assert any(item.destination_type in {ExfiltrationType.API, ExfiltrationType.HTTP} for item in exfiltration.destinations)


def test_form_classifier_detects_card_harvesting(sample_html: str) -> None:
    dom_result = DomAnalyzer().analyze(sample_html, base_url="https://phish.example")
    result = FormClassifier().classify(dom_result, sample_html)
    assert result == PhishingType.CARD_HARVESTING


def test_brand_detector_matches_itau(sample_html: str) -> None:
    dom_result = DomAnalyzer().analyze(sample_html, base_url="https://phish.example")
    result = BrandDetector().detect(dom_result, sample_html)
    assert result.target_brand == "itau"
    assert result.confidence >= 0.5


def test_fingerprint_analyzer_generates_campaign_hash(sample_html: str, sample_javascript: list[str]) -> None:
    dom_result = DomAnalyzer().analyze(sample_html, base_url="https://phish.example")
    js_result = JavaScriptAnalyzer().analyze(sample_javascript)
    result = KitFingerprintAnalyzer().build(dom_result, js_result)

    assert len(result.campaign_fingerprint) == 64
    assert result.dom_hash == dom_result.dom_hash
