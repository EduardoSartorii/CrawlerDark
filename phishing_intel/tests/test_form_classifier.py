"""Tests for form classifier."""

from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer
from phishing_intel.analyzers.form_classifier import FormClassifier
from phishing_intel.models.findings import PhishingType
from phishing_intel.tests.fixtures.sample_html import (
    SAMPLE_CARD_HTML,
    SAMPLE_OTP_HTML,
    SAMPLE_PHISHING_HTML,
)


class TestFormClassifier:
    def setup_method(self):
        self.classifier = FormClassifier()
        self.dom_analyzer = DOMAnalyzer()

    def test_credential_harvesting(self):
        dom = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        result = self.classifier.classify(dom)
        assert result == PhishingType.CREDENTIAL_HARVESTING

    def test_otp_harvesting(self):
        dom = self.dom_analyzer.analyze(SAMPLE_OTP_HTML)
        result = self.classifier.classify(dom)
        assert result == PhishingType.OTP_HARVESTING

    def test_card_harvesting(self):
        dom = self.dom_analyzer.analyze(SAMPLE_CARD_HTML)
        result = self.classifier.classify(dom)
        assert result == PhishingType.CARD_HARVESTING

    def test_generic_fallback(self):
        dom = self.dom_analyzer.analyze("<html><body><p>Hello</p></body></html>")
        result = self.classifier.classify(dom)
        assert result == PhishingType.GENERIC_DATA_COLLECTION
