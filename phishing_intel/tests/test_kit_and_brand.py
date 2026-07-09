"""Tests for kit fingerprinter and brand detector."""

from phishing_intel.analyzers.brand_detector import BrandDetector
from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer
from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.analyzers.kit_fingerprint import KitFingerprinter
from phishing_intel.tests.fixtures.sample_html import SAMPLE_OTP_HTML, SAMPLE_PHISHING_HTML


class TestKitFingerprinter:
    def setup_method(self):
        self.fingerprinter = KitFingerprinter()
        self.dom_analyzer = DOMAnalyzer(base_url="https://phish.example.com")
        self.js_analyzer = JavaScriptAnalyzer()

    def test_fingerprint_generation(self):
        dom = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        js = self.js_analyzer.analyze("")
        fp = self.fingerprinter.fingerprint(dom, js)
        assert len(fp.dom_hash) == 64
        assert len(fp.asset_hash) == 64
        assert len(fp.script_hash) == 64
        assert len(fp.campaign_fingerprint) == 64

    def test_fingerprint_stability(self):
        dom1 = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        dom2 = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        js = self.js_analyzer.analyze("")
        fp1 = self.fingerprinter.fingerprint(dom1, js)
        fp2 = self.fingerprinter.fingerprint(dom2, js)
        assert fp1.campaign_fingerprint == fp2.campaign_fingerprint

    def test_directory_structure(self):
        dom = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        js = self.js_analyzer.analyze("")
        fp = self.fingerprinter.fingerprint(dom, js)
        assert len(fp.directory_structure) > 0

    def test_different_pages_different_fingerprint(self):
        dom1 = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        dom2 = self.dom_analyzer.analyze(SAMPLE_OTP_HTML)
        js = self.js_analyzer.analyze("")
        fp1 = self.fingerprinter.fingerprint(dom1, js)
        fp2 = self.fingerprinter.fingerprint(dom2, js)
        assert fp1.campaign_fingerprint != fp2.campaign_fingerprint


class TestBrandDetector:
    def setup_method(self):
        self.brands = {
            "financial": ["itau", "bradesco", "nubank"],
            "loyalty": ["livelo"],
        }
        self.detector = BrandDetector(self.brands)
        self.dom_analyzer = DOMAnalyzer()

    def test_itau_detection(self):
        dom = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        result = self.detector.detect(dom, "Acesse sua conta Itaú")
        assert result is not None
        assert result.brand == "itau"
        assert result.confidence > 0

    def test_nubank_detection(self):
        dom = self.dom_analyzer.analyze(SAMPLE_OTP_HTML)
        result = self.detector.detect(dom, "Verificação Nubank")
        assert result is not None
        assert result.brand == "nubank"

    def test_no_brand_detected(self):
        dom = self.dom_analyzer.analyze("<html><body>Generic page</body></html>")
        result = self.detector.detect(dom)
        assert result is None

    def test_detection_sources(self):
        dom = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        result = self.detector.detect(dom, "Itaú login")
        assert result is not None
        assert len(result.detection_sources) > 0
