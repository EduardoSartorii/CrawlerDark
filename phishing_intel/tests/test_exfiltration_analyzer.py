"""Tests for exfiltration analyzer."""

from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer
from phishing_intel.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.models.findings import ExfiltrationType
from phishing_intel.tests.fixtures.sample_html import SAMPLE_JAVASCRIPT, SAMPLE_PHISHING_HTML


class TestExfiltrationAnalyzer:
    def setup_method(self):
        self.analyzer = ExfiltrationAnalyzer()
        self.dom_analyzer = DOMAnalyzer(base_url="https://phish.example.com")
        self.js_analyzer = JavaScriptAnalyzer()

    def test_form_post_detection(self):
        dom = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        js = self.js_analyzer.analyze("")
        result = self.analyzer.analyze(dom, js)
        assert len(result.destinations) > 0
        form_dests = [d for d in result.destinations if d.source == "form"]
        assert len(form_dests) > 0

    def test_messaging_detection(self):
        dom = self.dom_analyzer.analyze("<html></html>")
        js = self.js_analyzer.analyze(SAMPLE_JAVASCRIPT)
        result = self.analyzer.analyze(dom, js)
        messaging = [d for d in result.destinations if d.exfiltration_type == ExfiltrationType.MESSAGING]
        assert len(messaging) > 0

    def test_deduplication(self):
        dom = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        js = self.js_analyzer.analyze(SAMPLE_JAVASCRIPT)
        result = self.analyzer.analyze(dom, js)
        urls = [d.url for d in result.destinations]
        assert len(urls) == len(set(urls))

    def test_overall_confidence(self):
        dom = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        js = self.js_analyzer.analyze(SAMPLE_JAVASCRIPT)
        result = self.analyzer.analyze(dom, js)
        assert result.overall_confidence > 0

    def test_primary_method(self):
        dom = self.dom_analyzer.analyze(SAMPLE_PHISHING_HTML)
        js = self.js_analyzer.analyze(SAMPLE_JAVASCRIPT)
        result = self.analyzer.analyze(dom, js)
        assert result.primary_method is not None
