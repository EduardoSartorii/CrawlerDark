"""Tests for JavaScript analyzer."""

from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.tests.fixtures.sample_html import SAMPLE_JAVASCRIPT


class TestJavaScriptAnalyzer:
    def setup_method(self):
        self.analyzer = JavaScriptAnalyzer()

    def test_fetch_extraction(self):
        result = self.analyzer.analyze(SAMPLE_JAVASCRIPT)
        assert len(result.fetch_calls) > 0
        assert any("telegram" in url for url in result.fetch_calls)

    def test_xhr_extraction(self):
        result = self.analyzer.analyze(SAMPLE_JAVASCRIPT)
        assert len(result.xhr_urls) > 0

    def test_axios_extraction(self):
        result = self.analyzer.analyze(SAMPLE_JAVASCRIPT)
        assert len(result.axios_urls) > 0

    def test_hardcoded_urls(self):
        result = self.analyzer.analyze(SAMPLE_JAVASCRIPT)
        assert len(result.hardcoded_urls) > 0

    def test_exposed_tokens(self):
        result = self.analyzer.analyze(SAMPLE_JAVASCRIPT)
        assert len(result.exposed_tokens) > 0

    def test_suspicious_strings(self):
        result = self.analyzer.analyze(SAMPLE_JAVASCRIPT)
        assert len(result.suspicious_strings) > 0

    def test_script_hash(self):
        result = self.analyzer.analyze(SAMPLE_JAVASCRIPT)
        assert len(result.script_hash) == 64

    def test_empty_javascript(self):
        result = self.analyzer.analyze("")
        assert result.script_hash != ""

    def test_inline_scripts_combined(self):
        result = self.analyzer.analyze("", inline_scripts=["fetch('http://test.com')"])
        assert len(result.fetch_calls) > 0
