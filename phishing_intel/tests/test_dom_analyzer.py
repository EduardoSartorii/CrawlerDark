"""Tests for DOM analyzer."""

from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer
from phishing_intel.tests.fixtures.sample_html import SAMPLE_PHISHING_HTML, SAMPLE_OTP_HTML


class TestDOMAnalyzer:
    def setup_method(self):
        self.analyzer = DOMAnalyzer(base_url="https://phish.example.com")

    def test_extract_forms(self):
        result = self.analyzer.analyze(SAMPLE_PHISHING_HTML)
        assert len(result.forms) == 1
        form = result.forms[0]
        assert form.method == "POST"
        assert "evil-collector" in form.action

    def test_extract_form_fields(self):
        result = self.analyzer.analyze(SAMPLE_PHISHING_HTML)
        fields = result.forms[0].fields
        field_names = [f.name for f in fields]
        assert "agencia" in field_names
        assert "senha" in field_names

    def test_hidden_field_detection(self):
        result = self.analyzer.analyze(SAMPLE_PHISHING_HTML)
        hidden = [f for f in result.forms[0].fields if f.is_hidden]
        assert len(hidden) == 1
        assert hidden[0].name == "token"

    def test_extract_scripts(self):
        result = self.analyzer.analyze(SAMPLE_PHISHING_HTML)
        assert len(result.scripts) >= 2
        external = [s for s in result.scripts if not s.inline]
        assert any("jquery" in s.src for s in external)

    def test_extract_assets(self):
        result = self.analyzer.analyze(SAMPLE_PHISHING_HTML)
        assert len(result.assets) > 0
        assert any("itau-logo" in a.filename for a in result.assets)

    def test_extract_metatags(self):
        result = self.analyzer.analyze(SAMPLE_PHISHING_HTML)
        assert "description" in result.metatags
        assert "itaú" in result.metatags.get("og:site_name", "").lower()

    def test_extract_comments(self):
        result = self.analyzer.analyze(SAMPLE_PHISHING_HTML)
        assert any("phishkit" in c for c in result.html_comments)

    def test_structural_hash(self):
        result = self.analyzer.analyze(SAMPLE_PHISHING_HTML)
        assert len(result.structural_hash) == 64

    def test_external_urls(self):
        result = self.analyzer.analyze(SAMPLE_PHISHING_HTML)
        assert len(result.external_urls) > 0

    def test_css_classes_and_ids(self):
        result = self.analyzer.analyze(SAMPLE_PHISHING_HTML)
        assert "container" in result.css_classes
        assert "login-container" in result.html_ids

    def test_otp_html_forms(self):
        result = self.analyzer.analyze(SAMPLE_OTP_HTML)
        assert len(result.forms) == 1
