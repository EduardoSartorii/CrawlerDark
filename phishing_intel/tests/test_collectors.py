"""Tests for collectors with mocking."""

import responses

from phishing_intel.collectors.dns_collector import DNSCollector
from phishing_intel.collectors.html_collector import HTMLCollector
from phishing_intel.models.findings import RenderProfile
from phishing_intel.utils import load_config


class TestHTMLCollector:
    def setup_method(self):
        config = load_config()
        self.collector = HTMLCollector(config)

    @responses.activate
    def test_collect_html(self):
        responses.add(
            responses.GET,
            "https://phish.example.com",
            body="<html><body>phishing</body></html>",
            status=200,
        )
        result = self.collector.collect("https://phish.example.com")
        assert "phishing" in result["html"]
        assert len(result["html_hash"]) == 64
        assert result["status_code"] == 200

    @responses.activate
    def test_collect_with_profile(self):
        responses.add(
            responses.GET,
            "https://phish.example.com",
            body="<html>mobile</html>",
            status=200,
        )
        result = self.collector.collect(
            "https://phish.example.com", RenderProfile.ANDROID_CHROME
        )
        assert result["profile"] == "android_chrome"


class TestDNSCollector:
    def setup_method(self):
        self.collector = DNSCollector()

    def test_collect_returns_structure(self):
        result = self.collector.collect("example.com")
        assert "domain" in result
        assert result["domain"] == "example.com"
        assert "a_records" in result
        assert "resolved_ips" in result
