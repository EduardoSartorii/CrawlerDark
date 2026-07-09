"""Unit tests for collectors with network calls mocked."""

from __future__ import annotations

from types import SimpleNamespace

from phishing_intel.collectors.dns_collector import DnsCollector
from phishing_intel.collectors.html_collector import HtmlCollector
from phishing_intel.collectors.infrastructure_collector import InfrastructureCollector
from phishing_intel.models.infrastructure import DnsRecordSet


def test_html_collector_extracts_hash_and_scripts(monkeypatch) -> None:
    html = "<html><body><script>fetch('/x')</script></body></html>"

    class Response:
        text = html

        @staticmethod
        def raise_for_status():
            return None

    monkeypatch.setattr("phishing_intel.collectors.html_collector.requests.get", lambda *args, **kwargs: Response())
    result = HtmlCollector().collect("https://a.test")

    assert result.html_hash
    assert result.javascript_hash
    assert "fetch('/x')" in result.javascript_blobs[0]


def test_dns_collector_handles_failures(monkeypatch) -> None:
    monkeypatch.setattr("phishing_intel.collectors.dns_collector.dns.resolver.resolve", lambda *args, **kwargs: (_ for _ in ()).throw(Exception("boom")))
    result = DnsCollector().collect("example.test")
    assert result.a_records == []
    assert result.mx_records == []
    assert result.ns_records == []


def test_infrastructure_collector_with_mocked_whois(monkeypatch) -> None:
    monkeypatch.setattr("phishing_intel.collectors.infrastructure_collector.socket.gethostbyname", lambda _: "8.8.8.8")
    monkeypatch.setattr(
        "phishing_intel.collectors.infrastructure_collector.IPWhois.lookup_rdap",
        lambda self, depth=1: {
            "asn": "15169",
            "asn_description": "Google LLC",
            "network": {"name": "GOOGLE", "country": "US"},
        },
    )
    fake_dns = SimpleNamespace(collect=lambda _: DnsRecordSet(a_records=["8.8.8.8"], mx_records=[], ns_records=[]))

    profile = InfrastructureCollector(dns_collector=fake_dns).collect("google.test")
    assert profile.ip == "8.8.8.8"
    assert profile.asn == "15169"
    assert profile.provider == "GOOGLE"
