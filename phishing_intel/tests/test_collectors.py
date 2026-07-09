"""Unit tests for the collectors (network mocked)."""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from phishing_intel.collectors.dns_collector import DNSCollector
from phishing_intel.collectors.html_collector import HTMLCollector
from phishing_intel.collectors.infrastructure_collector import InfrastructureCollector
from phishing_intel.collectors.ssl_collector import SSLCollector
from phishing_intel.models.infrastructure import DNSRecords


# --- Certificate fixture ----------------------------------------------------
@pytest.fixture(scope="module")
def self_signed_pem() -> str:
    """Generate a self-signed certificate PEM for parse tests."""

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "phish.example")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(123456789)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("phish.example")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


# --- SSL collector ----------------------------------------------------------
def test_ssl_parse_pem(self_signed_pem: str) -> None:
    info = SSLCollector().parse_pem(self_signed_pem)
    assert "phish.example" in (info.subject or "")
    assert info.serial_number == format(123456789, "x")
    assert info.san == ["phish.example"]
    assert len(info.sha256_fingerprint) == 64
    assert len(info.sha1_fingerprint) == 40
    assert info.not_before is not None and info.not_after is not None


def test_ssl_collect_failure_returns_none(mocker) -> None:
    # Simulate a connection failure; collect must degrade to None.
    mocker.patch(
        "phishing_intel.collectors.ssl_collector.socket.create_connection",
        side_effect=OSError("refused"),
    )
    assert SSLCollector(timeout=1).collect("unreachable.invalid") is None


# --- HTML collector ---------------------------------------------------------
def test_html_collect_success(mocker) -> None:
    session = mocker.Mock()
    response = mocker.Mock()
    response.status_code = 200
    response.text = "<html>ok</html>"
    response.content = b"<html>ok</html>"
    session.get.return_value = response
    collector = HTMLCollector(session=session)
    assert collector.collect("https://x.example") == "<html>ok</html>"


def test_html_collect_failure_returns_none(mocker) -> None:
    import requests

    session = mocker.Mock()
    session.get.side_effect = requests.RequestException("boom")
    collector = HTMLCollector(session=session)
    assert collector.collect("https://x.example") is None


def test_html_collect_profiles_skips_failures(mocker) -> None:
    import requests

    session = mocker.Mock()
    ok = mocker.Mock(status_code=200, text="<html>desktop</html>", content=b"x")

    def side_effect(url, headers, timeout, verify, allow_redirects):
        if "Mobile" in headers["User-Agent"]:
            raise requests.RequestException("blocked")
        return ok

    session.get.side_effect = side_effect
    collector = HTMLCollector(session=session)
    profiles = {
        "desktop_chrome": "Mozilla/5.0 Chrome",
        "iphone_safari": "Mozilla/5.0 Mobile Safari",
    }
    results = collector.collect_profiles("https://x.example", profiles)
    assert "desktop_chrome" in results
    assert "iphone_safari" not in results


# --- DNS collector ----------------------------------------------------------
def test_dns_collect(mocker) -> None:
    collector = DNSCollector(timeout=1)

    def fake_resolve(domain, record_type):
        answers = {
            "A": ["203.0.113.5"],
            "MX": ['10 mail.phish.example.'],
        }.get(record_type, [])
        if not answers:
            raise Exception("no answer")
        return [mocker.Mock(to_text=lambda v=v: v) for v in answers]

    mocker.patch.object(collector.resolver, "resolve", side_effect=fake_resolve)
    records = collector.collect("phish.example")
    assert records.a == ["203.0.113.5"]
    assert records.mx == ["10 mail.phish.example."]
    assert records.ns == []


# --- Infrastructure collector ----------------------------------------------
def test_infrastructure_collect(mocker) -> None:
    dns = mocker.Mock()
    dns.collect.return_value = DNSRecords(domain="phish.example", a=["203.0.113.9"])
    collector = InfrastructureCollector(dns_collector=dns)
    mocker.patch.object(
        collector,
        "_whois_ip",
        return_value={
            "asn": "64500",
            "asn_description": "EVIL-AS",
            "asn_country_code": "RU",
            "network": {"name": "EvilNet"},
        },
    )
    info = collector.collect("phish.example")
    assert info.ip == "203.0.113.9"
    assert info.asn == "64500"
    assert info.country == "RU"
    assert info.hosting_provider == "EvilNet"


def test_infrastructure_collect_no_ip(mocker) -> None:
    dns = mocker.Mock()
    dns.collect.return_value = DNSRecords(domain="phish.example", a=[])
    collector = InfrastructureCollector(dns_collector=dns)
    info = collector.collect("phish.example")
    assert info.ip is None
    assert info.asn is None
