"""Testes dos coletores (HTML, SSL, DNS, infraestrutura) com mocking."""

from __future__ import annotations

import requests

from phishing_intel.collectors import (
    DnsCollector,
    HtmlCollector,
    InfrastructureCollector,
    SslCollector,
)
from phishing_intel.collectors.html_collector import RENDER_PROFILES


class _FakeResponse:
    """Resposta HTTP falsa para injetar em uma sessão mockada."""

    def __init__(self, text: str, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code


def test_html_collector_fetch(mocker):
    """O coletor deve retornar o HTML e o status usando a sessão injetada."""
    session = mocker.Mock(spec=requests.Session)
    session.get.return_value = _FakeResponse("<html>ok</html>", 200)
    collector = HtmlCollector(session=session)
    html, status = collector.fetch("https://x.tld", profile="android_chrome")
    assert html == "<html>ok</html>"
    assert status == 200
    # O User-Agent do perfil deve ter sido usado.
    _, kwargs = session.get.call_args
    assert kwargs["headers"]["User-Agent"] == RENDER_PROFILES["android_chrome"].user_agent


def test_html_collector_handles_network_error(mocker):
    """Falha de rede deve resultar em ('', 0) sem propagar exceção."""
    session = mocker.Mock(spec=requests.Session)
    session.get.side_effect = requests.RequestException("boom")
    collector = HtmlCollector(session=session)
    assert collector.fetch("https://x.tld") == ("", 0)


def test_html_collector_multi_profile(mocker):
    """A coleta multi-perfil deve retornar um HTML por perfil solicitado."""
    session = mocker.Mock(spec=requests.Session)
    session.get.return_value = _FakeResponse("<html>a</html>")
    collector = HtmlCollector(session=session)
    result = collector.fetch_multi_profile(
        "https://x.tld", ["desktop_chrome", "iphone_safari"]
    )
    assert set(result.keys()) == {"desktop_chrome", "iphone_safari"}


def test_ssl_collector_parse_pem(self_signed_pem):
    """O parse de PEM deve normalizar subject/issuer/serial/SAN/fingerprints."""
    info = SslCollector().parse_pem(self_signed_pem)
    assert "phishing.evil.tld" in info.subject
    assert info.serial_number == "1234567890"
    assert "phishing.evil.tld" in info.san
    assert len(info.sha256_fingerprint) == 64
    assert len(info.sha1_fingerprint) == 40
    assert info.pem == self_signed_pem


def test_ssl_collector_invalid_pem_is_resilient():
    """PEM inválido deve retornar objeto vazio preservando o PEM."""
    info = SslCollector().parse_pem("not a cert")
    assert info.serial_number == ""
    assert info.pem == "not a cert"


def test_ssl_collector_network_failure_is_resilient(mocker):
    """Falha de conexão TLS deve retornar CertificateInfo vazio."""
    mocker.patch("socket.create_connection", side_effect=OSError("no route"))
    info = SslCollector(timeout=1).collect("nonexistent.invalid")
    assert info.sha256_fingerprint == ""


def test_dns_collector_resolves(mocker):
    """O coletor de DNS deve mapear as respostas para os campos corretos."""
    collector = DnsCollector()

    def fake_query(domain, record_type):
        return {"A": ["1.2.3.4"], "MX": ["mail.x.tld"]}.get(record_type, [])

    mocker.patch.object(collector, "_query", side_effect=fake_query)
    records = collector.resolve("x.tld")
    assert records.a == ["1.2.3.4"]
    assert records.mx == ["mail.x.tld"]
    assert records.txt == []


def test_dns_collector_empty_domain():
    """Domínio vazio não deve gerar consultas."""
    assert DnsCollector().resolve("").a == []


def test_infrastructure_collector_no_ip(mocker):
    """Sem IP resolvível, o coletor retorna objeto parcial sem crashar."""
    collector = InfrastructureCollector()
    mocker.patch.object(collector, "resolve_ip", return_value="")
    info = collector.collect(domain="x.tld")
    assert info.ip == ""
    assert info.asn == ""


def test_infrastructure_collector_rdap(mocker):
    """O RDAP deve preencher ASN/organização/país/provedor."""
    collector = InfrastructureCollector()
    mocker.patch.object(collector, "resolve_ip", return_value="9.9.9.9")

    fake_whois = mocker.Mock()
    fake_whois.lookup_rdap.return_value = {
        "asn": "13335",
        "asn_country_code": "US",
        "asn_description": "CLOUDFLARE",
        "network": {"name": "CLOUDFLARENET"},
        "asn_cidr": "9.9.9.0/24",
    }
    mocker.patch("ipwhois.IPWhois", return_value=fake_whois)

    info = collector.collect(domain="x.tld")
    assert info.ip == "9.9.9.9"
    assert info.asn == "AS13335"
    assert info.country == "US"
    assert info.hosting_provider == "CLOUDFLARENET"
    assert "ipwhois_rdap" in info.enrichment_sources
