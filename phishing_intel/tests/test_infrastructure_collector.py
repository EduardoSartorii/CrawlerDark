"""Testes do coletor de infraestrutura (collectors.infrastructure_collector)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from collectors.dns_collector import DnsResolutionResult
from collectors.infrastructure_collector import collect_infrastructure


def test_collect_infrastructure_returns_full_finding() -> None:
    dns_result = DnsResolutionResult(domain="phish.example", a_records=["203.0.113.10"])
    rdap_payload = {
        "asn": "64500",
        "asn_description": "EVIL-HOSTING-INC",
        "asn_country_code": "NL",
        "network": {"name": "evil-hosting", "country": "NL"},
    }

    with (
        patch("collectors.infrastructure_collector.resolve_domain", return_value=dns_result),
        patch("collectors.infrastructure_collector.IPWhois") as mock_ipwhois_cls,
    ):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = rdap_payload
        mock_ipwhois_cls.return_value = mock_instance

        finding = collect_infrastructure("phish.example")

    assert finding.domain == "phish.example"
    assert finding.ip == "203.0.113.10"
    assert finding.asn == "AS64500"
    assert finding.asn_organization == "EVIL-HOSTING-INC"
    assert finding.hosting_provider == "evil-hosting"
    assert finding.country == "NL"


def test_collect_infrastructure_returns_partial_finding_without_ip() -> None:
    dns_result = DnsResolutionResult(domain="unresolvable.example")

    with patch("collectors.infrastructure_collector.resolve_domain", return_value=dns_result):
        finding = collect_infrastructure("unresolvable.example")

    assert finding.domain == "unresolvable.example"
    assert finding.ip is None


def test_collect_infrastructure_tolerates_whois_failure() -> None:
    dns_result = DnsResolutionResult(domain="phish.example", a_records=["203.0.113.10"])

    with (
        patch("collectors.infrastructure_collector.resolve_domain", return_value=dns_result),
        patch("collectors.infrastructure_collector.IPWhois", side_effect=RuntimeError("boom")),
    ):
        finding = collect_infrastructure("phish.example")

    assert finding.ip == "203.0.113.10"
    assert finding.asn is None
