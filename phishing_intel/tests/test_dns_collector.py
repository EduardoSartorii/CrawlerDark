"""Testes do coletor de DNS (collectors.dns_collector)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.resolver

from collectors.dns_collector import resolve_domain


def test_resolve_domain_returns_all_record_types() -> None:
    def fake_resolve(domain: str, record_type: str, lifetime: float):
        mapping = {
            "A": ["203.0.113.10"],
            "AAAA": [],
            "NS": ["ns1.evil.test."],
            "MX": ["mail.evil.test."],
        }
        if record_type == "AAAA":
            raise dns.resolver.NoAnswer()
        return [MagicMock(__str__=lambda self, v=v: v) for v in mapping[record_type]]

    with patch("collectors.dns_collector.dns.resolver.resolve", side_effect=fake_resolve):
        result = resolve_domain("phish.example")

    assert result.domain == "phish.example"
    assert result.a_records == ["203.0.113.10"]
    assert result.aaaa_records == []
    assert result.ns_records == ["ns1.evil.test"]
    assert result.mx_records == ["mail.evil.test"]


def test_resolve_domain_tolerates_nxdomain() -> None:
    with patch("collectors.dns_collector.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        result = resolve_domain("nonexistent.invalid")

    assert result.a_records == []
    assert result.ns_records == []
