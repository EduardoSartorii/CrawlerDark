"""Testes dos modelos de dominio de infraestrutura (models.infrastructure)."""

from __future__ import annotations

from datetime import datetime, timezone

from models.infrastructure import CertificateRecord, InfrastructureRecord


def test_certificate_record_accepts_normalized_fields() -> None:
    record = CertificateRecord(
        subject="CN=phish.example",
        issuer="CN=Evil CA",
        serial_number="123456",
        san=["phish.example", "www.phish.example"],
        sha1_fingerprint="a" * 40,
        sha256_fingerprint="b" * 64,
        not_before=datetime.now(timezone.utc),
        not_after=datetime.now(timezone.utc),
    )
    assert record.san == ["phish.example", "www.phish.example"]
    assert record.raw_pem is None


def test_infrastructure_record_defaults_to_empty_collections() -> None:
    record = InfrastructureRecord(domain="phish.example", ip="203.0.113.10", asn="AS64500")
    assert record.passive_dns_records == []
    assert record.external_references == {}
    assert record.hosting_provider is None
