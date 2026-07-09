"""Testes do coletor de certificado SSL (collectors.ssl_collector)."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from collectors.ssl_collector import SslCollectionError, collect_certificate, parse_der_certificate


def _build_self_signed_certificate() -> bytes:
    """Gera um certificado autoassinado em memoria para uso exclusivo nos testes."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "phish.example"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil Corp"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("phish.example")]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def test_parse_der_certificate_extracts_normalized_fields() -> None:
    der_cert = _build_self_signed_certificate()
    finding = parse_der_certificate(der_cert)

    assert "phish.example" in finding.subject
    assert "Evil Corp" in finding.issuer
    assert finding.san == ["phish.example"]
    assert len(finding.sha256_fingerprint) == 64
    assert len(finding.sha1_fingerprint) == 40
    assert finding.not_before.tzinfo is not None
    assert finding.not_after > finding.not_before
    assert finding.raw_pem is not None and "BEGIN CERTIFICATE" in finding.raw_pem


def test_collect_certificate_raises_on_socket_failure() -> None:
    with patch("collectors.ssl_collector.socket.create_connection", side_effect=OSError("unreachable")):
        with pytest.raises(SslCollectionError):
            collect_certificate("unreachable.example", port=443, timeout=1.0)


def test_collect_certificate_parses_response_from_mocked_socket() -> None:
    der_cert = _build_self_signed_certificate()

    mock_tls_sock = MagicMock()
    mock_tls_sock.getpeercert.return_value = der_cert
    mock_tls_sock.__enter__.return_value = mock_tls_sock
    mock_tls_sock.__exit__.return_value = False

    mock_raw_sock = MagicMock()
    mock_raw_sock.__enter__.return_value = mock_raw_sock
    mock_raw_sock.__exit__.return_value = False

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_tls_sock

    with (
        patch("collectors.ssl_collector.socket.create_connection", return_value=mock_raw_sock),
        patch("collectors.ssl_collector.ssl.SSLContext", return_value=mock_context),
    ):
        finding = collect_certificate("phish.example")

    assert "phish.example" in finding.subject
