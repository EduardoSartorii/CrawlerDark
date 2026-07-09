"""TLS certificate collector and parser."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from phishing_intel.models.infrastructure import CertificateFinding


class SslCollector:
    """Collect and normalize x509 certificates from phishing hosts."""

    def collect(self, domain: str, port: int = 443, timeout: int = 10) -> CertificateFinding:
        """Open a TLS connection and parse the peer certificate."""

        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                der = tls.getpeercert(binary_form=True)
        return self.parse_der(der)

    def parse_der(self, der: bytes) -> CertificateFinding:
        """Parse DER certificate bytes into normalized certificate metadata."""

        cert = x509.load_der_x509_certificate(der)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName
            )
        except x509.ExtensionNotFound:
            san = []
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        return CertificateFinding(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=str(cert.serial_number),
            san=san,
            sha1_fingerprint=cert.fingerprint(hashes.SHA1()).hex(),
            sha256_fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
            valid_from=cert.not_valid_before_utc.astimezone(UTC),
            valid_to=cert.not_valid_after_utc.astimezone(UTC),
            pem=pem,
        )
