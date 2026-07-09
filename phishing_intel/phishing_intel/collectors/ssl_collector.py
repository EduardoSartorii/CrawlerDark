"""SSL certificate collector for phishing infrastructure enrichment."""

from __future__ import annotations

import hashlib
import socket
import ssl

from cryptography import x509
from cryptography.x509 import ExtensionNotFound
from cryptography.hazmat.primitives import serialization

from phishing_intel.models.infrastructure import SslMetadata


class SslCollector:
    """Collect and normalize TLS certificate metadata for a domain."""

    def __init__(self, port: int = 443, timeout: int = 8) -> None:
        self.port = port
        self.timeout = timeout

    def collect(self, domain: str) -> SslMetadata:
        """Retrieve and parse TLS certificate metadata from remote host."""

        context = ssl.create_default_context()
        with socket.create_connection((domain, self.port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der_cert)
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        try:
            san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = san_extension.value.get_values_for_type(x509.DNSName)
        except ExtensionNotFound:
            san = []

        return SslMetadata(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=str(cert.serial_number),
            san=san,
            sha1_fingerprint=hashlib.sha1(der_cert).hexdigest(),  # nosec B303
            sha256_fingerprint=hashlib.sha256(der_cert).hexdigest(),
            not_before=cert.not_valid_before_utc.isoformat(),
            not_after=cert.not_valid_after_utc.isoformat(),
            pem=pem,
        )
