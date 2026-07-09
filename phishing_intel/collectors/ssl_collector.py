"""
SSL/TLS certificate collector.

Extracts and normalizes certificate metadata from target domains
for infrastructure correlation and campaign attribution.

Architectural Responsibility:
    Certificate fingerprinting enables high-confidence correlation
    when the same certificate is reused across phishing deployments.

Flow:
    1. Connect to target host on port 443
    2. Retrieve peer certificate
    3. Parse subject, issuer, SAN, fingerprints
    4. Return normalized certificate metadata
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from phishing_intel.models.findings import SSLCertificate
from phishing_intel.utils import extract_domain, sha1_hash, sha256_hash

logger = structlog.get_logger(__name__)


class SSLCollector:
    """SSL certificate metadata extractor."""

    def __init__(self, timeout: int = 10) -> None:
        """
        Initialize SSL collector.

        Args:
            timeout: Connection timeout in seconds.
        """
        self.timeout = timeout

    def collect(self, url_or_domain: str, port: int = 443) -> SSLCertificate | None:
        """
        Retrieve and parse SSL certificate for target.

        Args:
            url_or_domain: URL or domain name.
            port: TLS port (default 443).

        Returns:
            Parsed SSLCertificate or None on failure.
        """
        domain = extract_domain(url_or_domain)
        logger.info("ssl_collection_start", domain=domain, port=port)

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()

            if not cert_der:
                logger.warning("ssl_no_certificate", domain=domain)
                return None

            cert = x509.load_der_x509_certificate(cert_der)
            return self._parse_certificate(cert, cert_dict, cert_der)

        except (ssl.SSLError, socket.error, OSError) as exc:
            logger.warning("ssl_collection_failed", domain=domain, error=str(exc))
            return None

    def _parse_certificate(
        self,
        cert: x509.Certificate,
        cert_dict: dict[str, Any],
        cert_der: bytes,
    ) -> SSLCertificate:
        """
        Parse x509 certificate into normalized model.

        Args:
            cert: cryptography x509 Certificate object.
            cert_dict: Standard library cert dictionary.
            cert_der: DER-encoded certificate bytes.

        Returns:
            Normalized SSLCertificate model.
        """
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        serial = format(cert.serial_number, "x")

        # Extract Subject Alternative Names
        san_list: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass

        # Compute fingerprints
        sha1_fp = cert.fingerprint(hashes.SHA1()).hex()
        sha256_fp = cert.fingerprint(hashes.SHA256()).hex()

        # Parse validity dates from cert_dict
        not_before = self._parse_cert_date(cert_dict.get("notBefore"))
        not_after = self._parse_cert_date(cert_dict.get("notAfter"))

        pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        result = SSLCertificate(
            subject=subject,
            issuer=issuer,
            serial_number=serial,
            san=san_list,
            sha1_fingerprint=sha1_fp,
            sha256_fingerprint=sha256_fp,
            not_before=not_before,
            not_after=not_after,
            raw_certificate=pem,
        )

        logger.info(
            "ssl_collection_complete",
            subject=subject,
            sha256=sha256_fp,
        )
        return result

    @staticmethod
    def _parse_cert_date(date_str: str | None) -> datetime | None:
        """Parse SSL certificate date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return None
