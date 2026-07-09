"""SSL/TLS certificate collector.

Component responsibility
------------------------
Retrieve and normalise the X.509 certificate presented by a host, emitting a
:class:`~phishing_intel.models.infrastructure.CertificateInfo`. A reused
certificate (same serial/fingerprint) is one of the strongest campaign
correlation signals, so the full certificate is preserved for the evidence
chain.

Execution flow
--------------
``SSLCollector.collect(host, port)`` -> open a TLS socket -> grab the DER cert
-> parse with ``cryptography`` -> extract subject/issuer/serial/SAN/validity +
SHA1/SHA256 fingerprints -> return ``CertificateInfo``.

The parsing logic is also exposed via ``parse_pem`` so certificates supplied by
partners (as PEM) can be normalised without any network access.
"""

from __future__ import annotations

import socket
import ssl
from datetime import timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from phishing_intel.logging_config import get_logger
from phishing_intel.models.infrastructure import CertificateInfo

logger = get_logger(__name__)

_DEFAULT_TIMEOUT = 10


class SSLCollector:
    """Collect and normalise TLS certificates."""

    def __init__(self, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    def collect(self, host: str, port: int = 443) -> Optional[CertificateInfo]:
        """Fetch the certificate presented by ``host:port``.

        Returns ``None`` on any connection/handshake failure so the pipeline can
        proceed without SSL data.
        """

        try:
            # An unverified context is intentional: phishing hosts frequently
            # present invalid/self-signed certs, but we still want the cert.
            context = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
            if not der:
                logger.warning("ssl.no_certificate", host=host)
                return None
            pem = ssl.DER_cert_to_PEM_cert(der)
            info = self.parse_pem(pem)
            logger.info("ssl.collected", host=host, serial=info.serial_number, sha256=info.sha256_fingerprint)
            return info
        except (OSError, ssl.SSLError, socket.timeout) as exc:
            logger.warning("ssl.collect_failed", host=host, error=str(exc))
            return None

    def parse_pem(self, pem: str) -> CertificateInfo:
        """Parse a PEM certificate into a normalised ``CertificateInfo``.

        This pure function is reused for partner-supplied certificates.
        """

        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))

        # Subject Alternative Names (DNS entries) for pivoting.
        san: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san = []

        # ``not_valid_*_utc`` is the modern, timezone-aware accessor.
        not_before = getattr(cert, "not_valid_before_utc", None)
        not_after = getattr(cert, "not_valid_after_utc", None)
        if not_before is None:  # pragma: no cover - older cryptography fallback
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        if not_after is None:  # pragma: no cover
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        return CertificateInfo(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=format(cert.serial_number, "x"),
            san=san,
            sha1_fingerprint=cert.fingerprint(hashes.SHA1()).hex(),
            sha256_fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
            not_before=not_before,
            not_after=not_after,
            raw_pem=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        )
