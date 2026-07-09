"""Coletor/analisador de certificados SSL/TLS.

Arquitetura
-----------
Obtém o certificado X.509 apresentado por um host TLS e o normaliza em
:class:`CertificateInfo`. Também é capaz de parsear um PEM já fornecido pelo
parceiro (fluxo principal), sem necessidade de rede.

Responsabilidade do componente
------------------------------
Extrair subject, issuer, serial, SAN, fingerprints SHA-1/SHA-256 e datas de
validade, preservando o PEM completo para a cadeia de evidências.

Fluxo de execução
-----------------
``collect(host, port)`` -> abre socket TLS -> obtém DER -> ``parse_pem`` ->
:class:`CertificateInfo`.
"""

from __future__ import annotations

import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from phishing_intel.logging_config import get_logger
from phishing_intel.models.infrastructure import CertificateInfo

logger = get_logger(__name__)


class SslCollector:
    """Coleta e normaliza certificados SSL/TLS."""

    def __init__(self, timeout: int = 20) -> None:
        """Inicializa o coletor.

        Args:
            timeout: Timeout do handshake TLS em segundos.
        """
        self.timeout = timeout

    def parse_pem(self, pem: str) -> CertificateInfo:
        """Normaliza um certificado a partir de seu PEM.

        Este é o caminho preferencial: se o parceiro já forneceu o PEM,
        nenhuma conexão de rede é necessária (fluxo principal).

        Args:
            pem: Certificado em formato PEM.

        Returns:
            :class:`CertificateInfo` com metadados normalizados; em caso de
            PEM inválido, retorna um objeto vazio com o PEM preservado.
        """
        try:
            cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
            return self._normalize(cert, pem)
        except Exception as exc:  # pragma: no cover - defensivo
            logger.warning("ssl_pem_parse_failed", error=str(exc))
            return CertificateInfo(pem=pem)

    def collect(self, host: str, port: int = 443) -> CertificateInfo:
        """Coleta o certificado apresentado por ``host:port`` via TLS.

        Args:
            host: Hostname alvo.
            port: Porta TLS (padrão 443).

        Returns:
            :class:`CertificateInfo` normalizado; objeto vazio em caso de
            falha de rede/TLS (resiliência).
        """
        # ``PROTOCOL_TLS_CLIENT`` valida por padrão; desativamos verificação
        # de hostname/cadeia porque queremos capturar o certificado *como
        # apresentado*, mesmo se autoassinado (comum em phishing).
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der)
            pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            logger.info("ssl_collected", host=host, port=port)
            return self._normalize(cert, pem)
        except (OSError, ssl.SSLError, ValueError) as exc:
            logger.warning("ssl_collect_failed", host=host, error=str(exc))
            return CertificateInfo()

    def _normalize(self, cert: x509.Certificate, pem: str) -> CertificateInfo:
        """Converte um objeto ``cryptography`` em :class:`CertificateInfo`.

        Args:
            cert: Certificado parseado.
            pem: PEM original (preservado para evidências).

        Returns:
            Metadados normalizados do certificado.
        """
        # SAN pode não existir; tratamos a ausência de forma tolerante.
        san_values: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san_values = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_values = []

        sha1 = cert.fingerprint(hashes.SHA1()).hex()
        sha256 = cert.fingerprint(hashes.SHA256()).hex()

        return CertificateInfo(
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            serial_number=str(cert.serial_number),
            san=san_values,
            sha1_fingerprint=sha1,
            sha256_fingerprint=sha256,
            not_before=cert.not_valid_before_utc.isoformat(),
            not_after=cert.not_valid_after_utc.isoformat(),
            pem=pem,
        )
