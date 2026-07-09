"""Coletor de certificado SSL/TLS.

Responsabilidade do componente
-------------------------------
Estabelecer uma conexao TLS com o host suspeito e extrair o certificado
X.509 apresentado, normalizando seus metadados (subject, issuer, serial
number, SAN, fingerprints SHA1/SHA256, datas de validade) para o modelo
:class:`~models.findings.SslCertificateFinding`.

Fluxo de execucao
------------------
1. Abre um socket TCP para ``(host, port)``.
2. Envolve o socket em um contexto TLS (``ssl.SSLContext``) sem validar a
   cadeia (o objetivo e capturar o certificado apresentado por um phishing
   kit, que tipicamente usa certificados de terceiros como Let's Encrypt).
3. Extrai o certificado em DER, converte para um objeto ``cryptography``
   e normaliza os campos relevantes.

Regra de negocio
----------------
O certificado SSL e um dos sinais de correlacao de MAIOR peso no motor de
atribuicao: operadores de phishing frequentemente reutilizam a mesma conta
de emissao (ex.: mesma conta ACME) entre multiplas campanhas.
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from models.findings import SslCertificateFinding

logger = logging.getLogger(__name__)


class SslCollectionError(RuntimeError):
    """Levantado quando nao e possivel obter o certificado do host."""


def _to_utc(value: datetime) -> datetime:
    """Garante que um datetime esteja com timezone UTC explicito."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def collect_certificate(host: str, port: int = 443, timeout: float = 10.0) -> SslCertificateFinding:
    """Coleta e normaliza o certificado TLS apresentado por ``host``.

    Args:
        host: Nome de dominio ou IP do endpoint suspeito.
        port: Porta TLS (443 por padrao).
        timeout: Timeout de conexao em segundos.

    Returns:
        :class:`SslCertificateFinding` com os metadados normalizados.

    Raises:
        SslCollectionError: Se a conexao ou o handshake TLS falharem.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        raise SslCollectionError(f"Falha ao coletar certificado de {host}:{port}: {exc}") from exc

    if der_cert is None:
        raise SslCollectionError(f"Nenhum certificado apresentado por {host}:{port}")

    return parse_der_certificate(der_cert)


def parse_der_certificate(der_cert: bytes) -> SslCertificateFinding:
    """Converte bytes DER em :class:`SslCertificateFinding` normalizado."""
    certificate = x509.load_der_x509_certificate(der_cert)

    try:
        san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_values = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_values = []

    sha1_fp = certificate.fingerprint(hashes.SHA1()).hex()
    sha256_fp = certificate.fingerprint(hashes.SHA256()).hex()

    return SslCertificateFinding(
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=str(certificate.serial_number),
        san=list(san_values),
        sha1_fingerprint=sha1_fp,
        sha256_fingerprint=sha256_fp,
        not_before=_to_utc(certificate.not_valid_before_utc),
        not_after=_to_utc(certificate.not_valid_after_utc),
        raw_pem=certificate.public_bytes(Encoding.PEM).decode("ascii"),
    )
