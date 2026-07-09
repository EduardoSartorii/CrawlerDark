"""Correlacionador por infraestrutura.

Arquitetura
-----------
Compara ASN, provedor e certificado de um novo site com registros já
persistidos para identificar reuso de infraestrutura entre incidentes.

Responsabilidade do componente
------------------------------
Fornecer sinais booleanos (mesmo ASN, mesmo certificado) usados pelo
Attribution Score do :class:`CampaignCorrelator`.
"""

from __future__ import annotations

from phishing_intel.database.repositories import (
    CertificateRepository,
    InfrastructureRepository,
)
from phishing_intel.logging_config import get_logger
from phishing_intel.models.infrastructure import CertificateInfo, InfrastructureInfo

logger = get_logger(__name__)


class InfrastructureCorrelator:
    """Correlaciona sites por infraestrutura (ASN/provedor/certificado)."""

    def __init__(
        self,
        infra_repository: InfrastructureRepository,
        cert_repository: CertificateRepository,
    ) -> None:
        """Inicializa com os repositórios de infraestrutura e certificados.

        Args:
            infra_repository: Repositório de infraestrutura (ASN/provedor).
            cert_repository: Repositório de certificados (fingerprint/serial).
        """
        self.infra_repository = infra_repository
        self.cert_repository = cert_repository

    def matches_asn(self, infra: InfrastructureInfo) -> bool:
        """Verifica se o ASN já foi observado em outro incidente.

        Args:
            infra: Infraestrutura do site atual.

        Returns:
            ``True`` se o ASN já existir no histórico.
        """
        if not infra.asn:
            return False
        existing = self.infra_repository.find_by_asn(infra.asn)
        matched = len(existing) > 0
        logger.info("asn_correlation", asn=infra.asn, matched=matched)
        return matched

    def matches_certificate(self, cert: CertificateInfo) -> bool:
        """Verifica se o certificado (por fingerprint SHA-256) já foi visto.

        Regra de negócio: reuso do *mesmo* certificado entre domínios é um
        sinal fortíssimo de que a mesma operação está por trás.

        Args:
            cert: Certificado do site atual.

        Returns:
            ``True`` se o fingerprint SHA-256 já existir no histórico.
        """
        if not cert.sha256_fingerprint:
            return False
        existing = self.cert_repository.find_by_fingerprint(
            cert.sha256_fingerprint
        )
        matched = len(existing) > 0
        logger.info(
            "certificate_correlation",
            fingerprint=cert.sha256_fingerprint[:12],
            matched=matched,
        )
        return matched
