"""Correlacionador por fingerprint estrutural.

Arquitetura
-----------
Compara o fingerprint de um novo site com fingerprints já persistidos para
identificar reuso de kit (mesmo DOM/assets/scripts).

Responsabilidade do componente
------------------------------
Fornecer sinais booleanos de correlação de fingerprint usados pelo
Attribution Score do :class:`CampaignCorrelator`.
"""

from __future__ import annotations

from phishing_intel.database.repositories import FingerprintRepository
from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import FingerprintBundle

logger = get_logger(__name__)


class FingerprintCorrelator:
    """Correlaciona sites por seus hashes estruturais."""

    def __init__(self, repository: FingerprintRepository) -> None:
        """Inicializa com o repositório de fingerprints.

        Args:
            repository: Repositório para consultar fingerprints históricos.
        """
        self.repository = repository

    def matches_existing(self, bundle: FingerprintBundle) -> bool:
        """Verifica se o fingerprint composto já foi visto.

        Args:
            bundle: Fingerprint do site atual.

        Returns:
            ``True`` se existir ao menos um registro com o mesmo
            ``campaign_fingerprint``.
        """
        if not bundle.campaign_fingerprint:
            return False
        existing = self.repository.find_by_campaign_fingerprint(
            bundle.campaign_fingerprint
        )
        matched = len(existing) > 0
        logger.info(
            "fingerprint_correlation",
            fingerprint=bundle.campaign_fingerprint[:12],
            matched=matched,
            historical=len(existing),
        )
        return matched
