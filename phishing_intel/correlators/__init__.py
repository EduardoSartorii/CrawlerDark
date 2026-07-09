"""Subpacote de correlacionadores.

Responsabilidade
----------------
Agrupar sites em campanhas com base em sinais compartilhados (fingerprint,
certificado, ASN, provedor, marca) e calcular o Attribution Score que mede a
confiança da atribuição.

Componentes
-----------
* ``campaign_correlator``       — motor principal + Attribution Score.
* ``infrastructure_correlator`` — correlação por ASN/provedor/certificado.
* ``fingerprint_correlator``    — correlação por hashes estruturais.
"""

from __future__ import annotations

from phishing_intel.correlators.campaign_correlator import (
    CampaignCorrelator,
    CorrelationInput,
)
from phishing_intel.correlators.fingerprint_correlator import FingerprintCorrelator
from phishing_intel.correlators.infrastructure_correlator import (
    InfrastructureCorrelator,
)

__all__ = [
    "CampaignCorrelator",
    "CorrelationInput",
    "FingerprintCorrelator",
    "InfrastructureCorrelator",
]
