"""Motor de correlação de campanhas e Attribution Score.

Arquitetura
-----------
Reúne os sinais dos correlacionadores de fingerprint e infraestrutura, mais
a correlação de marca, e calcula um Attribution Score (0-100) ponderado. O
score é mapeado para um nível de confiança (baixa/média/alta).

Responsabilidade do componente
------------------------------
Ser a autoridade de atribuição: decide o ``campaign_id`` (derivado do
fingerprint composto) e produz um :class:`Campaign` com score, confiança e
os sinais que embasaram a decisão (auditável).

Fluxo de execução
-----------------
``correlate(input)`` -> avalia cada sinal -> soma pesos dos que casaram ->
normaliza para 0-100 -> mapeia confiança -> monta :class:`Campaign`.

Regras de negócio (pesos padrão):
    * fingerprint = 40 (peso alto)
    * certificado = 25 (peso alto)
    * ASN         = 15 (peso médio)
    * provedor    = 10 (peso médio)
    * marca       = 10 (peso médio)

Limiares de confiança: 0-39 baixa, 40-69 média, 70-100 alta.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from phishing_intel.config.settings import CorrelationConfig
from phishing_intel.correlators.fingerprint_correlator import FingerprintCorrelator
from phishing_intel.correlators.infrastructure_correlator import (
    InfrastructureCorrelator,
)
from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import (
    AttributionSignal,
    Campaign,
    ConfidenceLevel,
    FingerprintBundle,
)
from phishing_intel.models.findings import AnalysisResult
from phishing_intel.models.infrastructure import CertificateInfo, InfrastructureInfo

logger = get_logger(__name__)


@dataclass
class CorrelationInput:
    """Entrada agregada para o motor de correlação.

    Attributes:
        analysis: Resultado consolidado da análise de artefatos.
        fingerprint: Bundle de fingerprints do site.
        infrastructure: Metadados de infraestrutura (pode estar vazio).
        certificate: Certificado SSL (pode estar vazio).
    """

    analysis: AnalysisResult
    fingerprint: FingerprintBundle
    infrastructure: InfrastructureInfo = field(default_factory=InfrastructureInfo)
    certificate: CertificateInfo = field(default_factory=CertificateInfo)


class CampaignCorrelator:
    """Correlaciona sites em campanhas e calcula o Attribution Score."""

    def __init__(
        self,
        fingerprint_correlator: FingerprintCorrelator,
        infrastructure_correlator: InfrastructureCorrelator,
        config: CorrelationConfig | None = None,
    ) -> None:
        """Inicializa o motor com os correlacionadores e pesos.

        Args:
            fingerprint_correlator: Correlacionador de fingerprint.
            infrastructure_correlator: Correlacionador de infraestrutura.
            config: Pesos e limiares. Se ``None``, usa os padrões.
        """
        self.fingerprint_correlator = fingerprint_correlator
        self.infrastructure_correlator = infrastructure_correlator
        self.config = config or CorrelationConfig()

    def correlate(self, data: CorrelationInput) -> Campaign:
        """Correlaciona um site e produz a campanha atribuída.

        Args:
            data: Entrada agregada de correlação.

        Returns:
            Um :class:`Campaign` com ``campaign_id``, score, confiança e a
            lista de sinais avaliados.
        """
        signals: list[AttributionSignal] = []

        # Sinal 1: fingerprint composto reincidente (peso alto).
        fp_match = self.fingerprint_correlator.matches_existing(data.fingerprint)
        signals.append(
            AttributionSignal(
                name="fingerprint",
                matched=fp_match,
                weight=self.config.weight_fingerprint,
                detail=f"campaign_fingerprint={data.fingerprint.campaign_fingerprint[:12]}",
            )
        )

        # Sinal 2: mesmo certificado (peso alto).
        cert_match = self.infrastructure_correlator.matches_certificate(
            data.certificate
        )
        signals.append(
            AttributionSignal(
                name="certificate",
                matched=cert_match,
                weight=self.config.weight_certificate,
                detail=f"sha256={data.certificate.sha256_fingerprint[:12]}",
            )
        )

        # Sinal 3: mesmo ASN (peso médio).
        asn_match = self.infrastructure_correlator.matches_asn(data.infrastructure)
        signals.append(
            AttributionSignal(
                name="asn",
                matched=asn_match,
                weight=self.config.weight_asn,
                detail=f"asn={data.infrastructure.asn}",
            )
        )

        # Sinal 4: mesmo provedor de hospedagem (peso médio).
        # (Presença do provedor conta como sinal fraco de agrupamento.)
        provider_match = bool(data.infrastructure.hosting_provider)
        signals.append(
            AttributionSignal(
                name="provider",
                matched=provider_match,
                weight=self.config.weight_provider,
                detail=f"provider={data.infrastructure.hosting_provider}",
            )
        )

        # Sinal 5: marca-alvo identificada (peso médio).
        brand_match = data.analysis.brand is not None
        brand_name = data.analysis.brand.brand if data.analysis.brand else ""
        signals.append(
            AttributionSignal(
                name="brand",
                matched=brand_match,
                weight=self.config.weight_brand,
                detail=f"brand={brand_name}",
            )
        )

        score = self._compute_score(signals)
        confidence = self._confidence_for(score)

        # O ``campaign_id`` é derivado do fingerprint composto: sites com o
        # mesmo kit são atribuídos à mesma campanha, de forma determinística.
        campaign_id = data.fingerprint.campaign_fingerprint[:32] or "unknown"

        phishing_type = (
            data.analysis.phishing_types[0].value
            if data.analysis.phishing_types
            else ""
        )

        campaign = Campaign(
            campaign_id=campaign_id,
            score=score,
            confidence=confidence,
            signals=signals,
            target_brand=brand_name,
            phishing_type=phishing_type,
            hosting_provider=data.infrastructure.hosting_provider,
            asn=data.infrastructure.asn,
            kit_fingerprint=data.fingerprint.campaign_fingerprint,
            ssl_fingerprint=data.certificate.sha256_fingerprint,
            ssl_serial=data.certificate.serial_number,
            site_urls=[data.analysis.url] if data.analysis.url else [],
        )
        logger.info(
            "campaign_correlated",
            campaign_id=campaign_id,
            score=score,
            confidence=confidence.value,
        )
        return campaign

    def _compute_score(self, signals: list[AttributionSignal]) -> int:
        """Calcula o Attribution Score normalizado (0-100).

        Regra de negócio: soma os pesos dos sinais que casaram e normaliza
        pela soma total de pesos possíveis, evitando dependência da escala
        absoluta dos pesos configurados.

        Args:
            signals: Sinais avaliados.

        Returns:
            Score inteiro entre 0 e 100.
        """
        total_weight = sum(s.weight for s in signals) or 1.0
        matched_weight = sum(s.weight for s in signals if s.matched)
        return round((matched_weight / total_weight) * 100)

    def _confidence_for(self, score: int) -> ConfidenceLevel:
        """Mapeia o score numérico para um nível de confiança.

        Args:
            score: Attribution Score 0-100.

        Returns:
            :class:`ConfidenceLevel` conforme os limiares configurados.
        """
        if score >= self.config.threshold_high:
            return ConfidenceLevel.HIGH
        if score >= self.config.threshold_medium:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW
