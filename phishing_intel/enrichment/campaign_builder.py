"""Construtor de payload de evento MISP a partir de uma campanha.

Arquitetura
-----------
Transforma os objetos de domínio (análise, campanha, infraestrutura,
certificado) em uma estrutura declarativa (:class:`MispEventPayload`) que
descreve o evento, seus atributos, objetos e tags. O :class:`MispClient`
consome esse payload e o materializa via PyMISP.

Responsabilidade do componente
------------------------------
Isolar a *modelagem* do evento MISP da *comunicação* com o MISP, tornando o
mapeamento testável sem necessidade de uma instância MISP real.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from phishing_intel.enrichment.taxonomy_mapper import TaxonomyMapper
from phishing_intel.models.campaign import Campaign
from phishing_intel.models.findings import AnalysisResult
from phishing_intel.models.infrastructure import CertificateInfo, InfrastructureInfo


@dataclass
class MispEventPayload:
    """Descrição declarativa de um evento MISP a ser criado.

    Attributes:
        info: Título do evento.
        tags: Tags locais ``fraude:*``.
        attributes: Lista de atributos ``{type, value, category}``.
        objects: Lista de objetos ``{name, attributes:{...}}``.
    """

    info: str
    tags: list[str] = field(default_factory=list)
    attributes: list[dict[str, Any]] = field(default_factory=list)
    objects: list[dict[str, Any]] = field(default_factory=list)


class CampaignBuilder:
    """Monta o :class:`MispEventPayload` de uma campanha analisada."""

    def __init__(self, taxonomy_mapper: TaxonomyMapper | None = None) -> None:
        """Inicializa o construtor.

        Args:
            taxonomy_mapper: Mapeador de tags. Se ``None``, cria um padrão.
        """
        self.taxonomy_mapper = taxonomy_mapper or TaxonomyMapper()

    def build(
        self,
        analysis: AnalysisResult,
        campaign: Campaign,
        infrastructure: InfrastructureInfo | None = None,
        certificate: CertificateInfo | None = None,
    ) -> MispEventPayload:
        """Constrói o payload do evento MISP.

        Args:
            analysis: Resultado consolidado da análise.
            campaign: Campanha correlacionada.
            infrastructure: Infraestrutura (opcional).
            certificate: Certificado SSL (opcional).

        Returns:
            :class:`MispEventPayload` pronto para ser materializado no MISP.
        """
        infra = infrastructure or InfrastructureInfo()
        cert = certificate or CertificateInfo()

        title = self._build_title(analysis, campaign)
        tags = self.taxonomy_mapper.build_tags(analysis, campaign)

        payload = MispEventPayload(info=title, tags=tags)

        self._add_network_attributes(payload, analysis, infra)
        self._add_exfiltration_attributes(payload, analysis)
        self._add_certificate_object(payload, cert)
        self._add_campaign_object(payload, campaign)

        return payload

    def _build_title(self, analysis: AnalysisResult, campaign: Campaign) -> str:
        """Compõe um título descritivo para o evento."""
        brand = campaign.target_brand or "unknown-brand"
        objetivo = campaign.phishing_type or "phishing"
        return (
            f"[Phishing] {brand} — {objetivo} "
            f"(campanha {campaign.campaign_id[:12]}, "
            f"confiança {campaign.confidence.value})"
        )

    def _add_network_attributes(
        self,
        payload: MispEventPayload,
        analysis: AnalysisResult,
        infra: InfrastructureInfo,
    ) -> None:
        """Adiciona atributos de rede: url, domain, ip.

        Usa os tipos padrão do MISP (``url``, ``domain``, ``ip-dst``).
        """
        if analysis.url:
            payload.attributes.append(
                {"type": "url", "value": analysis.url, "category": "Network activity"}
            )
        if analysis.domain:
            payload.attributes.append(
                {
                    "type": "domain",
                    "value": analysis.domain,
                    "category": "Network activity",
                }
            )
        if infra.ip:
            payload.attributes.append(
                {"type": "ip-dst", "value": infra.ip, "category": "Network activity"}
            )
        # Hash do HTML como atributo ``sha256`` (tipo file) — cadeia de custódia.
        if analysis.html_hash:
            payload.attributes.append(
                {
                    "type": "sha256",
                    "value": analysis.html_hash,
                    "category": "Payload delivery",
                }
            )

    def _add_exfiltration_attributes(
        self, payload: MispEventPayload, analysis: AnalysisResult
    ) -> None:
        """Adiciona os destinos de exfiltração como atributos de URL/e-mail."""
        for dest in analysis.exfiltration:
            attr_type = "email-dst" if dest.kind.value == "email" else "url"
            payload.attributes.append(
                {
                    "type": attr_type,
                    "value": dest.target,
                    "category": "Payload delivery",
                    "comment": f"exfiltration:{dest.kind.value} conf={dest.confidence}",
                }
            )

    def _add_certificate_object(
        self, payload: MispEventPayload, cert: CertificateInfo
    ) -> None:
        """Adiciona um objeto ``x509`` quando há certificado disponível."""
        if not cert.sha256_fingerprint and not cert.serial_number:
            return
        payload.objects.append(
            {
                "name": "x509",
                "attributes": {
                    "x509-fingerprint-sha256": cert.sha256_fingerprint,
                    "x509-fingerprint-sha1": cert.sha1_fingerprint,
                    "serial-number": cert.serial_number,
                    "issuer": cert.issuer,
                    "subject": cert.subject,
                    "validity-not-before": cert.not_before,
                    "validity-not-after": cert.not_after,
                },
            }
        )

    def _add_campaign_object(
        self, payload: MispEventPayload, campaign: Campaign
    ) -> None:
        """Adiciona o objeto customizado ``phishing-campaign``.

        Regra de negócio: este objeto customizado consolida todos os
        metadados de atribuição em uma única entidade correlacionável no MISP.
        """
        payload.objects.append(
            {
                "name": "phishing-campaign",
                # Objeto customizado sem template MISP instalado: os atributos
                # precisam de um tipo explícito (``text``) ao serem criados.
                "custom": True,
                "attributes": {
                    "campaign_id": campaign.campaign_id,
                    "campaign_score": campaign.score,
                    "confidence_level": campaign.confidence.value,
                    "kit_fingerprint": campaign.kit_fingerprint,
                    "ssl_fingerprint": campaign.ssl_fingerprint,
                    "ssl_serial": campaign.ssl_serial,
                    "target_brand": campaign.target_brand,
                    "phishing_type": campaign.phishing_type,
                    "hosting_provider": campaign.hosting_provider,
                    "asn": campaign.asn,
                },
            }
        )
