"""Motor principal de correlacao de campanhas e atribuicao (campaign_correlator).

Responsabilidade do componente
-------------------------------
Orquestrar os correlacionadores especializados (``fingerprint_correlator``,
``infrastructure_correlator``) mais a correlacao por certificado TLS e por
marca-alvo, agregando todos os sinais produzidos em um unico
:class:`~models.campaign.AttributionScore` (0-100) com nivel de confianca
associado, e decidir se o incidente pertence a uma campanha existente ou
inicia uma nova campanha no historico.

Fluxo de execucao
------------------
1. Coleta sinais de cada correlacionador especializado.
2. Deduplica por TIPO de sinal (a presenca de pelo menos um casamento de um
   tipo conta o peso configurado uma unica vez — múltiplos sites com o
   mesmo fingerprint nao multiplicam o score, apenas reforcam a lista de
   ``correlated_site_urls``).
3. Soma os pesos configurados (``config.yaml`` -> ``correlation.weights``)
   dos tipos presentes, limitando o resultado a 100.
4. Deriva o :class:`~models.campaign.ConfidenceLevel` a partir dos limiares
   configurados (0-39 baixa, 40-69 media, 70-100 alta).
5. ``build_or_attach_campaign`` persiste o incidente: se houver correlacao
   com um site ja associado a uma campanha existente, o incidente e
   anexado a ela (e o score da campanha e recalculado); caso contrario, uma
   nova campanha e criada.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from config.settings import CorrelationSettings
from correlators.fingerprint_correlator import correlate_by_fingerprint
from correlators.infrastructure_correlator import correlate_by_infrastructure
from database.models import Campaign as CampaignOrm
from database.repositories import (
    CampaignRepository,
    CertificateRepository,
    FingerprintRepository,
    InfrastructureRepository,
    PhishingSiteRepository,
)
from models.campaign import AttributionScore, Campaign, ConfidenceLevel, CorrelationSignal, CorrelationSignalType
from models.findings import AnalysisReport, SslCertificateFinding


def _dedupe_signal_types(signals: list[CorrelationSignal]) -> dict[CorrelationSignalType, list[CorrelationSignal]]:
    """Agrupa sinais por tipo, preservando todas as ocorrencias para evidencia."""
    grouped: dict[CorrelationSignalType, list[CorrelationSignal]] = {}
    for signal in signals:
        grouped.setdefault(signal.signal_type, []).append(signal)
    return grouped


def correlate_certificate(
    ssl_finding: SslCertificateFinding | None,
    certificate_repo: CertificateRepository,
    site_repo: PhishingSiteRepository,
) -> list[CorrelationSignal]:
    """Correlaciona por reuso de certificado TLS (mesmo ``sha256_fingerprint``)."""
    if ssl_finding is None:
        return []
    existing = certificate_repo.get_by_fingerprint(ssl_finding.sha256_fingerprint)
    if existing is None:
        return []
    return [
        CorrelationSignal(
            signal_type=CorrelationSignalType.SAME_CERTIFICATE,
            weight=0,
            matched_value=ssl_finding.sha256_fingerprint,
            related_site_url=site.url,
        )
        for site in site_repo.find_by_certificate_id(existing.id)
    ]


def correlate_brand(target_brand: str | None, site_repo: PhishingSiteRepository) -> list[CorrelationSignal]:
    """Correlaciona por marca-alvo identica em incidentes historicos."""
    if not target_brand:
        return []
    return [
        CorrelationSignal(
            signal_type=CorrelationSignalType.SAME_TARGET_BRAND,
            weight=0,
            matched_value=target_brand,
            related_site_url=site.url,
        )
        for site in site_repo.find_by_target_brand(target_brand)
    ]


def calculate_attribution_score(
    signals: list[CorrelationSignal], correlation_settings: CorrelationSettings
) -> AttributionScore:
    """Agrega sinais de correlacao em um Attribution Score final.

    Args:
        signals: Sinais brutos produzidos pelos correlacionadores
            especializados (peso ainda nao aplicado).
        correlation_settings: Pesos e limiares de confianca configurados.

    Returns:
        :class:`AttributionScore` com o score final (0-100), nivel de
        confianca e a lista de sinais com peso ja aplicado.
    """
    weights = correlation_settings.weights.model_dump()
    grouped = _dedupe_signal_types(signals)

    weighted_signals: list[CorrelationSignal] = []
    total_score = 0
    correlated_urls: set[str] = set()

    for signal_type, occurrences in grouped.items():
        weight = weights.get(signal_type.value, 0)
        total_score += weight
        for occurrence in occurrences:
            weighted_signals.append(occurrence.model_copy(update={"weight": weight}))
            if occurrence.related_site_url:
                correlated_urls.add(occurrence.related_site_url)

    final_score = min(100.0, float(total_score))
    confidence = ConfidenceLevel.from_score(
        final_score,
        medium_max=correlation_settings.thresholds.medium_confidence_max,
        low_max=correlation_settings.thresholds.low_confidence_max,
    )

    return AttributionScore(
        score=final_score,
        confidence=confidence,
        signals=weighted_signals,
        correlated_site_urls=sorted(correlated_urls),
    )


def correlate_incident(
    report: AnalysisReport,
    session: Session,
    correlation_settings: CorrelationSettings,
) -> AttributionScore:
    """Executa a correlacao completa de um novo incidente contra o historico.

    Args:
        report: Relatorio de analise agregado do incidente atual.
        session: Sessao SQLAlchemy ativa.
        correlation_settings: Configuracao de pesos/limiares.

    Returns:
        :class:`AttributionScore` calculado para o incidente.
    """
    fingerprint_repo = FingerprintRepository(session)
    infrastructure_repo = InfrastructureRepository(session)
    certificate_repo = CertificateRepository(session)
    site_repo = PhishingSiteRepository(session)

    signals: list[CorrelationSignal] = []
    signals += correlate_by_fingerprint(report.fingerprint, fingerprint_repo, site_repo)
    if report.infrastructure:
        signals += correlate_by_infrastructure(report.infrastructure, infrastructure_repo, site_repo)
    signals += correlate_certificate(report.ssl, certificate_repo, site_repo)
    signals += correlate_brand(report.brand.target_brand, site_repo)

    return calculate_attribution_score(signals, correlation_settings)


def build_or_attach_campaign(
    report: AnalysisReport,
    attribution: AttributionScore,
    session: Session,
) -> Campaign:
    """Cria uma nova campanha ou anexa o incidente a uma campanha existente.

    Regra de negocio: quando ha correlacao com sites ja pertencentes a uma
    campanha, o incidente e anexado a ela e o score da campanha e
    atualizado para o MAIOR score de atribuicao ja observado entre seus
    membros (abordagem conservadora: uma campanha nunca "perde" confianca
    so porque um novo membro tem correlacao ligeiramente mais fraca).
    """
    campaign_repo = CampaignRepository(session)

    existing_campaign: CampaignOrm | None = None
    if attribution.correlated_site_urls:
        site_repo = PhishingSiteRepository(session)
        # Busca direta por URL exata via listagem geral (historico tende a ser
        # pequeno o suficiente por campanha para essa varredura ser aceitavel;
        # em volumes maiores, substituir por um indice dedicado url -> site).
        all_sites = site_repo.list_all()
        for url in attribution.correlated_site_urls:
            for site in all_sites:
                if site.url == url and site.campaign_id:
                    existing_campaign = session.get(CampaignOrm, site.campaign_id)
                    break
            if existing_campaign:
                break

    if existing_campaign is not None:
        updated_score = max(existing_campaign.score, attribution.score)
        updated_confidence = ConfidenceLevel.from_score(updated_score).value
        campaign_repo.update_score(existing_campaign, updated_score, updated_confidence)
        return Campaign(
            campaign_id=existing_campaign.campaign_id,
            score=existing_campaign.score,
            confidence=ConfidenceLevel(existing_campaign.confidence),
            target_brand=existing_campaign.target_brand,
            phishing_type=existing_campaign.phishing_type,
            kit_fingerprint=existing_campaign.kit_fingerprint,
            member_site_urls=list(attribution.correlated_site_urls) + [report.url],
        )

    new_campaign_id = f"CAMP-{uuid.uuid4().hex[:16]}"
    created = campaign_repo.create(
        campaign_id=new_campaign_id,
        score=attribution.score,
        confidence=attribution.confidence.value,
        target_brand=report.brand.target_brand,
        phishing_type=report.classification.phishing_type.value,
        kit_fingerprint=report.fingerprint.campaign_fingerprint,
    )
    return Campaign(
        campaign_id=created.campaign_id,
        score=created.score,
        confidence=ConfidenceLevel(created.confidence),
        target_brand=created.target_brand,
        phishing_type=created.phishing_type,
        kit_fingerprint=created.kit_fingerprint,
        member_site_urls=[report.url],
    )
