"""Orquestrador do pipeline de analise -> correlacao -> persistencia -> MISP.

Responsabilidade do componente
-------------------------------
Este e o modulo de mais alto nivel da plataforma: recebe o HTML/JS de um
incidente (fornecido pelo parceiro ou coletado no fluxo secundario) e
executa, em sequencia, TODA a cadeia de valor da plataforma:

    1. Analise estatica completa (DOM, JavaScript, classificacao,
       exfiltracao, fingerprint de kit, deteccao de marca).
    2. Persistencia do incidente e das evidencias (chain of custody).
    3. Correlacao com o historico e calculo do Attribution Score.
    4. Criacao/atualizacao da campanha correlacionada.
    5. (Opcional) Enriquecimento do evento MISP correspondente.

Fluxo de execucao
------------------
``main.py`` chama exclusivamente ``run_pipeline``; nenhuma outra camada da
aplicacao deve orquestrar estas etapas diretamente, garantindo um unico
ponto de entrada testavel para o fluxo de ponta a ponta.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from analyzers.brand_detector import detect_brand
from analyzers.dom_analyzer import analyze_dom
from analyzers.exfiltration_analyzer import analyze_exfiltration
from analyzers.form_classifier import classify_phishing_type
from analyzers.javascript_analyzer import analyze_javascript
from analyzers.kit_fingerprint import generate_kit_fingerprint
from config.settings import PhishingIntelSettings
from correlators.campaign_correlator import build_or_attach_campaign, correlate_incident
from database.repositories import (
    AuditLogRepository,
    CertificateRepository,
    EvidenceRepository,
    FingerprintRepository,
    InfrastructureRepository,
    MispEventRepository,
    PhishingSiteRepository,
    ProfileComparisonRepository,
)
from enrichment.misp_client import MispClient
from enrichment.taxonomy_mapper import build_tags
from models.campaign import AttributionScore, Campaign
from models.findings import AnalysisReport, EvidenceRecord, InfrastructureFinding, ProfileDiffResult, SslCertificateFinding

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Resultado consolidado da execucao completa do pipeline para um incidente."""

    report: AnalysisReport
    attribution: AttributionScore
    campaign: Campaign
    misp_event_uuid: str | None = None


def _sha256_or_none(content: str | None) -> str | None:
    """Calcula o SHA256 de um conteudo textual, retornando ``None`` se vazio."""
    if not content:
        return None
    return hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()


def build_analysis_report(
    url: str,
    html: str,
    javascript: str = "",
    ssl_finding: SslCertificateFinding | None = None,
    infrastructure_finding: InfrastructureFinding | None = None,
    profile_diffs: list[ProfileDiffResult] | None = None,
    source: str = "partner_supplied",
    settings: PhishingIntelSettings | None = None,
) -> AnalysisReport:
    """Executa toda a cadeia de analisadores estaticos sobre um incidente.

    Args:
        url: URL do incidente analisado.
        html: HTML bruto (fornecido pelo parceiro ou coletado).
        javascript: JavaScript bruto consolidado (inline + externo).
        ssl_finding: Certificado TLS observado, quando disponivel.
        infrastructure_finding: Dados de infraestrutura, quando disponiveis.
        profile_diffs: Resultados da comparacao multi-perfil, quando
            executada.
        source: Origem do artefato (``partner_supplied`` ou ``collected``),
            usada na trilha de evidencias.
        settings: Configuracao tipada da plataforma (marcas conhecidas).

    Returns:
        :class:`AnalysisReport` totalmente populado.
    """
    from config.settings import get_settings

    cfg = settings or get_settings()

    dom = analyze_dom(html, base_url=url)
    javascript_finding = analyze_javascript(javascript)
    classification = classify_phishing_type(dom)
    exfiltration = analyze_exfiltration(dom, javascript_finding)
    fingerprint = generate_kit_fingerprint(dom, javascript_finding)
    brand = detect_brand(html, dom, cfg.brands.known_brands)

    evidence = EvidenceRecord(
        url=url,
        html_sha256=_sha256_or_none(html),
        javascript_sha256=_sha256_or_none(javascript),
        ssl_sha256_fingerprint=ssl_finding.sha256_fingerprint if ssl_finding else None,
        source=source,
    )

    return AnalysisReport(
        url=url,
        evidence=evidence,
        dom=dom,
        javascript=javascript_finding,
        classification=classification,
        exfiltration=exfiltration,
        fingerprint=fingerprint,
        brand=brand,
        ssl=ssl_finding,
        infrastructure=infrastructure_finding,
        profile_diffs=profile_diffs or [],
    )


def persist_report(report: AnalysisReport, session: Session) -> int:
    """Persiste o incidente, evidencias e entidades relacionadas no banco.

    Args:
        report: Relatorio de analise agregado a ser persistido.
        session: Sessao SQLAlchemy ativa (transacao gerenciada pelo chamador).

    Returns:
        O ID do registro ``PhishingSite`` criado.
    """
    from urllib.parse import urlparse

    fingerprint_repo = FingerprintRepository(session)
    certificate_repo = CertificateRepository(session)
    infrastructure_repo = InfrastructureRepository(session)
    site_repo = PhishingSiteRepository(session)
    evidence_repo = EvidenceRepository(session)
    profile_repo = ProfileComparisonRepository(session)
    audit_repo = AuditLogRepository(session)

    fingerprint_row = fingerprint_repo.create(
        dom_hash=report.fingerprint.dom_sha256,
        asset_hash=report.fingerprint.assets_sha256,
        script_hash=report.fingerprint.scripts_sha256,
        campaign_fingerprint=report.fingerprint.campaign_fingerprint,
    )

    certificate_row = None
    if report.ssl:
        certificate_row = certificate_repo.get_or_create(
            subject=report.ssl.subject,
            issuer=report.ssl.issuer,
            serial_number=report.ssl.serial_number,
            sha1_fingerprint=report.ssl.sha1_fingerprint,
            sha256_fingerprint=report.ssl.sha256_fingerprint,
            san=report.ssl.san,
            not_before=report.ssl.not_before,
            not_after=report.ssl.not_after,
            raw_pem=report.ssl.raw_pem,
        )

    infrastructure_row = None
    if report.infrastructure:
        infrastructure_row = infrastructure_repo.create(
            ip=report.infrastructure.ip,
            asn=report.infrastructure.asn,
            provider=report.infrastructure.hosting_provider,
            domain=report.infrastructure.domain,
            country=report.infrastructure.country,
        )

    site = site_repo.create(
        url=report.url,
        domain=urlparse(report.url).netloc or None,
        html_hash=report.evidence.html_sha256,
        javascript_hash=report.evidence.javascript_sha256,
        phishing_type=report.classification.phishing_type.value,
        target_brand=report.brand.target_brand,
        certificate_id=certificate_row.id if certificate_row else None,
        infrastructure_id=infrastructure_row.id if infrastructure_row else None,
        fingerprint_id=fingerprint_row.id,
    )

    evidence_repo.create(
        url=report.url,
        site_id=site.id,
        html_sha256=report.evidence.html_sha256,
        javascript_sha256=report.evidence.javascript_sha256,
        ssl_sha256_fingerprint=report.evidence.ssl_sha256_fingerprint,
        source=report.evidence.source,
    )

    for diff in report.profile_diffs:
        profile_repo.create(
            site_id=site.id,
            baseline_profile=diff.baseline_profile,
            compared_profile=diff.compared_profile,
            dom_differs=diff.dom_differs,
            assets_diff=diff.assets_diff,
            scripts_diff=diff.scripts_diff,
        )

    audit_repo.log(
        action="analysis_completed",
        url=report.url,
        details={
            "phishing_type": report.classification.phishing_type.value,
            "target_brand": report.brand.target_brand,
            "kit_fingerprint": report.fingerprint.campaign_fingerprint,
            "exfiltration_destinations": [d.url for d in report.exfiltration.destinations],
        },
    )

    return site.id


def _link_site_to_campaign(session: Session, site_id: int, campaign_id: str) -> None:
    """Associa o ``PhishingSite`` persistido a campanha resultante da correlacao.

    Regra de negocio: esta ligacao e o que permite que INCIDENTES FUTUROS
    encontrem este site via ``site.campaign_id`` durante a resolucao de
    ``build_or_attach_campaign`` (ver ``correlators/campaign_correlator.py``).
    """
    from database.models import PhishingSite
    from database.repositories import CampaignRepository

    campaign_row = CampaignRepository(session).get_by_campaign_id(campaign_id)
    if campaign_row is None:
        return
    site = session.get(PhishingSite, site_id)
    if site is not None:
        site.campaign_id = campaign_row.id
        session.flush()


def run_pipeline(
    url: str,
    html: str,
    javascript: str,
    session: Session,
    settings: PhishingIntelSettings,
    ssl_finding: SslCertificateFinding | None = None,
    infrastructure_finding: InfrastructureFinding | None = None,
    profile_diffs: list[ProfileDiffResult] | None = None,
    source: str = "partner_supplied",
    misp_client: MispClient | None = None,
) -> PipelineResult:
    """Executa o pipeline completo: analise -> persistencia -> correlacao -> MISP.

    Args:
        url: URL do incidente.
        html: HTML bruto do incidente.
        javascript: JavaScript bruto consolidado do incidente.
        session: Sessao SQLAlchemy ativa.
        settings: Configuracao tipada da plataforma.
        ssl_finding: Certificado TLS observado, quando disponivel.
        infrastructure_finding: Dados de infraestrutura, quando disponiveis.
        profile_diffs: Resultados da comparacao multi-perfil, quando
            executada.
        source: Origem do HTML/JS (``partner_supplied`` ou ``collected``).
        misp_client: Cliente MISP a utilizar. Quando ``None``, o
            enriquecimento MISP e pulado (util em ambientes de teste sem
            uma instancia MISP disponivel).

    Returns:
        :class:`PipelineResult` com o relatorio de analise, o score de
        atribuicao, a campanha resultante e o UUID do evento MISP criado
        (quando aplicavel).
    """
    report = build_analysis_report(
        url=url,
        html=html,
        javascript=javascript,
        ssl_finding=ssl_finding,
        infrastructure_finding=infrastructure_finding,
        profile_diffs=profile_diffs,
        source=source,
        settings=settings,
    )

    # Regra de negocio CRITICA: a correlacao DEVE ocorrer antes da
    # persistencia do incidente atual. Caso contrario, o proprio incidente
    # recem-persistido seria encontrado pelos correlacionadores (mesmo
    # fingerprint/marca que ele mesmo), inflando artificialmente o
    # Attribution Score por autocorrelacao.
    attribution = correlate_incident(report, session, settings.correlation)

    site_id = persist_report(report, session)

    campaign = build_or_attach_campaign(report, attribution, session)
    _link_site_to_campaign(session, site_id, campaign.campaign_id)

    audit_repo = AuditLogRepository(session)
    audit_repo.log(
        action="attribution_score_calculated",
        url=url,
        details={"score": attribution.score, "confidence": attribution.confidence.value, "campaign_id": campaign.campaign_id},
    )

    misp_event_uuid: str | None = None
    if misp_client is not None:
        tags = build_tags(report, campaign, attribution)
        event = misp_client.create_event_for_report(report, tags)
        misp_client.enrich_event(event, report, campaign, attribution)
        misp_event_uuid = getattr(event, "uuid", None)

        if misp_event_uuid:
            from database.repositories import CampaignRepository

            campaign_row = CampaignRepository(session).get_by_campaign_id(campaign.campaign_id)
            MispEventRepository(session).create(
                event_uuid=misp_event_uuid,
                event_id=getattr(event, "id", None),
                campaign_id=campaign_row.id if campaign_row else None,
            )
        audit_repo.log(action="misp_event_enriched", url=url, details={"event_uuid": misp_event_uuid})

    return PipelineResult(report=report, attribution=attribution, campaign=campaign, misp_event_uuid=misp_event_uuid)
