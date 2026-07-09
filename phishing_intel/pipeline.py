"""Pipeline de orquestração da plataforma.

Arquitetura
-----------
O :class:`Pipeline` é o maestro que conecta coleta, análise, correlação,
persistência e enriquecimento. Ele implementa os dois fluxos da
especificação:

* **Fluxo principal**: artefatos (HTML/JS) já fornecidos -> análise ->
  correlação -> enriquecimento MISP.
* **Fluxo secundário**: HTML ausente -> coleta -> armazena evidências ->
  segue o fluxo principal.

Responsabilidade do componente
------------------------------
Coordenar a ordem de execução e a passagem de dados entre componentes, sem
conter lógica de análise (que vive nos analisadores) nem de I/O de rede
(que vive nos coletores). Toda a persistência é feita via repositórios.

Fluxo de execução
-----------------
``process(request)`` -> (coleta se necessário) -> evidências -> análise ->
IOCs -> infraestrutura/SSL/DNS -> correlação/atribuição -> persistência ->
MISP -> :class:`PipelineResult`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from phishing_intel.analyzers import (
    BrandDetector,
    DomAnalyzer,
    ExfiltrationAnalyzer,
    FormClassifier,
    JavaScriptAnalyzer,
    KitFingerprinter,
)
from phishing_intel.collectors import (
    DnsCollector,
    HtmlCollector,
    InfrastructureCollector,
    SslCollector,
)
from phishing_intel.config.settings import AppConfig
from phishing_intel.correlators import (
    CampaignCorrelator,
    CorrelationInput,
    FingerprintCorrelator,
    InfrastructureCorrelator,
)
from phishing_intel.database.models import (
    CertificateORM,
    FingerprintORM,
    InfrastructureORM,
    MispEventORM,
    PhishingSiteORM,
)
from phishing_intel.database.repositories import RepositoryBundle
from phishing_intel.database.session import Database
from phishing_intel.enrichment import CampaignBuilder, MispClient
from phishing_intel.evidence import EvidenceStore
from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import Campaign, FingerprintBundle
from phishing_intel.models.findings import AnalysisResult
from phishing_intel.models.infrastructure import (
    CertificateInfo,
    DnsRecords,
    InfrastructureInfo,
)
from phishing_intel.utils import URL_REGEX, extract_domain, sha256_text

logger = get_logger(__name__)


@dataclass
class AnalysisRequest:
    """Entrada de uma solicitação de análise.

    Attributes:
        url: URL suspeita (obrigatória para contexto/coleta).
        html: HTML já coletado (fluxo principal). Se vazio, dispara coleta.
        javascript: JavaScript já coletado (opcional).
        collect_infrastructure: Se ``True``, coleta SSL/DNS/infra (rede).
    """

    url: str = ""
    html: str = ""
    javascript: str = ""
    collect_infrastructure: bool = False


@dataclass
class PipelineResult:
    """Resultado consolidado de uma execução do pipeline."""

    analysis: AnalysisResult
    fingerprint: FingerprintBundle
    campaign: Campaign
    infrastructure: InfrastructureInfo = field(default_factory=InfrastructureInfo)
    certificate: CertificateInfo = field(default_factory=CertificateInfo)
    dns: DnsRecords = field(default_factory=DnsRecords)
    evidence_path: str = ""
    misp_event_id: str = ""
    misp_event_uuid: str = ""


class Pipeline:
    """Orquestra o processamento fim-a-fim de artefatos de phishing."""

    def __init__(
        self,
        config: AppConfig,
        database: Database,
        html_collector: HtmlCollector | None = None,
        ssl_collector: SslCollector | None = None,
        dns_collector: DnsCollector | None = None,
        infra_collector: InfrastructureCollector | None = None,
        misp_client: MispClient | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        """Inicializa o pipeline com dependências injetáveis.

        Todos os coletores/cliente MISP são injetáveis para facilitar o teste
        (mocking) e permitir operação offline.

        Args:
            config: Configuração da aplicação.
            database: Camada de banco (fornece sessões).
            html_collector: Coletor de HTML (fluxo secundário).
            ssl_collector: Coletor/parseador de certificados.
            dns_collector: Coletor de DNS.
            infra_collector: Coletor de infraestrutura.
            misp_client: Cliente MISP.
            evidence_store: Armazenamento de evidências.
        """
        self.config = config
        self.database = database

        # Coletores (rede) — injetáveis; criados sob demanda com timeouts.
        self.html_collector = html_collector or HtmlCollector(
            timeout=config.request_timeout
        )
        self.ssl_collector = ssl_collector or SslCollector(
            timeout=config.request_timeout
        )
        self.dns_collector = dns_collector or DnsCollector()
        self.infra_collector = infra_collector or InfrastructureCollector()

        # Analisadores (estáticos, sem rede).
        self.dom_analyzer = DomAnalyzer()
        self.js_analyzer = JavaScriptAnalyzer()
        self.form_classifier = FormClassifier()
        self.exfiltration_analyzer = ExfiltrationAnalyzer()
        self.kit_fingerprinter = KitFingerprinter()
        self.brand_detector = BrandDetector()

        # Enriquecimento.
        self.misp_client = misp_client or MispClient(config.misp)
        self.campaign_builder = CampaignBuilder()

        # Evidências / OPSEC.
        self.evidence_store = evidence_store or EvidenceStore(
            base_dir=config.evidence.storage_dir,
            enabled=config.evidence.store_artifacts,
        )

    def process(self, request: AnalysisRequest) -> PipelineResult:
        """Processa uma solicitação de análise fim-a-fim.

        Args:
            request: Solicitação com URL e, opcionalmente, HTML/JS.

        Returns:
            :class:`PipelineResult` com análise, fingerprint, campanha e
            metadados de enriquecimento.
        """
        html = request.html
        # Fluxo secundário: se o HTML não foi fornecido, coleta.
        if not html and request.url:
            logger.info("pipeline_collecting_html", url=request.url)
            html, _ = self.html_collector.fetch(request.url)

        domain = extract_domain(request.url)

        # --- Análise estática (fluxo principal) ---------------------------
        analysis = self._analyze(request, html, domain)

        # --- Fingerprint de kit ------------------------------------------
        fingerprint = self.kit_fingerprinter.fingerprint(analysis.dom)

        # --- Infraestrutura / SSL / DNS (opcional, requer rede) ----------
        infra, cert, dns = self._collect_infrastructure(request, domain)

        # --- Evidências / cadeia de custódia -----------------------------
        evidence_path = self.evidence_store.store(
            url=request.url,
            html=html,
            javascript=request.javascript,
            analysis_summary=analysis.to_summary(),
            certificate_pem=cert.pem,
        )

        # --- Correlação, persistência e enriquecimento -------------------
        with self.database.session_scope() as session:
            repos = RepositoryBundle.from_session(session)
            campaign = self._correlate(analysis, fingerprint, infra, cert, repos)
            self._persist(analysis, fingerprint, infra, cert, campaign, evidence_path, repos)
            event_id, event_uuid = self._enrich_misp(
                analysis, campaign, infra, cert, fingerprint, repos
            )

        return PipelineResult(
            analysis=analysis,
            fingerprint=fingerprint,
            campaign=campaign,
            infrastructure=infra,
            certificate=cert,
            dns=dns,
            evidence_path=evidence_path,
            misp_event_id=event_id,
            misp_event_uuid=event_uuid,
        )

    def _analyze(
        self, request: AnalysisRequest, html: str, domain: str
    ) -> AnalysisResult:
        """Executa toda a análise estática de HTML/JS.

        Args:
            request: Solicitação original (fornece JS e URL).
            html: HTML (fornecido ou coletado).
            domain: Domínio extraído da URL.

        Returns:
            :class:`AnalysisResult` consolidado.
        """
        dom = self.dom_analyzer.analyze(html, base_url=request.url)

        # O JS analisado inclui os scripts inline do DOM + o JS fornecido.
        js_blocks = list(dom.scripts_inline)
        if request.javascript:
            js_blocks.append(request.javascript)
        js_findings = self.js_analyzer.analyze(js_blocks)

        phishing_types = self.form_classifier.classify(dom)
        exfiltration = self.exfiltration_analyzer.analyze(dom, js_findings)
        brand = self.brand_detector.detect(dom)

        combined_js = "\n".join(js_blocks)
        analysis = AnalysisResult(
            url=request.url,
            domain=domain,
            html_hash=sha256_text(html) if html else "",
            js_hash=sha256_text(combined_js) if combined_js else "",
            dom=dom,
            javascript=js_findings,
            phishing_types=phishing_types,
            exfiltration=exfiltration,
            brand=brand,
            iocs=self._extract_iocs(dom, js_findings, exfiltration),
        )
        logger.info("pipeline_analyzed", **analysis.to_summary())
        return analysis

    def _extract_iocs(self, dom, js_findings, exfiltration) -> dict[str, list[str]]:
        """Consolida os IOCs extraídos em categorias.

        Returns:
            Mapa de categoria -> lista de valores (URLs, domínios, e-mails,
            destinos de exfiltração).
        """
        urls: set[str] = set(dom.external_urls)
        urls.update(js_findings.hardcoded_urls)
        domains = {extract_domain(u) for u in urls}
        domains.discard("")
        exfil_targets = [d.target for d in exfiltration]

        return {
            "urls": sorted(urls),
            "domains": sorted(domains),
            "exfiltration": sorted(exfil_targets),
            "exposed_keys": list(js_findings.exposed_keys),
            "exposed_tokens": list(js_findings.exposed_tokens),
        }

    def _collect_infrastructure(
        self, request: AnalysisRequest, domain: str
    ) -> tuple[InfrastructureInfo, CertificateInfo, DnsRecords]:
        """Coleta infraestrutura/SSL/DNS quando solicitado.

        Args:
            request: Solicitação (flag ``collect_infrastructure``).
            domain: Domínio alvo.

        Returns:
            Tupla ``(infraestrutura, certificado, dns)`` — objetos vazios se
            a coleta não foi solicitada ou falhou.
        """
        infra = InfrastructureInfo(domain=domain)
        cert = CertificateInfo()
        dns = DnsRecords(domain=domain)

        if not request.collect_infrastructure or not domain:
            return infra, cert, dns

        infra = self.infra_collector.collect(domain=domain)
        dns = self.dns_collector.resolve(domain)
        cert = self.ssl_collector.collect(domain)
        return infra, cert, dns

    def _correlate(
        self, analysis, fingerprint, infra, cert, repos: RepositoryBundle
    ) -> Campaign:
        """Executa a correlação e o cálculo do Attribution Score.

        A correlação consulta o histórico *antes* de persistir o site atual,
        de modo que o score reflita reincidências passadas.
        """
        fingerprint_correlator = FingerprintCorrelator(repos.fingerprints)
        infra_correlator = InfrastructureCorrelator(
            repos.infrastructures, repos.certificates
        )
        correlator = CampaignCorrelator(
            fingerprint_correlator,
            infra_correlator,
            config=self.config.correlation,
        )
        return correlator.correlate(
            CorrelationInput(
                analysis=analysis,
                fingerprint=fingerprint,
                infrastructure=infra,
                certificate=cert,
            )
        )

    def _persist(
        self,
        analysis,
        fingerprint,
        infra,
        cert,
        campaign: Campaign,
        evidence_path: str,
        repos: RepositoryBundle,
    ) -> None:
        """Persiste o histórico: campanha, site, fingerprint, infra e cert.

        A ordem importa: a campanha é upsertada primeiro para vincular o site.
        """
        campaign_orm = repos.campaigns.upsert(
            campaign_id=campaign.campaign_id,
            score=campaign.score,
            confidence=campaign.confidence.value,
            target_brand=campaign.target_brand,
            phishing_type=campaign.phishing_type,
        )

        repos.sites.add(
            PhishingSiteORM(
                url=analysis.url,
                domain=analysis.domain,
                html_hash=analysis.html_hash,
                js_hash=analysis.js_hash,
                target_brand=campaign.target_brand,
                phishing_type=campaign.phishing_type,
                evidence_path=evidence_path,
                campaign_id=campaign_orm.id,
            )
        )

        repos.fingerprints.add(
            FingerprintORM(
                dom_hash=fingerprint.dom_hash,
                asset_hash=fingerprint.asset_hash,
                script_hash=fingerprint.script_hash,
                campaign_fingerprint=fingerprint.campaign_fingerprint,
            )
        )

        # Persiste infraestrutura apenas se houver algo relevante.
        if infra.ip or infra.asn:
            repos.infrastructures.add(
                InfrastructureORM(
                    ip=infra.ip,
                    asn=infra.asn,
                    provider=infra.hosting_provider,
                    organization=infra.organization,
                    country=infra.country,
                    domain=infra.domain,
                )
            )

        # Persiste certificado apenas se houver fingerprint/serial.
        if cert.sha256_fingerprint or cert.serial_number:
            repos.certificates.upsert(
                CertificateORM(
                    serial_number=cert.serial_number,
                    issuer=cert.issuer,
                    subject=cert.subject,
                    fingerprint=cert.sha256_fingerprint,
                    not_before=cert.not_before,
                    not_after=cert.not_after,
                    pem=cert.pem,
                )
            )

    def _enrich_misp(
        self, analysis, campaign, infra, cert, fingerprint, repos: RepositoryBundle
    ) -> tuple[str, str]:
        """Enriquece o MISP com o evento da campanha (idempotente).

        Regra de negócio: se já existir um evento MISP para o mesmo
        fingerprint de campanha, não recriamos — evita duplicidade.

        Returns:
            Tupla ``(event_id, event_uuid)``; vazia se o MISP estiver
            indisponível ou o evento já existir.
        """
        existing = repos.misp_events.find_by_fingerprint(
            fingerprint.campaign_fingerprint
        )
        if existing is not None:
            logger.info(
                "misp_event_exists",
                fingerprint=fingerprint.campaign_fingerprint[:12],
            )
            return existing.event_id, existing.event_uuid

        payload = self.campaign_builder.build(analysis, campaign, infra, cert)
        event_id, event_uuid = self.misp_client.push_event(payload)

        # Registra o vínculo apenas se um evento foi de fato criado.
        if event_uuid:
            repos.misp_events.add(
                MispEventORM(
                    event_uuid=event_uuid,
                    event_id=event_id,
                    campaign_fingerprint=fingerprint.campaign_fingerprint,
                )
            )
        return event_id, event_uuid
