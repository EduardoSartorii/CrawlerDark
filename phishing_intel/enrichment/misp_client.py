"""Cliente de integracao MISP via PyMISP (misp_client).

Responsabilidade do componente
-------------------------------
Encapsular toda a interacao com a API do MISP: criacao de eventos,
atributos (``domain``, ``url``, ``ip``, ``x509``, ``file``,
``http-request``), objetos MISP padrao e o objeto customizado
``phishing-campaign`` (contendo ``campaign_id``, ``campaign_score``,
``confidence_level``, ``kit_fingerprint``, ``ssl_fingerprint``,
``ssl_serial``, ``target_brand``, ``phishing_type``, ``hosting_provider``
e ``asn``), alem da aplicacao das tags locais produzidas pelo
``taxonomy_mapper``.

Fluxo de execucao
------------------
1. ``create_event_for_report`` cria (ou reutiliza) o evento MISP para um
   incidente, aplicando as tags de taxonomia.
2. ``enrich_event`` adiciona todos os atributos/objetos derivados do
   :class:`~models.findings.AnalysisReport` (IOCs, certificado, destinos de
   exfiltracao) e o objeto customizado ``phishing-campaign``.
3. O evento e entao publicado (ou mantido como rascunho, conforme politica
   operacional do parceiro de CTI) via ``PyMISP.add_event``/``update_event``.

Regra de negocio (OPSEC)
-------------------------
Nenhuma credencial real capturada por um kit de phishing (senhas, OTPs,
numeros de cartao reais) e enviada ao MISP — apenas METADADOS estruturais
do ataque (URLs de exfiltracao, fingerprints, certificados, infraestrutura).
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from config.settings import MispSettings
from models.campaign import AttributionScore, Campaign
from models.findings import AnalysisReport

logger = logging.getLogger(__name__)

try:
    from pymisp import MISPEvent, MISPObject, PyMISP
except ImportError:  # pragma: no cover - ambiente sem pymisp instalado
    MISPEvent = None  # type: ignore[assignment, misc]
    MISPObject = None  # type: ignore[assignment, misc]
    PyMISP = None  # type: ignore[assignment, misc]


class MispClientError(RuntimeError):
    """Levantado quando a integracao com o MISP falha de forma irrecuperavel."""


class MispClient:
    """Wrapper de alto nivel sobre :class:`pymisp.PyMISP`.

    O client subjacente pode ser injetado (parametro ``client``), o que
    viabiliza testes unitarios completos sem uma instancia MISP real
    (via mocking do ``PyMISP``).
    """

    CUSTOM_OBJECT_NAME = "phishing-campaign"

    def __init__(self, settings: MispSettings, client: "PyMISP | None" = None) -> None:
        self._settings = settings
        if client is not None:
            self._client = client
        else:
            if PyMISP is None:  # pragma: no cover - depende de ambiente
                raise MispClientError("pymisp nao esta instalado neste ambiente.")
            self._client = PyMISP(settings.url, settings.api_key, settings.verify_cert)

    def create_event_for_report(self, report: AnalysisReport, tags: list[str]) -> "MISPEvent":
        """Cria um novo evento MISP representando o incidente analisado.

        Args:
            report: Relatorio de analise agregado do incidente.
            tags: Tags locais (``fraude:*``) a serem aplicadas ao evento.

        Returns:
            O objeto :class:`pymisp.MISPEvent` criado no servidor MISP.
        """
        event = MISPEvent()
        event.info = f"Phishing detectado: {urlparse(report.url).netloc or report.url}"
        event.distribution = self._settings.default_distribution
        event.threat_level_id = self._settings.default_threat_level_id
        event.analysis = self._settings.default_analysis_level

        for tag in tags:
            event.add_tag(tag)

        created = self._client.add_event(event, pythonify=True)
        logger.info("Evento MISP criado: uuid=%s info=%s", getattr(created, "uuid", None), event.info)
        return created

    def add_ioc_attributes(self, event: "MISPEvent", report: AnalysisReport) -> None:
        """Adiciona atributos padrao de IOC (domain, url, ip) ao evento."""
        parsed = urlparse(report.url)

        self._client.add_attribute(event, {"type": "url", "value": report.url, "category": "Network activity"})
        if parsed.netloc:
            self._client.add_attribute(
                event, {"type": "domain", "value": parsed.netloc, "category": "Network activity"}
            )
        if report.infrastructure and report.infrastructure.ip:
            self._client.add_attribute(
                event, {"type": "ip-dst", "value": report.infrastructure.ip, "category": "Network activity"}
            )

    def add_html_evidence_attribute(self, event: "MISPEvent", report: AnalysisReport) -> None:
        """Adiciona o hash SHA256 do HTML coletado como atributo do tipo ``sha256``."""
        if report.evidence.html_sha256:
            self._client.add_attribute(
                event,
                {
                    "type": "sha256",
                    "value": report.evidence.html_sha256,
                    "category": "Payload delivery",
                    "comment": "Hash do HTML da pagina de phishing analisada",
                },
            )

    def add_certificate_object(self, event: "MISPEvent", report: AnalysisReport) -> "MISPObject | None":
        """Cria o objeto MISP ``x509`` com os metadados do certificado TLS observado."""
        if report.ssl is None:
            return None
        x509_object = MISPObject(name="x509", strict=False)
        x509_object.add_attribute("subject", value=report.ssl.subject)
        x509_object.add_attribute("issuer", value=report.ssl.issuer)
        x509_object.add_attribute("serial-number", value=report.ssl.serial_number)
        x509_object.add_attribute("x509-fingerprint-sha1", value=report.ssl.sha1_fingerprint)
        x509_object.add_attribute("x509-fingerprint-sha256", value=report.ssl.sha256_fingerprint)
        x509_object.add_attribute("validity-not-before", value=report.ssl.not_before.isoformat())
        x509_object.add_attribute("validity-not-after", value=report.ssl.not_after.isoformat())
        return self._client.add_object(event, x509_object, pythonify=True)

    def add_exfiltration_objects(self, event: "MISPEvent", report: AnalysisReport) -> list["MISPObject"]:
        """Cria um objeto MISP ``http-request`` para cada destino de exfiltracao identificado."""
        created_objects: list[MISPObject] = []
        for destination in report.exfiltration.destinations:
            if not destination.url:
                continue
            http_object = MISPObject(name="http-request", strict=False)
            http_object.add_attribute("uri", value=destination.url)
            http_object.add_attribute("method", value="POST")
            http_object.add_attribute("text", value=f"channel={destination.channel.value}")
            created_objects.append(self._client.add_object(event, http_object, pythonify=True))
        return created_objects

    def add_phishing_campaign_object(
        self,
        event: "MISPEvent",
        report: AnalysisReport,
        campaign: Campaign,
        attribution: AttributionScore,
    ) -> "MISPObject":
        """Cria o objeto MISP customizado ``phishing-campaign``.

        Campos: ``campaign_id``, ``campaign_score``, ``confidence_level``,
        ``kit_fingerprint``, ``ssl_fingerprint``, ``ssl_serial``,
        ``target_brand``, ``phishing_type``, ``hosting_provider``, ``asn``.
        """
        # `phishing-campaign` e um objeto customizado sem template MISP
        # padrao; por isso cada atributo precisa declarar seu `type`
        # explicitamente (sem template, o PyMISP nao consegue inferi-lo).
        campaign_object = MISPObject(name=self.CUSTOM_OBJECT_NAME, strict=False)
        campaign_object.add_attribute("campaign_id", value=campaign.campaign_id, type="text")
        campaign_object.add_attribute("campaign_score", value=str(attribution.score), type="float")
        campaign_object.add_attribute("confidence_level", value=attribution.confidence.value, type="text")
        campaign_object.add_attribute(
            "kit_fingerprint", value=report.fingerprint.campaign_fingerprint, type="text"
        )
        if report.ssl:
            campaign_object.add_attribute("ssl_fingerprint", value=report.ssl.sha256_fingerprint, type="sha256")
            campaign_object.add_attribute("ssl_serial", value=report.ssl.serial_number, type="text")
        if report.brand.target_brand:
            campaign_object.add_attribute("target_brand", value=report.brand.target_brand, type="text")
        campaign_object.add_attribute(
            "phishing_type", value=report.classification.phishing_type.value, type="text"
        )
        if report.infrastructure:
            if report.infrastructure.hosting_provider:
                campaign_object.add_attribute(
                    "hosting_provider", value=report.infrastructure.hosting_provider, type="text"
                )
            if report.infrastructure.asn:
                campaign_object.add_attribute("asn", value=report.infrastructure.asn, type="AS")

        return self._client.add_object(event, campaign_object, pythonify=True)

    def enrich_event(
        self,
        event: "MISPEvent",
        report: AnalysisReport,
        campaign: Campaign,
        attribution: AttributionScore,
    ) -> None:
        """Executa o enriquecimento completo de um evento ja criado.

        Adiciona IOCs, evidencia de HTML, certificado, destinos de
        exfiltracao e o objeto customizado ``phishing-campaign``.
        """
        self.add_ioc_attributes(event, report)
        self.add_html_evidence_attribute(event, report)
        self.add_certificate_object(event, report)
        self.add_exfiltration_objects(event, report)
        self.add_phishing_campaign_object(event, report, campaign, attribution)
        logger.info(
            "Evento MISP %s enriquecido: campaign=%s score=%s",
            getattr(event, "uuid", None),
            campaign.campaign_id,
            attribution.score,
        )
