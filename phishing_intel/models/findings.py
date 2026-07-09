"""Modelos de achados (findings) produzidos pelos analisadores estaticos.

Responsabilidade do componente
-------------------------------
Representar, de forma tipada e serializavel, os resultados de cada etapa da
analise estatica de um artefato de phishing: estrutura DOM, comportamento de
JavaScript, classificacao do tipo de phishing, destinos de exfiltracao,
fingerprint do kit e marca-alvo detectada.

Fluxo de execucao
------------------
``analyzers/*`` populam estes modelos a partir do HTML/JS bruto. O resultado
agregado (:class:`AnalysisReport`) e o principal artefato consumido pelos
``correlators`` e pela camada de ``enrichment`` (MISP).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, HttpUrl


class PhishingType(str, Enum):
    """Categorias de objetivo de um kit/pagina de phishing.

    A classificacao e usada tanto para taxonomias MISP (``fraude:objetivo``)
    quanto para priorizacao de triagem (ex.: OTP harvesting tende a ser mais
    critico por permitir bypass de MFA em tempo real).
    """

    ACCOUNT_TAKEOVER = "account_takeover"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    IDENTITY_THEFT = "identity_theft"
    CARD_HARVESTING = "card_harvesting"
    OTP_HARVESTING = "otp_harvesting"
    GENERIC_DATA_COLLECTION = "generic_data_collection"
    UNKNOWN = "unknown"


class ExfiltrationChannel(str, Enum):
    """Meio tecnico utilizado para exfiltrar dados capturados pela pagina."""

    HTTP = "http"
    API = "api"
    EMAIL = "email"
    MESSAGING = "messaging"
    CUSTOM = "custom"


class FormFieldFinding(BaseModel):
    """Um campo de input dentro de um formulario HTML."""

    name: str | None = None
    field_id: str | None = None
    field_type: str = "text"
    placeholder: str | None = None
    label: str | None = None
    is_hidden: bool = False
    autocomplete: str | None = None


class FormFinding(BaseModel):
    """Um formulario HTML extraido pelo DOM Analyzer."""

    action: str | None = None
    method: str = "GET"
    form_id: str | None = None
    css_classes: list[str] = Field(default_factory=list)
    fields: list[FormFieldFinding] = Field(default_factory=list)


class ScriptReference(BaseModel):
    """Referencia a um script (inline ou externo) encontrado no HTML."""

    src: str | None = None
    is_inline: bool = False
    filename: str | None = None
    inline_content_hash: str | None = None


class AssetReference(BaseModel):
    """Referencia a um asset estatico (imagem, CSS, fonte) da pagina."""

    url: str
    asset_type: str = "unknown"
    filename: str | None = None


class DomFinding(BaseModel):
    """Resultado estrutural completo da analise de DOM de uma pagina.

    Regra de negocio: a estrutura normalizada (``normalized_structure``) e a
    base para o hash estrutural (``structural_hash``), usado no
    ``kit_fingerprint`` para correlacionar campanhas que reutilizam o mesmo
    kit mesmo apos pequenas alteracoes de conteudo textual.
    """

    forms: list[FormFinding] = Field(default_factory=list)
    scripts: list[ScriptReference] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)
    assets: list[AssetReference] = Field(default_factory=list)
    external_urls: list[str] = Field(default_factory=list)
    meta_tags: dict[str, str] = Field(default_factory=dict)
    comments: list[str] = Field(default_factory=list)
    css_classes: list[str] = Field(default_factory=list)
    html_ids: list[str] = Field(default_factory=list)
    title: str | None = None
    normalized_structure: str = ""
    structural_hash: str = ""


class JavaScriptCallFinding(BaseModel):
    """Uma chamada de rede detectada no JavaScript analisado."""

    call_type: str  # fetch | xhr | axios | jquery_ajax
    destination: str | None = None
    raw_snippet: str = ""


class SecretExposure(BaseModel):
    """Token/chave/segredo exposto encontrado em codigo JavaScript."""

    kind: str  # api_key | jwt | bearer_token | generic_secret
    value_preview: str
    raw_snippet: str = ""


class JavaScriptFinding(BaseModel):
    """Resultado completo da analise estatica de JavaScript."""

    network_calls: list[JavaScriptCallFinding] = Field(default_factory=list)
    hardcoded_urls: list[str] = Field(default_factory=list)
    exposed_secrets: list[SecretExposure] = Field(default_factory=list)
    suspicious_strings: list[str] = Field(default_factory=list)
    external_resources: list[str] = Field(default_factory=list)
    script_hash: str = ""


class ClassificationResult(BaseModel):
    """Resultado da classificacao heuristica do tipo de phishing."""

    phishing_type: PhishingType
    confidence: float = Field(ge=0.0, le=1.0)
    matched_signals: list[str] = Field(default_factory=list)


class ExfiltrationDestination(BaseModel):
    """Um destino identificado de exfiltracao de dados capturados."""

    url: str | None = None
    channel: ExfiltrationChannel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


class ExfiltrationReport(BaseModel):
    """Consolidacao de todos os destinos de exfiltracao identificados."""

    destinations: list[ExfiltrationDestination] = Field(default_factory=list)
    overall_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class KitFingerprint(BaseModel):
    """Fingerprint criptografico do kit de phishing.

    ``campaign_fingerprint`` combina os tres hashes individuais (DOM, assets
    e scripts) em um identificador estavel, usado pelo
    ``fingerprint_correlator`` para reconhecer reuso de infraestrutura entre
    incidentes distintos.
    """

    dom_sha256: str
    assets_sha256: str
    scripts_sha256: str
    campaign_fingerprint: str


class BrandDetectionResult(BaseModel):
    """Marca-alvo identificada pela heuristica de Brand Detection."""

    target_brand: str | None = None
    category: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_keywords: list[str] = Field(default_factory=list)
    matched_domains: list[str] = Field(default_factory=list)


class SslCertificateFinding(BaseModel):
    """Metadados normalizados de um certificado X.509 capturado via TLS."""

    subject: str
    issuer: str
    serial_number: str
    san: list[str] = Field(default_factory=list)
    sha1_fingerprint: str
    sha256_fingerprint: str
    not_before: datetime
    not_after: datetime
    raw_pem: str | None = None


class InfrastructureFinding(BaseModel):
    """Dados de infraestrutura de rede associados ao dominio/IP analisado."""

    domain: str | None = None
    ip: str | None = None
    asn: str | None = None
    asn_organization: str | None = None
    hosting_provider: str | None = None
    country: str | None = None


class ProfileDomSnapshot(BaseModel):
    """Snapshot minimo de DOM capturado sob um perfil de renderizacao especifico."""

    profile_name: str
    structural_hash: str
    asset_urls: list[str] = Field(default_factory=list)
    script_hashes: list[str] = Field(default_factory=list)


class ProfileDiffResult(BaseModel):
    """Resultado da comparacao multi-perfil (ex.: Desktop Chrome x iPhone Safari)."""

    baseline_profile: str
    compared_profile: str
    dom_differs: bool
    assets_diff: list[str] = Field(default_factory=list)
    scripts_diff: list[str] = Field(default_factory=list)


class EvidenceRecord(BaseModel):
    """Registro de cadeia de evidencias (chain of custody) de um artefato."""

    url: HttpUrl | str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    html_sha256: str | None = None
    javascript_sha256: str | None = None
    ssl_sha256_fingerprint: str | None = None
    source: str = "partner_supplied"  # partner_supplied | collected


class AnalysisReport(BaseModel):
    """Relatorio agregado de toda a analise estatica de um artefato de phishing.

    Este e o objeto de "fronteira" entre a camada de analise e as camadas de
    correlacao/enriquecimento: tudo que os correladores e o MISP client
    precisam esta condensado aqui.
    """

    url: str
    evidence: EvidenceRecord
    dom: DomFinding
    javascript: JavaScriptFinding
    classification: ClassificationResult
    exfiltration: ExfiltrationReport
    fingerprint: KitFingerprint
    brand: BrandDetectionResult
    ssl: SslCertificateFinding | None = None
    infrastructure: InfrastructureFinding | None = None
    profile_diffs: list[ProfileDiffResult] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
