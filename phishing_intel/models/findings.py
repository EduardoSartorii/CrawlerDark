"""Modelos de resultados de análise (findings).

Arquitetura
-----------
Define os objetos produzidos pelos analisadores estáticos (DOM, JavaScript,
classificação de formulários, exfiltração, brand detection) e o agregado
:class:`AnalysisResult` que consolida uma análise completa de um artefato.

Responsabilidade do componente
------------------------------
Servir como contrato tipado entre analisadores e as camadas de correlação
e enriquecimento. Nenhum destes modelos executa I/O; são estruturas de dados
puras com validação Pydantic.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PhishingType(str, Enum):
    """Classificação do objetivo da página de phishing.

    Regras de negócio: cada valor mapeia um objetivo de fraude que será
    convertido em tag MISP ``fraude:objetivo=<valor>``.
    """

    ACCOUNT_TAKEOVER = "account_takeover"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    IDENTITY_THEFT = "identity_theft"
    CARD_HARVESTING = "card_harvesting"
    OTP_HARVESTING = "otp"
    GENERIC_DATA_COLLECTION = "generic_data_collection"


class ExfiltrationKind(str, Enum):
    """Categoria do canal de exfiltração detectado."""

    HTTP = "http"
    API = "api"
    EMAIL = "email"
    MESSAGING = "messaging"
    CUSTOM = "custom"


class DomForm(BaseModel):
    """Representa um formulário HTML extraído do DOM.

    Attributes:
        action: Destino do envio (atributo ``action``).
        method: Método HTTP do formulário (``get``/``post``).
        input_names: Nomes dos campos ``<input>`` do formulário.
        input_types: Tipos dos campos (``password``, ``email`` ...).
        hidden_fields: Nomes de campos ocultos (``type=hidden``).
        labels: Textos de rótulos associados aos campos.
        placeholders: Textos de placeholder dos campos.
    """

    action: str = ""
    method: str = "get"
    input_names: list[str] = Field(default_factory=list)
    input_types: list[str] = Field(default_factory=list)
    hidden_fields: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    placeholders: list[str] = Field(default_factory=list)


class DomStructure(BaseModel):
    """Estrutura DOM normalizada extraída de uma página.

    Este objeto é a base para o fingerprint estrutural (hash do DOM) e para
    a classificação de phishing.
    """

    forms: list[DomForm] = Field(default_factory=list)
    scripts_inline: list[str] = Field(default_factory=list)
    scripts_external: list[str] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)
    external_urls: list[str] = Field(default_factory=list)
    meta_tags: dict[str, str] = Field(default_factory=dict)
    comments: list[str] = Field(default_factory=list)
    css_classes: list[str] = Field(default_factory=list)
    html_ids: list[str] = Field(default_factory=list)
    file_names: list[str] = Field(default_factory=list)
    title: str = ""
    # Sequência normalizada de tags (esqueleto do DOM) usada no hash estrutural.
    normalized_skeleton: str = ""


class JavaScriptFindings(BaseModel):
    """Resultados da análise estática de JavaScript."""

    fetch_urls: list[str] = Field(default_factory=list)
    xhr_urls: list[str] = Field(default_factory=list)
    axios_urls: list[str] = Field(default_factory=list)
    jquery_ajax_urls: list[str] = Field(default_factory=list)
    hardcoded_urls: list[str] = Field(default_factory=list)
    exposed_tokens: list[str] = Field(default_factory=list)
    exposed_keys: list[str] = Field(default_factory=list)
    suspicious_strings: list[str] = Field(default_factory=list)
    external_resources: list[str] = Field(default_factory=list)


class ExfiltrationDestination(BaseModel):
    """Destino de exfiltração detectado com score de confiança.

    Attributes:
        target: URL/endpoint/e-mail para onde os dados são enviados.
        kind: Categoria do canal (HTTP/API/e-mail/mensageria/custom).
        source: Onde o destino foi encontrado (``form_action``, ``fetch`` ...).
        confidence: Score 0-100 de confiança de que é exfiltração real.
    """

    target: str
    kind: ExfiltrationKind
    source: str = ""
    confidence: int = 50


class BrandDetection(BaseModel):
    """Resultado da detecção de marca-alvo.

    Attributes:
        brand: Identificador normalizado da marca (ex.: ``itau``).
        sector: Setor da marca (ex.: ``bank``, ``loyalty``).
        confidence: Score 0-100 de confiança na detecção.
        evidence: Trechos/sinais que embasaram a detecção.
    """

    brand: str
    sector: str = ""
    confidence: int = 0
    evidence: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Agregado consolidado de uma análise completa de artefato.

    Este é o objeto central que flui do pipeline de análise para os
    correlacionadores e para o enriquecimento MISP.
    """

    url: str = ""
    domain: str = ""
    html_hash: str = ""
    js_hash: str = ""
    dom: DomStructure = Field(default_factory=DomStructure)
    javascript: JavaScriptFindings = Field(default_factory=JavaScriptFindings)
    phishing_types: list[PhishingType] = Field(default_factory=list)
    exfiltration: list[ExfiltrationDestination] = Field(default_factory=list)
    brand: BrandDetection | None = None
    iocs: dict[str, list[str]] = Field(default_factory=dict)
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_summary(self) -> dict[str, Any]:
        """Retorna um resumo compacto para logging/auditoria.

        Returns:
            Dicionário com os campos mais relevantes da análise, evitando
            dados brutos volumosos (HTML/JS completos).
        """
        return {
            "url": self.url,
            "domain": self.domain,
            "html_hash": self.html_hash,
            "phishing_types": [t.value for t in self.phishing_types],
            "exfiltration_count": len(self.exfiltration),
            "brand": self.brand.brand if self.brand else None,
        }
