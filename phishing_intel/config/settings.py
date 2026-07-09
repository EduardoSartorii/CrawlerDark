"""Carregamento tipado da configuracao operacional (``config.yaml``).

Responsabilidade do componente
-------------------------------
Traduzir o arquivo YAML de configuracao em modelos Pydantic fortemente
tipados, aplicando overrides de variaveis de ambiente para segredos
(chave de API do MISP, credenciais de banco) sem exigir que estes valores
fiquem gravados em texto plano no repositorio.

Regra de negocio
----------------
Overrides de ambiente utilizam o prefixo ``PHISHING_INTEL_`` seguido do
caminho do campo em maiusculas separado por ``__`` (duplo underscore), por
exemplo ``PHISHING_INTEL_MISP__API_KEY``. Isso segue a convencao do
``pydantic-settings`` para configuracoes aninhadas.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"
ENV_PREFIX = "PHISHING_INTEL_"


class DatabaseSettings(BaseModel):
    """Parametros de conexao com o banco de dados relacional."""

    url: str = "sqlite:///phishing_intel.db"
    echo: bool = False


class MispSettings(BaseModel):
    """Parametros de integracao com a instancia MISP do parceiro de CTI."""

    url: str
    api_key: str
    verify_cert: bool = True
    default_distribution: int = 0
    default_threat_level_id: int = 2
    default_analysis_level: int = 1


class RenderProfile(BaseModel):
    """Perfil de navegador utilizado na comparacao multi-perfil (desktop/mobile)."""

    name: str
    user_agent: str


class CollectorSettings(BaseModel):
    """Parametros de coleta HTTP utilizados no fluxo secundario (sem HTML fornecido)."""

    http_timeout_seconds: int = 15
    max_redirects: int = 5
    retry_attempts: int = 2
    user_agent_default: str = "phishing-intel-cti/0.1"
    render_profiles: list[RenderProfile] = Field(default_factory=list)


class CorrelationWeights(BaseModel):
    """Pesos aplicados a cada sinal de correlacao no Attribution Score."""

    same_fingerprint: int = 35
    same_certificate: int = 25
    same_asn: int = 15
    same_hosting_provider: int = 10
    same_dom_pattern: int = 10
    same_javascript_pattern: int = 10
    same_target_brand: int = 10


class CorrelationThresholds(BaseModel):
    """Limites de classificacao de confianca do Attribution Score (0-100)."""

    low_confidence_max: int = 39
    medium_confidence_max: int = 69


class CorrelationSettings(BaseModel):
    """Configuracao do motor de correlacao de campanhas."""

    weights: CorrelationWeights = Field(default_factory=CorrelationWeights)
    thresholds: CorrelationThresholds = Field(default_factory=CorrelationThresholds)


class KnownBrand(BaseModel):
    """Entrada da base de marcas conhecidas usada pelo Brand Detector."""

    name: str
    category: str
    keywords: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)


class BrandSettings(BaseModel):
    """Container da base de marcas conhecidas."""

    known_brands: list[KnownBrand] = Field(default_factory=list)


class LoggingSettings(BaseModel):
    """Parametros do logging estruturado da plataforma."""

    level: str = "INFO"
    json_format: bool = True


class PhishingIntelSettings(BaseModel):
    """Raiz da configuracao operacional da plataforma phishing_intel."""

    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    misp: MispSettings
    collectors: CollectorSettings = Field(default_factory=CollectorSettings)
    correlation: CorrelationSettings = Field(default_factory=CorrelationSettings)
    brands: BrandSettings = Field(default_factory=BrandSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """Aplica overrides de variaveis de ambiente sobre a configuracao bruta.

    Percorre apenas o primeiro e segundo nivel de aninhamento (suficiente
    para os campos sensiveis atuais: ``misp.api_key``, ``misp.url`` e
    ``database.url``), evitando a complexidade de um parser generico de
    caminhos arbitrarios.
    """
    for env_key, env_value in os.environ.items():
        if not env_key.startswith(ENV_PREFIX):
            continue
        path = env_key[len(ENV_PREFIX) :].lower().split("__")
        if len(path) != 2:
            continue
        section, field = path
        if section in raw and isinstance(raw[section], dict) and field in raw[section]:
            raw[section][field] = env_value
    return raw


def load_settings(config_path: Path | str | None = None) -> PhishingIntelSettings:
    """Carrega e valida a configuracao a partir de um arquivo YAML.

    Args:
        config_path: Caminho customizado para o arquivo de configuracao.
            Quando omitido, utiliza ``config/config.yaml`` do pacote.

    Returns:
        Instancia validada de :class:`PhishingIntelSettings`.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    with path.open("r", encoding="utf-8") as stream:
        raw = yaml.safe_load(stream) or {}
    raw = _apply_env_overrides(raw)
    return PhishingIntelSettings.model_validate(raw)


@lru_cache(maxsize=1)
def get_settings() -> PhishingIntelSettings:
    """Retorna a configuracao cacheada (singleton por processo)."""
    return load_settings()
