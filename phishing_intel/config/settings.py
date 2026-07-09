"""Carregamento e validação de configuração da plataforma.

Arquitetura
-----------
Este módulo define modelos Pydantic que descrevem toda a configuração da
plataforma e uma função :func:`load_config` que hidrata esses modelos a
partir de um arquivo YAML (com sobreposição por variáveis de ambiente).

Responsabilidade do componente
------------------------------
* Garantir que a configuração seja válida *antes* do pipeline iniciar.
* Fornecer valores padrão seguros para operação (fail-safe).
* Permitir que segredos (ex.: chave do MISP) venham de variáveis de ambiente,
  evitando que credenciais fiquem versionadas no YAML.

Fluxo de execução
-----------------
``load_config(path)`` -> lê YAML -> aplica overrides de ambiente ->
valida com Pydantic -> retorna :class:`AppConfig`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Caminho padrão do arquivo de configuração, relativo a este módulo.
DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.yaml")


class DatabaseConfig(BaseModel):
    """Configuração da camada de persistência.

    Attributes:
        url: URL de conexão SQLAlchemy (ex.: ``sqlite:///phishing_intel.db``).
        echo: Se ``True``, o SQLAlchemy loga todas as queries SQL emitidas.
    """

    url: str = "sqlite:///phishing_intel.db"
    echo: bool = False


class MISPConfig(BaseModel):
    """Configuração de integração com o MISP.

    Regras de negócio:
        * A plataforma deve funcionar mesmo *sem* MISP configurado; por isso
          ``enabled`` controla se o enriquecimento será tentado.
        * ``verify_ssl`` deve ser ``True`` em produção; ``False`` apenas para
          instâncias de laboratório com certificados autoassinados.
    """

    enabled: bool = False
    url: str = ""
    key: str = ""
    verify_ssl: bool = True
    # Distribuição padrão dos eventos criados (0 = organização apenas).
    distribution: int = 0
    # Nível de ameaça padrão (1 = high, 2 = medium, 3 = low, 4 = undefined).
    threat_level_id: int = 2
    # Estado de análise padrão (0 = initial, 1 = ongoing, 2 = completed).
    analysis: int = 0


class LoggingConfig(BaseModel):
    """Configuração de logging estruturado.

    Attributes:
        level: Nível mínimo de log (``DEBUG``, ``INFO``, ``WARNING`` ...).
        json: Se ``True``, emite logs em JSON (ideal para SIEM/coleta).
    """

    # ``populate_by_name`` permite usar tanto a chave YAML ``json`` (alias)
    # quanto o nome de campo ``json_output`` em código, evitando o shadowing
    # do método ``BaseModel.json``.
    model_config = ConfigDict(populate_by_name=True)

    level: str = "INFO"
    json_output: bool = Field(default=True, alias="json")

    @field_validator("level")
    @classmethod
    def _normalize_level(cls, value: str) -> str:
        """Normaliza o nível para maiúsculas e valida contra níveis conhecidos."""
        normalized = value.upper()
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if normalized not in valid:
            raise ValueError(f"Nível de log inválido: {value!r}. Use um de {valid}.")
        return normalized


class EvidenceConfig(BaseModel):
    """Configuração da cadeia de evidências / OPSEC.

    Regras de negócio:
        * Todo artefato (HTML/JS bruto) deve ser preservado em disco para
          fins de auditoria e reprodutibilidade da análise.
    """

    # Diretório raiz onde evidências (HTML/JS brutos) são armazenadas.
    storage_dir: str = "evidence"
    # Se ``True``, artefatos são persistidos em disco.
    store_artifacts: bool = True


class CorrelationConfig(BaseModel):
    """Pesos e limiares do motor de correlação/atribuição.

    Regras de negócio (Attribution Score):
        Cada sinal de correlação contribui com um peso; a soma normalizada
        gera um score de 0 a 100 usado para atribuir campanhas.
    """

    weight_fingerprint: float = 40.0
    weight_certificate: float = 25.0
    weight_asn: float = 15.0
    weight_provider: float = 10.0
    weight_brand: float = 10.0
    # Limiares de confiança conforme especificação (0-39 / 40-69 / 70-100).
    threshold_medium: int = 40
    threshold_high: int = 70


class AppConfig(BaseModel):
    """Configuração raiz da aplicação, agregando todas as seções."""

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    misp: MISPConfig = Field(default_factory=MISPConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)
    # Timeout (segundos) para operações de rede dos coletores.
    request_timeout: int = 20
    # User-Agent padrão usado quando um perfil específico não é informado.
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )


def _apply_env_overrides(raw: dict[str, Any]) -> dict[str, Any]:
    """Sobrepõe valores sensíveis a partir de variáveis de ambiente.

    Regra de negócio: segredos nunca devem ficar apenas no YAML. Se as
    variáveis de ambiente estiverem definidas, elas têm prioridade.

    Args:
        raw: Dicionário de configuração carregado do YAML.

    Returns:
        O mesmo dicionário, com overrides de ambiente aplicados.
    """
    misp_section = raw.setdefault("misp", {})

    # URL e chave do MISP são segredos operacionais → preferir env.
    if os.environ.get("MISP_URL"):
        misp_section["url"] = os.environ["MISP_URL"]
    if os.environ.get("MISP_KEY"):
        misp_section["key"] = os.environ["MISP_KEY"]
    if os.environ.get("MISP_ENABLED"):
        misp_section["enabled"] = os.environ["MISP_ENABLED"].lower() in {
            "1",
            "true",
            "yes",
        }

    # URL do banco também pode vir do ambiente (12-factor).
    if os.environ.get("DATABASE_URL"):
        raw.setdefault("database", {})["url"] = os.environ["DATABASE_URL"]

    return raw


def load_config(path: str | Path | None = None) -> AppConfig:
    """Carrega a configuração a partir de um arquivo YAML.

    Fluxo:
        1. Resolve o caminho (usa o padrão se ``path`` for ``None``).
        2. Lê o YAML se existir; caso contrário, usa apenas os padrões.
        3. Aplica overrides de variáveis de ambiente.
        4. Valida e retorna um :class:`AppConfig`.

    Args:
        path: Caminho para o arquivo YAML. Se ``None``, usa o arquivo
            ``config.yaml`` empacotado ao lado deste módulo.

    Returns:
        Uma instância validada de :class:`AppConfig`.
    """
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH

    raw: dict[str, Any] = {}
    if config_path.exists():
        # ``safe_load`` evita execução de tags arbitrárias do YAML (segurança).
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        if loaded:
            raw = dict(loaded)

    raw = _apply_env_overrides(raw)
    return AppConfig.model_validate(raw)
