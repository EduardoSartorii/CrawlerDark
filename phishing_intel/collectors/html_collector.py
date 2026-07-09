"""Coletor de HTML (fluxo secundario).

Responsabilidade do componente
-------------------------------
Obter o HTML bruto de uma URL suspeita quando o parceiro de CTI NAO o
fornece previamente. Suporta multiplos perfis de renderizacao (Desktop
Chrome/Edge/Firefox, Android Chrome, iPhone Safari) atraves da troca do
cabecalho ``User-Agent``, viabilizando a comparacao multi-perfil exigida
pela plataforma (ver ``analyzers/profile_comparator.py``).

Fluxo de execucao
------------------
1. ``fetch_html`` executa um GET HTTP simples com o perfil solicitado.
2. ``fetch_html_multi_profile`` repete a coleta para todos os perfis
   configurados em ``config.yaml`` (``collectors.render_profiles``),
   retornando um mapa ``nome_do_perfil -> CollectedHtml``.

Regra de negocio
----------------
Este modulo NUNCA e chamado quando o HTML ja foi fornecido pelo parceiro —
a decisao de qual fluxo utilizar e responsabilidade de ``main.py``.
"""

from __future__ import annotations

import logging

import requests
from pydantic import BaseModel

from config.settings import CollectorSettings, RenderProfile

logger = logging.getLogger(__name__)


class CollectedHtml(BaseModel):
    """Resultado bruto da coleta de uma pagina HTML."""

    url: str
    final_url: str
    status_code: int
    html: str
    profile_name: str = "default"
    headers: dict[str, str] = {}


class HtmlCollectionError(RuntimeError):
    """Levantado quando a coleta de HTML falha de forma irrecuperavel."""


def fetch_html(
    url: str,
    settings: CollectorSettings,
    user_agent: str | None = None,
    profile_name: str = "default",
) -> CollectedHtml:
    """Coleta o HTML bruto de uma URL suspeita.

    Args:
        url: URL suspeita a ser coletada.
        settings: Configuracao de coleta (timeout, redirects, retries).
        user_agent: User-Agent customizado (perfil de renderizacao).
        profile_name: Nome do perfil de renderizacao utilizado.

    Returns:
        :class:`CollectedHtml` com o HTML bruto e metadados da resposta.

    Raises:
        HtmlCollectionError: Se todas as tentativas de coleta falharem.
    """
    headers = {"User-Agent": user_agent or settings.user_agent_default}
    last_error: Exception | None = None

    # Regra de negocio: tentativas adicionais (retry) sao aplicadas somente
    # a falhas de rede/timeout, nunca a respostas HTTP validas (mesmo 4xx/5xx),
    # pois um phishing kit pode legitimamente responder com paginas de erro
    # customizadas que ainda sao relevantes para a analise.
    for attempt in range(settings.retry_attempts + 1):
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=settings.http_timeout_seconds,
                allow_redirects=True,
            )
            return CollectedHtml(
                url=url,
                final_url=response.url,
                status_code=response.status_code,
                html=response.text,
                profile_name=profile_name,
                headers=dict(response.headers),
            )
        except requests.RequestException as exc:
            last_error = exc
            logger.warning(
                "Falha ao coletar HTML (tentativa %s/%s) de %s: %s",
                attempt + 1,
                settings.retry_attempts + 1,
                url,
                exc,
            )

    raise HtmlCollectionError(f"Nao foi possivel coletar HTML de {url}: {last_error}")


def fetch_html_multi_profile(
    url: str,
    settings: CollectorSettings,
    profiles: list[RenderProfile] | None = None,
) -> dict[str, CollectedHtml]:
    """Coleta o mesmo recurso sob multiplos perfis de renderizacao.

    Usado para alimentar o ``profile_comparator``, que identifica se o kit
    de phishing serve conteudo diferente para desktop e mobile (tecnica
    comum de evasao de sandboxes/crawlers automatizados).
    """
    active_profiles = profiles if profiles is not None else settings.render_profiles
    results: dict[str, CollectedHtml] = {}
    for profile in active_profiles:
        try:
            results[profile.name] = fetch_html(
                url, settings, user_agent=profile.user_agent, profile_name=profile.name
            )
        except HtmlCollectionError as exc:
            logger.error("Perfil %s falhou para %s: %s", profile.name, url, exc)
    return results
