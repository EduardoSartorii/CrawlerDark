"""Coletor de HTML (fluxo secundário) com suporte a multi-perfil.

Arquitetura
-----------
Quando o HTML não é fornecido pelo parceiro, este coletor o obtém via HTTP.
Suporta múltiplos *perfis de renderização* (User-Agents de Desktop e Mobile)
para permitir a comparação de conteúdo Desktop vs. Mobile (cloaking).

Responsabilidade do componente
------------------------------
* Buscar o HTML de uma URL usando ``requests``.
* NÃO analisar o conteúdo (isso é responsabilidade dos ``analyzers``).
* Ser resiliente: falhas de rede resultam em conteúdo vazio, nunca em crash.

Fluxo de execução
-----------------
``fetch(url, profile)`` -> monta headers do perfil -> GET com timeout ->
retorna ``(html, status_code)``.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from phishing_intel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class RenderProfile:
    """Perfil de renderização (User-Agent + dica de plataforma).

    Attributes:
        name: Nome do perfil (ex.: ``desktop_chrome``).
        user_agent: String de User-Agent enviada no header.
        platform: Categoria (``desktop`` ou ``mobile``) para diffs.
    """

    name: str
    user_agent: str
    platform: str


# Catálogo de perfis exigido pela especificação (Desktop e Mobile).
RENDER_PROFILES: dict[str, RenderProfile] = {
    "desktop_chrome": RenderProfile(
        name="desktop_chrome",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        ),
        platform="desktop",
    ),
    "desktop_edge": RenderProfile(
        name="desktop_edge",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 Edg/124.0"
        ),
        platform="desktop",
    ),
    "desktop_firefox": RenderProfile(
        name="desktop_firefox",
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) "
            "Gecko/20100101 Firefox/126.0"
        ),
        platform="desktop",
    ),
    "android_chrome": RenderProfile(
        name="android_chrome",
        user_agent=(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"
        ),
        platform="mobile",
    ),
    "iphone_safari": RenderProfile(
        name="iphone_safari",
        user_agent=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 "
            "Mobile/15E148 Safari/604.1"
        ),
        platform="mobile",
    ),
}


class HtmlCollector:
    """Obtém HTML de URLs suspeitas quando não fornecido."""

    def __init__(self, timeout: int = 20, session: requests.Session | None = None):
        """Inicializa o coletor.

        Args:
            timeout: Timeout de rede em segundos.
            session: Sessão ``requests`` opcional (facilita injeção/mocking).
        """
        self.timeout = timeout
        # Reutiliza uma sessão para keep-alive; injetável para testes.
        self.session = session or requests.Session()

    def fetch(
        self, url: str, profile: str = "desktop_chrome"
    ) -> tuple[str, int]:
        """Busca o HTML de uma URL usando o perfil de renderização indicado.

        Args:
            url: URL a ser coletada.
            profile: Nome do perfil de renderização (ver ``RENDER_PROFILES``).

        Returns:
            Tupla ``(html, status_code)``. Em caso de erro de rede, retorna
            ``("", 0)`` — o pipeline continua com o que tiver.
        """
        render = RENDER_PROFILES.get(profile, RENDER_PROFILES["desktop_chrome"])
        headers = {"User-Agent": render.user_agent, "Accept": "text/html,*/*"}

        try:
            response = self.session.get(
                url, headers=headers, timeout=self.timeout, allow_redirects=True
            )
            logger.info(
                "html_collected",
                url=url,
                profile=profile,
                status_code=response.status_code,
                bytes=len(response.text),
            )
            return response.text, response.status_code
        except requests.RequestException as exc:
            # Falha de coleta NÃO deve interromper a análise dos artefatos
            # que já possuímos — logamos e seguimos com conteúdo vazio.
            logger.warning("html_collect_failed", url=url, error=str(exc))
            return "", 0

    def fetch_multi_profile(
        self, url: str, profiles: list[str] | None = None
    ) -> dict[str, str]:
        """Coleta o HTML sob múltiplos perfis para comparação Desktop/Mobile.

        Args:
            url: URL a coletar.
            profiles: Lista de nomes de perfis. Se ``None``, usa todos.

        Returns:
            Mapa ``{nome_do_perfil: html}``.
        """
        selected = profiles or list(RENDER_PROFILES.keys())
        results: dict[str, str] = {}
        for profile in selected:
            html, _ = self.fetch(url, profile)
            results[profile] = html
        return results
