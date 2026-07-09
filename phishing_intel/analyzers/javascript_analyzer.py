"""Analisador estático de JavaScript.

Arquitetura
-----------
Aplica expressões regulares sobre o código JS (inline ou de arquivos) para
extrair chamadas de rede (fetch/XHR/axios/jQuery.ajax), URLs hardcoded,
tokens/chaves expostos, strings suspeitas e recursos externos.

Responsabilidade do componente
------------------------------
Fornecer sinais que alimentam o :class:`ExfiltrationAnalyzer` (destinos de
coleta) e a extração de IOCs. Não executa JS — apenas análise estática.

Fluxo de execução
-----------------
``analyze(js_list)`` -> concatena -> aplica regex por categoria ->
:class:`JavaScriptFindings`.
"""

from __future__ import annotations

import re

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import JavaScriptFindings
from phishing_intel.utils import URL_REGEX

logger = get_logger(__name__)

# --- Regex de chamadas de rede -------------------------------------------
# Capturam o primeiro argumento string (a URL) de cada API.
_FETCH_RE = re.compile(r"""fetch\s*\(\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE)
_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)
_AXIOS_RE = re.compile(
    r"""axios(?:\.(?:get|post|put|delete|patch|request))?\s*\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)
_JQUERY_AJAX_RE = re.compile(
    r"""(?:\$|jQuery)\.(?:ajax|get|post)\s*\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)
# Também captura ``url:`` dentro de objetos de configuração de jQuery.ajax.
_AJAX_URL_KEY_RE = re.compile(
    r"""url\s*:\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE
)

# --- Regex de segredos / strings suspeitas -------------------------------
# Chaves de API/serviços comuns (Google, Stripe, AWS) e tokens JWT/bearer.
_KEY_RE = re.compile(
    r"""(?:AIza[0-9A-Za-z_\-]{20,}|sk_(?:live|test)_[0-9A-Za-z]{10,}|AKIA[0-9A-Z]{16})"""
)
_TOKEN_RE = re.compile(
    r"""(?:eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+|(?:bearer|token|api[_-]?key)["'`\s:=]+[A-Za-z0-9_\-]{16,})""",
    re.IGNORECASE,
)
# Padrões que sugerem coleta/exfiltração de credenciais.
_SUSPICIOUS_TERMS = (
    "sendtotelegram",
    "telegram.org",
    "bot",
    "chat_id",
    "exfil",
    "gate.php",
    "result.php",
    "save.php",
    "next.php",
    "log.php",
    "grabber",
    "webhook",
    "onclick=submit",
    "atob(",
    "eval(",
    "document.forms",
    "mail(",
    "sendmail",
)


class JavaScriptAnalyzer:
    """Extrai IOCs e chamadas de rede de código JavaScript."""

    def analyze(self, scripts: list[str] | str) -> JavaScriptFindings:
        """Analisa um ou mais blocos de JavaScript.

        Args:
            scripts: Uma string única ou uma lista de blocos de JS (inline
                e/ou conteúdo de arquivos ``.js``).

        Returns:
            :class:`JavaScriptFindings` com todos os sinais extraídos
            (listas deduplicadas e ordenadas para estabilidade).
        """
        if isinstance(scripts, str):
            scripts = [scripts]
        code = "\n".join(s for s in scripts if s)

        findings = JavaScriptFindings()
        if not code:
            return findings

        findings.fetch_urls = self._dedup(_FETCH_RE.findall(code))
        findings.xhr_urls = self._dedup(_XHR_OPEN_RE.findall(code))
        findings.axios_urls = self._dedup(_AXIOS_RE.findall(code))
        # jQuery.ajax pode aparecer como primeiro argumento ou como ``url:``.
        jquery = _JQUERY_AJAX_RE.findall(code) + _AJAX_URL_KEY_RE.findall(code)
        findings.jquery_ajax_urls = self._dedup(jquery)

        findings.hardcoded_urls = self._dedup(URL_REGEX.findall(code))
        findings.exposed_keys = self._dedup(_KEY_RE.findall(code))
        findings.exposed_tokens = self._dedup(_TOKEN_RE.findall(code))
        findings.suspicious_strings = self._find_suspicious(code)

        # Recursos externos = URLs hardcoded (base para correlação de infra).
        findings.external_resources = findings.hardcoded_urls

        logger.info(
            "javascript_analyzed",
            fetch=len(findings.fetch_urls),
            xhr=len(findings.xhr_urls),
            suspicious=len(findings.suspicious_strings),
        )
        return findings

    def _find_suspicious(self, code: str) -> list[str]:
        """Detecta termos/padrões suspeitos de exfiltração no código.

        Args:
            code: Código JavaScript concatenado.

        Returns:
            Lista dos termos suspeitos efetivamente encontrados.
        """
        lowered = code.lower()
        found = [term for term in _SUSPICIOUS_TERMS if term in lowered]
        return sorted(set(found))

    @staticmethod
    def _dedup(items: list[str]) -> list[str]:
        """Remove duplicatas preservando determinismo (ordenação).

        Args:
            items: Lista possivelmente com duplicatas.

        Returns:
            Lista ordenada e sem duplicatas.
        """
        return sorted({item.strip() for item in items if item and item.strip()})
