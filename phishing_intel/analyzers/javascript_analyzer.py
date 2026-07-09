"""Analisador estatico de JavaScript.

Responsabilidade do componente
-------------------------------
Aplicar heuristicas baseadas em expressoes regulares sobre o codigo
JavaScript bruto (inline ou de arquivos externos) para identificar chamadas
de rede (``fetch``, ``XMLHttpRequest``, ``axios``, ``jQuery.ajax``), URLs
hardcoded, tokens/chaves expostos e strings suspeitas — sinais essenciais
para reconstruir o metodo de exfiltracao de um kit de phishing sem executar
o codigo (analise puramente estatica, sem sandboxing/execucao real).

Fluxo de execucao
------------------
1. Cada categoria de achado e extraida por uma funcao dedicada usando
   regex compiladas em modulo (custo de compilacao pago uma unica vez).
2. Os resultados sao consolidados em ``models.findings.JavaScriptFinding``,
   incluindo o hash SHA256 do script completo (usado no ``kit_fingerprint``).

Regra de negocio
----------------
Um "segredo exposto" e reportado com um preview truncado do valor (nunca o
valor completo), reduzindo o risco de vazamento secundario de credenciais
reais capturadas por kits de phishing durante a propria analise de CTI.
"""

from __future__ import annotations

import hashlib
import re

from models.findings import JavaScriptCallFinding, JavaScriptFinding, SecretExposure

_FETCH_PATTERN = re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_XHR_OPEN_PATTERN = re.compile(
    r"\.open\s*\(\s*[\"'](?:GET|POST|PUT|DELETE)[\"']\s*,\s*[\"']([^\"']+)[\"']", re.IGNORECASE
)
_AXIOS_PATTERN = re.compile(
    r"axios(?:\.(?:get|post|put|delete))?\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE
)
_JQUERY_AJAX_PATTERN = re.compile(r"\$\.ajax\s*\(\s*\{[^}]*?url\s*:\s*[\"']([^\"']+)[\"']", re.IGNORECASE | re.DOTALL)
_JQUERY_POST_GET_PATTERN = re.compile(r"\$\.(?:post|get)\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)

_HARDCODED_URL_PATTERN = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)

# Regras heuristicas de deteccao de segredos expostos. Cada padrao deve
# conter exatamente um grupo de captura com o valor do segredo.
_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "jwt": re.compile(r"\b(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b"),
    "bearer_token": re.compile(r"[\"']?Bearer\s+([A-Za-z0-9\-_.=]{16,})[\"']?", re.IGNORECASE),
    "api_key": re.compile(
        r"[\"']?(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9\-_.]{12,})[\"']",
        re.IGNORECASE,
    ),
    "aws_access_key": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
}

_SUSPICIOUS_STRING_PATTERNS = [
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"atob\s*\(", re.IGNORECASE),
    re.compile(r"unescape\s*\(", re.IGNORECASE),
    re.compile(r"window\.location\s*=\s*[\"']data:", re.IGNORECASE),
    re.compile(r"navigator\.sendBeacon\s*\(", re.IGNORECASE),
    re.compile(r"new\s+Image\s*\(\s*\)\s*\.src\s*=", re.IGNORECASE),
]


def _extract_network_calls(js: str) -> list[JavaScriptCallFinding]:
    """Extrai todas as chamadas de rede detectaveis estaticamente no JS."""
    calls: list[JavaScriptCallFinding] = []

    for match in _FETCH_PATTERN.finditer(js):
        calls.append(JavaScriptCallFinding(call_type="fetch", destination=match.group(1), raw_snippet=match.group(0)))
    for match in _XHR_OPEN_PATTERN.finditer(js):
        calls.append(JavaScriptCallFinding(call_type="xhr", destination=match.group(1), raw_snippet=match.group(0)))
    for match in _AXIOS_PATTERN.finditer(js):
        calls.append(JavaScriptCallFinding(call_type="axios", destination=match.group(1), raw_snippet=match.group(0)))
    for match in _JQUERY_AJAX_PATTERN.finditer(js):
        calls.append(
            JavaScriptCallFinding(call_type="jquery_ajax", destination=match.group(1), raw_snippet=match.group(0))
        )
    for match in _JQUERY_POST_GET_PATTERN.finditer(js):
        calls.append(
            JavaScriptCallFinding(call_type="jquery_ajax", destination=match.group(1), raw_snippet=match.group(0))
        )
    return calls


def _extract_hardcoded_urls(js: str) -> list[str]:
    """Extrai todas as URLs absolutas hardcoded no codigo (deduplicadas)."""
    seen: set[str] = set()
    ordered: list[str] = []
    for match in _HARDCODED_URL_PATTERN.finditer(js):
        url = match.group(0).rstrip(",;)")
        if url not in seen:
            seen.add(url)
            ordered.append(url)
    return ordered


def _extract_secrets(js: str) -> list[SecretExposure]:
    """Aplica as heuristicas de deteccao de segredos expostos."""
    exposures: list[SecretExposure] = []
    for kind, pattern in _SECRET_PATTERNS.items():
        for match in pattern.finditer(js):
            value = match.group(1)
            preview = f"{value[:6]}...{value[-4:]}" if len(value) > 10 else "***"
            exposures.append(SecretExposure(kind=kind, value_preview=preview, raw_snippet=match.group(0)[:120]))
    return exposures


def _extract_suspicious_strings(js: str) -> list[str]:
    """Identifica trechos de codigo associados a tecnicas de evasao/obfuscacao."""
    findings: list[str] = []
    for pattern in _SUSPICIOUS_STRING_PATTERNS:
        for match in pattern.finditer(js):
            findings.append(match.group(0))
    return findings


def _extract_external_resources(js: str, network_calls: list[JavaScriptCallFinding]) -> list[str]:
    """Consolida destinos de rede + URLs hardcoded como recursos externos usados."""
    resources = {call.destination for call in network_calls if call.destination}
    resources.update(_extract_hardcoded_urls(js))
    return sorted(resources)


def analyze_javascript(js: str) -> JavaScriptFinding:
    """Executa a analise estatica completa de um bloco de codigo JavaScript.

    Args:
        js: Codigo JavaScript bruto (concatenacao de todos os scripts
            inline e externos coletados para a pagina).

    Returns:
        :class:`JavaScriptFinding` com todos os sinais extraidos.
    """
    network_calls = _extract_network_calls(js)
    script_hash = hashlib.sha256(js.encode("utf-8", errors="ignore")).hexdigest()

    return JavaScriptFinding(
        network_calls=network_calls,
        hardcoded_urls=_extract_hardcoded_urls(js),
        exposed_secrets=_extract_secrets(js),
        suspicious_strings=_extract_suspicious_strings(js),
        external_resources=_extract_external_resources(js, network_calls),
        script_hash=script_hash,
    )
