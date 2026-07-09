"""Utilitários compartilhados da plataforma.

Arquitetura
-----------
Funções puras e livres de estado usadas em múltiplos módulos: hashing,
normalização de texto e extração de domínio. Manter estas funções isoladas
evita duplicação e facilita o teste unitário.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

# Regex para URLs http(s) — usado por analisadores de HTML e JS.
URL_REGEX = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)

# Regex para endereços de e-mail (destinos de exfiltração por e-mail).
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
)


def sha256_text(text: str) -> str:
    """Calcula o SHA-256 hexadecimal de uma string (UTF-8).

    Args:
        text: Texto de entrada.

    Returns:
        Digest SHA-256 em hexadecimal.
    """
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Calcula o SHA-256 hexadecimal de um buffer de bytes.

    Args:
        data: Dados binários de entrada.

    Returns:
        Digest SHA-256 em hexadecimal.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_list(items: list[str]) -> str:
    """Calcula um hash estável de uma lista de strings.

    Regra de negócio: a lista é ordenada e deduplicada antes do hash para
    que a ordem de extração não afete o fingerprint (estabilidade).

    Args:
        items: Lista de strings (ex.: nomes de assets/scripts).

    Returns:
        Digest SHA-256 do conteúdo canônico.
    """
    canonical = "\n".join(sorted(set(items)))
    return sha256_text(canonical)


def extract_domain(url: str) -> str:
    """Extrai o hostname (domínio) de uma URL.

    Args:
        url: URL potencialmente com esquema, porta e caminho.

    Returns:
        O hostname em minúsculas, ou string vazia se não for possível
        extrair. Se a URL não tiver esquema, tenta prefixar ``http://``.
    """
    if not url:
        return ""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").lower()


def normalize_text(text: str) -> str:
    """Normaliza texto para heurísticas: minúsculas e espaços colapsados.

    Args:
        text: Texto de entrada.

    Returns:
        Texto normalizado (lowercase, sem espaços redundantes).
    """
    return re.sub(r"\s+", " ", text or "").strip().lower()


def file_name_from_path(path: str) -> str:
    """Extrai o nome de arquivo do final de um caminho/URL.

    Args:
        path: Caminho ou URL (ex.: ``/assets/js/login.min.js``).

    Returns:
        O último segmento não vazio (ex.: ``login.min.js``), ou string vazia.
    """
    if not path:
        return ""
    # Remove querystring/fragment antes de pegar o basename.
    clean = path.split("?", 1)[0].split("#", 1)[0]
    segments = [seg for seg in clean.split("/") if seg]
    return segments[-1] if segments else ""
