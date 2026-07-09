"""Shared, dependency-light helper utilities.

Responsibility
--------------
House small pure functions reused across analyzers/collectors: cryptographic
hashing, URL/domain parsing and normalisation. Keeping these here avoids
duplicated logic and makes them trivially unit-testable.
"""

from __future__ import annotations

import hashlib
import re
from typing import Iterable, List, Optional
from urllib.parse import urlparse

# Regex matching absolute HTTP(S) URLs anywhere in a blob of text.
URL_REGEX = re.compile(r"https?://[^\s\"'<>()\\]+", re.IGNORECASE)

# Regex matching bare domains (used when a scheme is absent).
DOMAIN_REGEX = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE
)

# Simplistic IPv4 matcher.
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def sha256_text(text: str) -> str:
    """Return the hex SHA256 of a UTF-8 string."""

    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return the hex SHA256 of a byte string."""

    return hashlib.sha256(data).hexdigest()


def sha256_of_iterable(items: Iterable[str]) -> str:
    """Return a stable SHA256 over a collection of strings.

    The items are sorted and de-duplicated before hashing so that ordering
    differences (e.g. asset discovery order) do not change the fingerprint.
    """

    normalised = "\n".join(sorted({item.strip() for item in items if item}))
    return sha256_text(normalised)


def extract_domain(url: str) -> Optional[str]:
    """Extract the lowercased hostname from a URL.

    Falls back to a bare-domain regex when the URL has no scheme, so partner
    inputs such as ``login.example.com/path`` still resolve to a domain.
    """

    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname
    if host:
        return host.lower()
    match = DOMAIN_REGEX.search(url)
    return match.group(0).lower() if match else None


def is_external_url(url: str, base_domain: Optional[str]) -> bool:
    """Return True when ``url`` points to a domain other than ``base_domain``."""

    if not url or not url.lower().startswith(("http://", "https://")):
        return False
    domain = extract_domain(url)
    if domain is None:
        return False
    if base_domain is None:
        return True
    return domain != base_domain.lower()


def filename_from_url(url: str) -> Optional[str]:
    """Return the last path segment (filename) of a URL, if any."""

    if not url:
        return None
    path = urlparse(url if "://" in url else f"http://{url}").path
    segment = path.rsplit("/", 1)[-1]
    return segment or None


def extract_urls(text: str) -> List[str]:
    """Extract and de-duplicate absolute URLs from arbitrary text."""

    seen: dict[str, None] = {}
    for match in URL_REGEX.findall(text or ""):
        cleaned = match.rstrip(".,;)")
        seen.setdefault(cleaned, None)
    return list(seen.keys())


def dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    """De-duplicate a sequence while preserving first-seen order."""

    seen: dict[str, None] = {}
    for item in items:
        if item:
            seen.setdefault(item, None)
    return list(seen.keys())
