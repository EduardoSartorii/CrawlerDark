"""Shared utility functions for hashing, IOC extraction, logging, and evidence."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse


URL_RE = re.compile(r"https?://[^\s'\"<>\\)]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-z]{2,}", re.IGNORECASE)


def sha256_text(value: str) -> str:
    """Return the SHA256 digest for a Unicode string."""

    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def sha1_bytes(value: bytes) -> str:
    """Return the SHA1 digest for bytes, used for x509 fingerprints."""

    return hashlib.sha1(value).hexdigest()


def sha256_bytes(value: bytes) -> str:
    """Return the SHA256 digest for bytes."""

    return hashlib.sha256(value).hexdigest()


def extract_domain(url: str | None) -> str | None:
    """Extract and normalize a hostname from a URL or bare domain."""

    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.hostname.lower() if parsed.hostname else None


def extract_iocs(*texts: str | None) -> list[str]:
    """Extract URLs and e-mail addresses from arbitrary artifact text."""

    found: set[str] = set()
    for text in texts:
        if not text:
            continue
        found.update(match.rstrip(".,;") for match in URL_RE.findall(text))
        found.update(match.lower() for match in EMAIL_RE.findall(text))
    return sorted(found)


def configure_logging(debug: bool = False) -> None:
    """Configure JSON-like structured logging with stable CTI fields."""

    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")


def log_event(logger: logging.Logger, event: str, **fields: object) -> None:
    """Write a structured log event without requiring a third-party logger."""

    payload = {"event": event, "timestamp": datetime.now(UTC).isoformat(), **fields}
    logger.info(json.dumps(payload, sort_keys=True, default=str))


def preserve_evidence(base_path: Path, campaign_id: str, name: str, content: str) -> Path:
    """Persist raw evidence under a campaign-specific immutable filename."""

    target_dir = base_path / campaign_id
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / name
    target.write_text(content, encoding="utf-8")
    return target
