"""
Core utilities for the Phishing Intelligence Platform.

This module provides shared infrastructure used across collectors, analyzers,
correlators, and enrichment components:

- Structured logging configuration
- Configuration loading from YAML
- Cryptographic hashing utilities
- URL/domain parsing helpers
- Evidence and audit chain management

Architectural Responsibility:
    Centralizes cross-cutting concerns to maintain OPSEC-compliant evidence
    preservation and consistent operational logging across the platform.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog
import yaml

# Module-level logger instance
logger = structlog.get_logger(__name__)

# Default configuration path relative to package root
DEFAULT_CONFIG_PATH = Path(__file__).parent / "config" / "config.yaml"


def setup_logging(level: str = "INFO", log_format: str = "json") -> None:
    """
    Configure structured logging for the platform.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR).
        log_format: Output format ('json' or 'console').
    """
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    log_level = getattr(logging, level.upper(), logging.INFO)
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """
    Load platform configuration from YAML file with environment variable substitution.

    Environment variables in config values use ${VAR_NAME} syntax and are
    replaced at load time for secure credential handling.

    Args:
        config_path: Path to config.yaml. Defaults to package config.

    Returns:
        Parsed configuration dictionary.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    with open(path, encoding="utf-8") as f:
        raw = f.read()

  # Substitute environment variables: ${VAR_NAME} -> os.environ value
    def _env_replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, "")

    raw = re.sub(r"\$\{([^}]+)\}", _env_replace, raw)
    config: dict[str, Any] = yaml.safe_load(raw)
    logger.info("config_loaded", path=str(path))
    return config


def sha256_hash(data: str | bytes) -> str:
    """
    Compute SHA256 hash of input data.

    Args:
        data: String or bytes to hash.

    Returns:
        Hexadecimal SHA256 digest.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha1_hash(data: str | bytes) -> str:
    """
    Compute SHA1 hash of input data (used for certificate fingerprints).

    Args:
        data: String or bytes to hash.

    Returns:
        Hexadecimal SHA1 digest.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha1(data).hexdigest()


def extract_domain(url: str) -> str:
    """
    Extract registrable domain from URL.

    Args:
        url: Full URL string.

    Returns:
        Domain hostname without port.
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.netloc.split(":")[0].lower()


def normalize_url(url: str) -> str:
    """
    Normalize URL for consistent storage and comparison.

    Args:
        url: Raw URL string.

    Returns:
        Normalized URL with scheme and lowercase domain.
    """
    if "://" not in url:
        url = f"https://{url}"
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path or '/'}"


def utc_now() -> datetime:
    """Return current UTC datetime with timezone awareness."""
    return datetime.now(timezone.utc)


class EvidenceStore:
    """
    OPSEC-compliant evidence storage for raw artifacts.

    Preserves HTML, JavaScript, and analysis results with cryptographic
    hashes for chain-of-custody verification in CTI operations.

    Flow:
        1. Store raw artifact with timestamp
        2. Compute and record hash
        3. Return evidence metadata for audit trail
    """

    def __init__(self, storage_path: str | Path) -> None:
        """
        Initialize evidence store.

        Args:
            storage_path: Base directory for evidence files.
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def store(
        self,
        artifact_type: str,
        content: str | bytes,
        url: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Store an evidence artifact with hash and metadata.

        Args:
            artifact_type: Type label (html, javascript, screenshot).
            content: Raw artifact content.
            url: Associated URL for provenance.
            metadata: Optional additional metadata.

        Returns:
            Evidence record with path, hash, and timestamp.
        """
        timestamp = utc_now()
        content_hash = sha256_hash(content)
        filename = f"{timestamp.strftime('%Y%m%d_%H%M%S')}_{content_hash[:16]}_{artifact_type}"

        if isinstance(content, str):
            content = content.encode("utf-8")

        filepath = self.storage_path / filename
        filepath.write_bytes(content)

        record = {
            "artifact_type": artifact_type,
            "filepath": str(filepath),
            "sha256": content_hash,
            "url": url,
            "timestamp": timestamp.isoformat(),
            "metadata": metadata or {},
        }

        # Persist metadata sidecar for audit
        meta_path = filepath.with_suffix(".meta.json")
        meta_path.write_text(json.dumps(record, indent=2, default=str))

        logger.info(
            "evidence_stored",
            artifact_type=artifact_type,
            sha256=content_hash,
            url=url,
        )
        return record


class AuditLogger:
    """
    Complete audit trail for CTI operations.

    Records all analysis operations, MISP submissions, and correlation
  decisions for compliance and operational review.
    """

    def __init__(self, storage_path: str | Path) -> None:
        """
        Initialize audit logger.

        Args:
            storage_path: Directory for audit log files.
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.log_file = self.storage_path / "audit.jsonl"

    def log(
        self,
        operation: str,
        details: dict[str, Any],
        url: str | None = None,
    ) -> None:
        """
        Append an audit record to the immutable log.

        Args:
            operation: Operation type (analyze, correlate, misp_export, etc.).
            details: Operation-specific details.
            url: Optional associated URL.
        """
        record = {
            "timestamp": utc_now().isoformat(),
            "operation": operation,
            "url": url,
            "details": details,
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

        logger.info("audit_logged", operation=operation, url=url)
