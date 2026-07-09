"""Tests for utility functions and evidence/audit chain."""

import json
import tempfile
from pathlib import Path

import pytest

from phishing_intel.utils import (
    AuditLogger,
    EvidenceStore,
    extract_domain,
    load_config,
    normalize_url,
    sha256_hash,
    sha1_hash,
)


class TestHashing:
    def test_sha256_string(self):
        result = sha256_hash("test")
        assert len(result) == 64
        assert result == sha256_hash("test")

    def test_sha256_bytes(self):
        assert sha256_hash(b"test") == sha256_hash("test")

    def test_sha1_string(self):
        result = sha1_hash("test")
        assert len(result) == 40


class TestURLUtils:
    def test_extract_domain(self):
        assert extract_domain("https://evil.example.com/path") == "evil.example.com"

    def test_extract_domain_no_scheme(self):
        assert extract_domain("evil.example.com") == "evil.example.com"

    def test_normalize_url(self):
        assert normalize_url("EVIL.EXAMPLE.COM/path") == "https://evil.example.com/path"


class TestConfig:
    def test_load_config(self):
        config = load_config()
        assert "database" in config
        assert "misp" in config
        assert "correlation" in config


class TestEvidenceStore:
    def test_store_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EvidenceStore(tmpdir)
            record = store.store("html", "<html>test</html>", "https://evil.com")
            assert record["artifact_type"] == "html"
            assert len(record["sha256"]) == 64
            assert Path(record["filepath"]).exists()

    def test_store_bytes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = EvidenceStore(tmpdir)
            record = store.store("javascript", b"console.log(1)", "https://evil.com")
            assert record["artifact_type"] == "javascript"


class TestAuditLogger:
    def test_log_operation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLogger(tmpdir)
            audit.log("test_op", {"key": "value"}, "https://evil.com")
            log_file = Path(tmpdir) / "audit.jsonl"
            assert log_file.exists()
            lines = log_file.read_text().strip().split("\n")
            record = json.loads(lines[0])
            assert record["operation"] == "test_op"
            assert record["url"] == "https://evil.com"
