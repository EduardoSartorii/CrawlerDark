"""
Unit tests for the Deduplication Domain Service.

Tests cover:
    - Fingerprint computation
    - Exact duplicate detection
    - Similarity-based duplicate detection
    - Non-duplicate scenarios
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from ....core.domain.services.deduplication_service import (
    DeduplicationService,
    FingerprintStrategy,
)
from ...fixtures.factories import make_finding


class TestFingerprintStrategy:
    """Tests for fingerprint computation."""

    def test_same_finding_same_fingerprint(self):
        f1 = make_finding(
            title="Test Finding",
            connector="reddit",
        )
        f2 = make_finding(
            title="Test Finding",
            connector="reddit",
        )
        fp1 = FingerprintStrategy.compute(f1)
        fp2 = FingerprintStrategy.compute(f2)
        assert fp1 == fp2

    def test_different_title_different_fingerprint(self):
        f1 = make_finding(title="Finding A", connector="reddit")
        f2 = make_finding(title="Finding B", connector="reddit")
        fp1 = FingerprintStrategy.compute(f1)
        fp2 = FingerprintStrategy.compute(f2)
        assert fp1 != fp2

    def test_different_connector_different_fingerprint(self):
        f1 = make_finding(title="Same Title", connector="reddit")
        f2 = make_finding(title="Same Title", connector="github")
        fp1 = FingerprintStrategy.compute(f1)
        fp2 = FingerprintStrategy.compute(f2)
        assert fp1 != fp2

    def test_fingerprint_is_hex_string(self):
        f = make_finding()
        fp = FingerprintStrategy.compute(f)
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_normalizes_whitespace(self):
        f1 = make_finding(title="Finding  With  Extra  Spaces")
        f2 = make_finding(title="Finding With Extra Spaces")
        fp1 = FingerprintStrategy.compute(f1)
        fp2 = FingerprintStrategy.compute(f2)
        assert fp1 == fp2


class TestDeduplicationService:
    """Tests for duplicate detection logic."""

    def test_exact_fingerprint_match_is_duplicate(self):
        svc = DeduplicationService()
        f1 = make_finding(title="Credential Leak", connector="paste")
        f2 = make_finding(title="Credential Leak", connector="paste")
        svc.compute_fingerprint(f1)
        svc.compute_fingerprint(f2)
        result = svc.is_duplicate(f1, f2)
        assert result.is_duplicate is True
        assert result.score == pytest.approx(1.0)

    def test_same_source_id_same_connector_is_duplicate(self):
        svc = DeduplicationService()
        f1 = make_finding()
        f2 = make_finding()
        f1.source_id = "post_abc123"
        f2.source_id = "post_abc123"
        f1.connector = "reddit"
        f2.connector = "reddit"
        result = svc.is_duplicate(f1, f2)
        assert result.is_duplicate is True

    def test_different_source_ids_not_duplicate(self):
        svc = DeduplicationService()
        f1 = make_finding(title="Finding A", connector="reddit")
        f2 = make_finding(title="Finding B completely different", connector="reddit")
        f1.source_id = "id_001"
        f2.source_id = "id_002"
        svc.compute_fingerprint(f1)
        svc.compute_fingerprint(f2)
        result = svc.is_duplicate(f1, f2)
        assert result.is_duplicate is False

    def test_high_similarity_within_window_is_duplicate(self):
        svc = DeduplicationService(similarity_threshold=0.8)
        f1 = make_finding(title="GitHub credential exposure in repository example")
        f2 = make_finding(title="GitHub credential exposure in repository example updated")
        # Both created_at defaults to now, so within window
        result = svc.is_duplicate(f1, f2)
        assert result.is_duplicate is True

    def test_compute_fingerprint_sets_field(self):
        svc = DeduplicationService()
        f = make_finding()
        f.fingerprint = ""
        fingerprint = svc.compute_fingerprint(f)
        assert f.fingerprint == fingerprint
        assert len(fingerprint) == 64
