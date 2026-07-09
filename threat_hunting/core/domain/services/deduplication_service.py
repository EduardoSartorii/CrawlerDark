"""
Deduplication Domain Service.

Computes deduplication fingerprints for Findings and determines
whether a candidate Finding is a duplicate of an existing one.

This is a pure domain service — no I/O, no external calls.
The application layer provides the repository for lookups.

Business Rules:
    - Fingerprint = hash of (connector, source_url, normalized title, category)
    - Exact fingerprint match → definitive duplicate
    - High similarity score (configurable threshold) → probable duplicate
    - Dedup decision is logged for audit trail
    - Same IOC appearing in different contexts is NOT a duplicate
"""

from __future__ import annotations

import hashlib
import unicodedata
from datetime import timedelta

from ..entities.finding import Finding


class FingerprintStrategy:
    """
    Generates a stable deduplication fingerprint for a Finding.

    Uses SHA-256 of normalized fields to ensure determinism across runs.
    """

    @staticmethod
    def _normalize(text: str) -> str:
        """Normalize text: lowercase, remove accents, collapse whitespace."""
        text = text.lower().strip()
        text = unicodedata.normalize("NFD", text)
        text = "".join(c for c in text if unicodedata.category(c) != "Mn")
        return " ".join(text.split())

    @classmethod
    def compute(cls, finding: Finding) -> str:
        """
        Compute a stable fingerprint from the finding's most stable attributes.

        The fingerprint is deliberately NOT based on volatile fields (score, timestamps)
        to ensure the same real-world finding always produces the same fingerprint.
        """
        components = [
            finding.connector,
            finding.category.value,
            cls._normalize(finding.title),
            finding.source_url or "",
            finding.source_id or "",
        ]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SimilarityResult:
    """Result of a similarity comparison between two findings."""

    def __init__(
        self,
        score: float,
        is_duplicate: bool,
        reason: str = "",
    ) -> None:
        self.score = score
        self.is_duplicate = is_duplicate
        self.reason = reason


class DeduplicationService:
    """
    Pure domain service for finding deduplication.

    The application layer (use case) is responsible for:
    - Providing the repository for fingerprint lookups
    - Persisting dedup decisions

    This service only makes decisions — no I/O.
    """

    def __init__(
        self,
        exact_threshold: float = 1.0,
        similarity_threshold: float = 0.90,
        time_window_hours: int = 24,
    ) -> None:
        """
        Args:
            exact_threshold: Fingerprint match threshold (1.0 = exact only)
            similarity_threshold: Fuzzy similarity threshold [0, 1]
            time_window_hours: How far back to check for duplicates
        """
        self.exact_threshold = exact_threshold
        self.similarity_threshold = similarity_threshold
        self.time_window = timedelta(hours=time_window_hours)

    def compute_fingerprint(self, finding: Finding) -> str:
        """Compute and assign the deduplication fingerprint."""
        fingerprint = FingerprintStrategy.compute(finding)
        finding.fingerprint = fingerprint
        return fingerprint

    def compute_similarity(self, a: Finding, b: Finding) -> float:
        """
        Compute title-based similarity using a simple token overlap metric.
        For production, replace with rapidfuzz.fuzz.ratio for better accuracy.
        """
        tokens_a = set(a.title.lower().split())
        tokens_b = set(b.title.lower().split())
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = len(tokens_a & tokens_b)
        union = len(tokens_a | tokens_b)
        return intersection / union if union else 0.0

    def is_duplicate(self, candidate: Finding, existing: Finding) -> SimilarityResult:
        """
        Determine if candidate is a duplicate of an existing finding.

        Checks:
        1. Exact fingerprint match
        2. Same connector + source_id
        3. High title similarity within time window
        """
        # Exact fingerprint match
        if (
            candidate.fingerprint
            and existing.fingerprint
            and candidate.fingerprint == existing.fingerprint
        ):
            return SimilarityResult(1.0, True, "Exact fingerprint match")

        # Same source ID from same connector
        if (
            candidate.source_id
            and existing.source_id
            and candidate.connector == existing.connector
            and candidate.source_id == existing.source_id
        ):
            return SimilarityResult(1.0, True, "Same source_id from same connector")

        # Fuzzy title similarity within time window
        time_diff = abs(
            (candidate.created_at - existing.created_at).total_seconds()
        )
        if time_diff <= self.time_window.total_seconds():
            similarity = self.compute_similarity(candidate, existing)
            if similarity >= self.similarity_threshold:
                return SimilarityResult(
                    similarity, True,
                    f"Title similarity {similarity:.0%} within {self.time_window}"
                )

        return SimilarityResult(0.0, False, "No duplicate")
