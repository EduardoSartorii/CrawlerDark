"""Unit tests for domain entities."""

from __future__ import annotations

import pytest

from threat_hunting.domain.entities import Finding


def test_finding_fingerprint_is_deterministic() -> None:
    finding_one = Finding(
        title="Credential leak",
        description="Leak detected",
        source="reddit",
        connector="reddit",
        category="credential_hunting",
        normalized_data={"ioc": "198.51.100.10"},
    )
    finding_two = Finding(
        title="Credential leak",
        description="Different text but same indicators",
        source="reddit",
        connector="reddit",
        category="credential_hunting",
        normalized_data={"ioc": "198.51.100.10"},
    )
    assert finding_one.fingerprint == finding_two.fingerprint


def test_finding_score_must_be_in_range() -> None:
    with pytest.raises(ValueError):
        Finding(
            title="Invalid score",
            description="Out of bounds score",
            source="reddit",
            connector="reddit",
            category="osint",
            score=200,
        )
