"""Testes dos Value Objects — imutabilidade, validação, ordenação."""

from __future__ import annotations

import pytest

from threat_hunting.core.domain.value_objects import (
    Category,
    Confidence,
    Score,
    Severity,
    TLP,
)


class TestSeverity:
    def test_from_string_case_insensitive(self):
        assert Severity.from_string("high") is Severity.HIGH
        assert Severity.from_string("CRITICAL") is Severity.CRITICAL

    def test_from_string_invalid(self):
        with pytest.raises(ValueError):
            Severity.from_string("nope")

    def test_ordering(self):
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


class TestScore:
    def test_clamps_upper_bound(self):
        assert Score(200.0).value == 100.0

    def test_clamps_lower_bound(self):
        assert Score(-10.0).value == 0.0

    def test_accepts_int(self):
        assert Score(75).value == 75.0


class TestConfidence:
    @pytest.mark.parametrize("v", [-1, 101])
    def test_out_of_range(self, v):
        with pytest.raises(ValueError):
            Confidence(v)

    def test_helpers(self):
        assert Confidence.low().value == 25
        assert Confidence.medium().value == 50
        assert Confidence.high().value == 85


class TestCategory:
    def test_coerce_unknown_returns_other(self):
        assert Category.coerce("does-not-exist") is Category.OTHER

    def test_coerce_case_insensitive(self):
        assert Category.coerce("credential") is Category.CREDENTIAL


class TestTLP:
    def test_default_is_amber(self):
        assert TLP.coerce(None) is TLP.AMBER

    def test_case_insensitive(self):
        assert TLP.coerce("red") is TLP.RED
