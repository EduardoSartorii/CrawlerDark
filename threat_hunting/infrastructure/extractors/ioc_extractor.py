"""Regex-based IOC extractor with validation.

Responsibility
--------------
Implement :class:`ExtractorPort`: find observables in clean text and return
typed :class:`Indicator` objects. Beyond raw regex matching it applies domain
validation to cut false positives — Luhn for credit cards, check-digit
validation for Brazilian CPF/CNPJ — because fraud intelligence is worthless when
it is noisy.

Business rules
--------------
* Every indicator type is extracted independently; the caller decides relevance.
* Credentials are matched as ``user:password`` / ``email:password`` pairs common
  in leak dumps.
* Values are captured verbatim; normalisation for equality happens on the
  :class:`Indicator` itself.
"""

from __future__ import annotations

import re

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.application.ports.pipeline_stages import ExtractorPort
from threat_hunting.core.domain.entities import Indicator
from threat_hunting.core.domain.enums import IndicatorType

# Ordered so more specific patterns (hashes before generic numbers) win.
_PATTERNS: dict[IndicatorType, re.Pattern[str]] = {
    IndicatorType.URL: re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE),
    IndicatorType.EMAIL: re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    IndicatorType.SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
    IndicatorType.SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
    IndicatorType.MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
    IndicatorType.IPV4: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    IndicatorType.CVE: re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    IndicatorType.BTC_WALLET: re.compile(
        r"\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
    ),
    IndicatorType.ETH_WALLET: re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    IndicatorType.CPF: re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
    IndicatorType.CNPJ: re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
    IndicatorType.CREDIT_CARD: re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    IndicatorType.TELEGRAM: re.compile(
        r"(?:t\.me/|telegram[:\s]+@?|(?<![\w@.])@)([A-Za-z0-9_]{4,32})", re.IGNORECASE
    ),
    IndicatorType.DOMAIN: re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|gov|edu|br|onion|ru|info|biz|xyz|top|shop)\b"
    ),
    IndicatorType.CREDENTIAL: re.compile(
        r"\b([A-Za-z0-9._%+\-]+(?:@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})?):(?!//)([^\s:/]{3,})\b"
    ),
}


class RegexIOCExtractor(ExtractorPort):
    """Extracts validated indicators from clean text."""

    def extract(self, record: RawRecord) -> list[Indicator]:
        """Return the deduplicated list of indicators found in the record."""
        text = record.content or ""
        indicators: list[Indicator] = []
        seen: set[str] = set()

        for ioc_type, pattern in _PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0).strip()
                if not self._is_valid(ioc_type, match):
                    continue
                indicator = self._build(ioc_type, match)
                if indicator.fingerprint() in seen:
                    continue
                seen.add(indicator.fingerprint())
                indicators.append(indicator)
        return indicators

    # -- construction & validation -----------------------------------------

    def _build(self, ioc_type: IndicatorType, match: re.Match[str]) -> Indicator:
        """Build an indicator, preferring a capture group when present."""
        if ioc_type is IndicatorType.TELEGRAM:
            value = f"@{match.group(1).strip()}"
        else:
            value = match.group(0).strip()
        return Indicator(type=ioc_type, value=value)

    def _is_valid(self, ioc_type: IndicatorType, match: re.Match[str]) -> bool:
        """Apply per-type validation to suppress false positives."""
        raw = match.group(0)
        if ioc_type is IndicatorType.CREDIT_CARD:
            return self._luhn(re.sub(r"\D", "", raw))
        if ioc_type is IndicatorType.CPF:
            return self._valid_cpf(re.sub(r"\D", "", raw))
        if ioc_type is IndicatorType.CNPJ:
            return self._valid_cnpj(re.sub(r"\D", "", raw))
        return True

    @staticmethod
    def _luhn(digits: str) -> bool:
        """Validate a card number with the Luhn checksum."""
        if not (13 <= len(digits) <= 19):
            return False
        total = 0
        parity = len(digits) % 2
        for index, char in enumerate(digits):
            value = int(char)
            if index % 2 == parity:
                value *= 2
                if value > 9:
                    value -= 9
            total += value
        return total % 10 == 0

    @staticmethod
    def _valid_cpf(digits: str) -> bool:
        """Validate a Brazilian CPF via its two check digits."""
        if len(digits) != 11 or len(set(digits)) == 1:
            return False
        for length in (9, 10):
            weights = range(length + 1, 1, -1)
            total = sum(int(d) * w for d, w in zip(digits, weights))
            check = (total * 10) % 11 % 10
            if check != int(digits[length]):
                return False
        return True

    @staticmethod
    def _valid_cnpj(digits: str) -> bool:
        """Validate a Brazilian CNPJ via its two check digits."""
        if len(digits) != 14 or len(set(digits)) == 1:
            return False
        weights_first = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
        weights_second = [6] + weights_first
        for weights, position in ((weights_first, 12), (weights_second, 13)):
            total = sum(int(d) * w for d, w in zip(digits, weights))
            remainder = total % 11
            check = 0 if remainder < 2 else 11 - remainder
            if check != int(digits[position]):
                return False
        return True
