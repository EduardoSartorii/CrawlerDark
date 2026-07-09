"""IndicatorExtractor.

Responsibility
--------------
Extract typed :class:`Indicator`s from free text using a curated regex library
plus algorithmic validators. Defanged notations (``hxxp``, ``[.]``) are handled
by the :class:`Indicator` value object itself, so this extractor only needs to
*find* candidates and let the VO canonicalise them.

Design
------
The pattern table is data (a class attribute), so adding an indicator type is a
one-line change. Post-match validators (Luhn/CPF/CNPJ) prune false positives.
Order matters: more specific patterns (SHA256 before MD5, CNPJ before CPF-like
digit runs) are applied first and matched spans are recorded to avoid
double-extraction.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.infrastructure.extractors.validators import (
    cnpj_valid,
    cpf_valid,
    ipv4_valid,
    luhn_valid,
)

# Refang the text before matching so patterns are simple and robust.
_REFANG = (
    (re.compile(r"hxxps?", re.IGNORECASE), lambda m: m.group(0).lower().replace("hxxp", "http")),
    (re.compile(r"\[\.\]"), lambda m: "."),
    (re.compile(r"\(\.\)"), lambda m: "."),
    (re.compile(r"\[:\]"), lambda m: ":"),
    (re.compile(r"\[(?:@|at)\]", re.IGNORECASE), lambda m: "@"),
)

# (type, compiled pattern, optional validator on the matched string)
_Pattern = tuple[IndicatorType, re.Pattern[str], Callable[[str], bool] | None]


class IndicatorExtractor:
    """Regex + validator based extractor of IOCs from text."""

    PATTERNS: tuple[_Pattern, ...] = (
        (IndicatorType.URL, re.compile(r"https?://[^\s\"'<>)\]]+"), None),
        (IndicatorType.EMAIL, re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), None),
        (IndicatorType.SHA256, re.compile(r"\b[a-fA-F0-9]{64}\b"), None),
        (IndicatorType.SHA1, re.compile(r"\b[a-fA-F0-9]{40}\b"), None),
        (IndicatorType.MD5, re.compile(r"\b[a-fA-F0-9]{32}\b"), None),
        (IndicatorType.CVE, re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE), None),
        (IndicatorType.IPV4, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), ipv4_valid),
        (
            IndicatorType.ETH_WALLET,
            re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
            None,
        ),
        (
            IndicatorType.BTC_WALLET,
            re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
            None,
        ),
        (
            IndicatorType.CNPJ,
            re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
            cnpj_valid,
        ),
        (
            IndicatorType.CPF,
            re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
            cpf_valid,
        ),
        (
            IndicatorType.CREDIT_CARD,
            re.compile(r"\b(?:\d[ -]?){13,19}\b"),
            luhn_valid,
        ),
        (IndicatorType.TELEGRAM, re.compile(r"(?<![\w])@[A-Za-z]\w{4,}"), None),
        (
            IndicatorType.DOMAIN,
            re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
            None,
        ),
    )

    def _refang(self, text: str) -> str:
        for pattern, repl in _REFANG:
            text = pattern.sub(repl, text)
        return text

    def extract(self, text: str) -> list[Indicator]:
        """Return the de-duplicated indicators found in ``text``."""
        if not text:
            return []
        refanged = self._refang(text)
        found: dict[str, Indicator] = {}
        consumed: list[tuple[int, int]] = []  # spans already claimed by a match

        for indicator_type, pattern, validator in self.PATTERNS:
            for match in pattern.finditer(refanged):
                span = match.span()
                if _overlaps(span, consumed):
                    continue
                raw = match.group(0)
                if validator is not None and not validator(raw):
                    continue
                # Domains that are actually part of a URL/email are skipped by the
                # span-overlap guard above (URL/email patterns run first).
                try:
                    indicator = Indicator(type=indicator_type, value=raw)
                except Exception:
                    continue
                found.setdefault(indicator.key, indicator)
                consumed.append(span)
        return list(found.values())

    def extract_many(self, texts: Iterable[str]) -> list[Indicator]:
        """Extract indicators across multiple texts, de-duplicated globally."""
        merged: dict[str, Indicator] = {}
        for text in texts:
            for indicator in self.extract(text):
                merged.setdefault(indicator.key, indicator)
        return list(merged.values())


def _overlaps(span: tuple[int, int], claimed: list[tuple[int, int]]) -> bool:
    """Return whether ``span`` intersects any already-claimed span."""
    start, end = span
    for cstart, cend in claimed:
        if start < cend and cstart < end:
            return True
    return False
