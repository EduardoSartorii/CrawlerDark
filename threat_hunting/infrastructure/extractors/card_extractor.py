"""
CardExtractor
=============

Detects and extracts payment card data from text content.
Supports PAN (Primary Account Number) validation via Luhn algorithm.

Detected formats:
    - Visa (4xxx xxxx xxxx xxxx)
    - MasterCard (5xxx xxxx xxxx xxxx)
    - Amex (37xx xxxxxx xxxxx)
    - Discover (6011 xxxx xxxx xxxx)
    - Fullz format: PAN|expiry|CVV

Luhn validation:
    - Applied to all extracted PANs to reduce false positives.
    - Cards failing Luhn check are discarded.

Note:
    This extractor produces HIGH/CRITICAL findings when combined with
    the ScoringEngine (card_match weight = 3.5).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ExtractedCard:
    """Extracted payment card data."""

    pan: str
    pan_masked: str
    card_brand: str
    expiry: str | None = None
    cvv: str | None = None
    raw: str = ""


# Match 13-19 digit card numbers with optional separators.
_PAN_PATTERN = re.compile(
    r"\b(?:4\d{12}(?:\d{3}(?:\d{3})?)?|"   # Visa 13/16/19
    r"[25][1-7]\d{14}|"                      # MC / MC 2-series
    r"3[47]\d{13}|"                           # Amex
    r"3(?:0[0-5]|[68]\d)\d{11}|"            # Diners
    r"6(?:011|5\d{2})\d{12}|"               # Discover
    r"(?:2131|1800|35\d{3})\d{11})"         # JCB
    r"(?:[ \-]?\d{4})*\b"
)

_FULLZ_PATTERN = re.compile(
    r"(\d[\d ]{12,18}\d)[|;,](\d{2}/\d{2,4})[|;,](\d{3,4})"
)


def _luhn_check(number: str) -> bool:
    """Validate a card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _detect_brand(pan: str) -> str:
    """Detect card brand from the PAN prefix."""
    pan = pan.replace(" ", "").replace("-", "")
    if pan.startswith("4"):
        return "visa"
    if pan[:2] in ("51", "52", "53", "54", "55") or pan[:4].isdigit() and 2221 <= int(pan[:4]) <= 2720:
        return "mastercard"
    if pan[:2] in ("34", "37"):
        return "amex"
    if pan[:4] == "6011" or pan[:2] == "65":
        return "discover"
    return "unknown"


class CardExtractor:
    """Stateless payment card extractor with Luhn validation."""

    def extract(self, text: str, max_results: int = 200) -> list[ExtractedCard]:
        """
        Extract and validate card numbers from text.

        Args:
            text: Raw text (paste, forum post, dump).
            max_results: Maximum cards to return.

        Returns:
            List of ExtractedCard objects (Luhn-validated).
        """
        results: list[ExtractedCard] = []
        seen: set[str] = set()

        # Try fullz format first.
        for match in _FULLZ_PATTERN.finditer(text):
            if len(results) >= max_results:
                break
            raw_pan = match.group(1).replace(" ", "").replace("-", "")
            if raw_pan in seen or not _luhn_check(raw_pan):
                continue
            seen.add(raw_pan)
            results.append(
                ExtractedCard(
                    pan=raw_pan,
                    pan_masked=f"****-****-****-{raw_pan[-4:]}",
                    card_brand=_detect_brand(raw_pan),
                    expiry=match.group(2),
                    cvv=match.group(3),
                    raw=match.group(0),
                )
            )

        # Fall back to plain PAN search.
        for match in _PAN_PATTERN.finditer(text):
            if len(results) >= max_results:
                break
            raw_pan = match.group(0).replace(" ", "").replace("-", "")
            if raw_pan in seen or not _luhn_check(raw_pan):
                continue
            seen.add(raw_pan)
            results.append(
                ExtractedCard(
                    pan=raw_pan,
                    pan_masked=f"****-****-****-{raw_pan[-4:]}",
                    card_brand=_detect_brand(raw_pan),
                    raw=match.group(0),
                )
            )

        return results

    def count(self, text: str) -> int:
        """Count valid card numbers in text."""
        return len(self.extract(text))
