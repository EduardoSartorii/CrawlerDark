"""CardExtractor — detecção de PANs com validação Luhn."""

from __future__ import annotations

import re

from ...core.domain.entities import Finding, Indicator
from ...core.domain.value_objects import Confidence, IndicatorType

_PAN_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(pan: str) -> bool:
    digits = [int(d) for d in pan if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _mask(pan: str) -> str:
    only_digits = "".join(c for c in pan if c.isdigit())
    if len(only_digits) < 10:
        return only_digits
    return f"{only_digits[:6]}******{only_digits[-4:]}"


class CardExtractor:
    """Extrai PANs válidos por Luhn, mascarados."""

    async def extract(self, finding: Finding) -> Finding:
        haystack = "\n".join([finding.title, finding.description])
        for match in set(_PAN_CANDIDATE.findall(haystack)):
            pan_clean = "".join(c for c in match if c.isdigit())
            if not _luhn_ok(pan_clean):
                continue
            finding.add_indicator(
                Indicator(
                    type=IndicatorType.CARD_PAN,
                    value=_mask(pan_clean),
                    confidence=Confidence(90),
                    tags={"card", "pci"},
                    context={"bin": pan_clean[:6], "last4": pan_clean[-4:]},
                )
            )
        return finding
