"""WalletExtractor — carteiras BTC e ETH."""

from __future__ import annotations

import re

from ...core.domain.entities import Finding, Indicator
from ...core.domain.value_objects import Confidence, IndicatorType

_BTC = re.compile(r"\b(bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")


class WalletExtractor:
    async def extract(self, finding: Finding) -> Finding:
        text = "\n".join([finding.title, finding.description])
        for w in set(_BTC.findall(text)):
            finding.add_indicator(
                Indicator(type=IndicatorType.WALLET_BTC, value=w, confidence=Confidence(80))
            )
        for w in set(_ETH.findall(text)):
            finding.add_indicator(
                Indicator(type=IndicatorType.WALLET_ETH, value=w, confidence=Confidence(85))
            )
        return finding
