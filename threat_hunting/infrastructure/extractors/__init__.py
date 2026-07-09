"""Indicator extraction.

Turns free text into typed :class:`Indicator` value objects. The
:class:`IndicatorExtractor` is regex-driven with domain-specific validators
(Luhn for cards, checksum for CPF/CNPJ) to cut false positives before the data
reaches scoring/correlation.
"""

from threat_hunting.infrastructure.extractors.indicator_extractor import IndicatorExtractor

__all__ = ["IndicatorExtractor"]
