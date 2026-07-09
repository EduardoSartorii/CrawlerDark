"""Extractor adapters (clean text -> indicators/IOCs)."""

from threat_hunting.infrastructure.extractors.ioc_extractor import RegexIOCExtractor

__all__ = ["RegexIOCExtractor"]
