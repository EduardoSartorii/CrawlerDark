"""Normalizers.

Canonicalise a finding after parsing/extraction: trim/collapse text, populate
``normalized_data``, and ensure indicators are in canonical form. Normalisation
makes downstream detection/scoring/dedup deterministic and source independent.
"""

from threat_hunting.infrastructure.normalizers.finding_normalizer import FindingNormalizer

__all__ = ["FindingNormalizer"]
