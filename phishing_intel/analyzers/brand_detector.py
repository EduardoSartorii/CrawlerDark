"""
Brand impersonation detector.

Identifies targeted brands from logos, visible text, metadata,
and asset references in phishing pages.

Architectural Responsibility:
    Determines impersonated institution for MISP tagging
    (fraude:marca=*) and campaign correlation by target brand.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from phishing_intel.models.findings import BrandFinding, DOMFinding

logger = structlog.get_logger(__name__)


class BrandDetector:
    """
    Target brand detection engine.

    Uses configurable brand lists and multi-source detection
    (text, metadata, assets, logos) to identify impersonated brands.
    """

    def __init__(self, brand_config: dict[str, list[str]] | None = None) -> None:
        """
        Initialize brand detector.

        Args:
            brand_config: Brand categories mapping to brand name lists.
        """
        self.brand_config = brand_config or {}
        self._brand_patterns = self._build_patterns()

    def _build_patterns(self) -> dict[str, re.Pattern[str]]:
        """Build regex patterns for all configured brands."""
        patterns: dict[str, re.Pattern[str]] = {}
        for _category, brands in self.brand_config.items():
            for brand in brands:
                # Word boundary match for brand name
                patterns[brand.lower()] = re.compile(
                    rf"\b{re.escape(brand)}\b", re.IGNORECASE
                )
        return patterns

    def detect(self, dom: DOMFinding, page_text: str = "") -> BrandFinding | None:
        """
        Detect impersonated brand from page analysis.

        Detection sources (weighted):
            - Visible text: high confidence
            - Meta tags (og:site_name, title): high confidence
            - Asset URLs (logo paths): medium confidence
            - HTML comments: low confidence

        Args:
            dom: DOM analysis result.
            page_text: Visible page text content.

        Returns:
            BrandFinding with highest confidence match, or None.
        """
        logger.info("brand_detection_start")

        scores: dict[str, float] = {}
        sources: dict[str, list[str]] = {}

        # Text-based detection
        text_sources = [
            ("page_text", page_text, 30.0),
            ("normalized_dom", dom.normalized_dom[:5000], 20.0),
        ]

        for source_name, text, weight in text_sources:
            if not text:
                continue
            for brand, pattern in self._brand_patterns.items():
                if pattern.search(text):
                    scores[brand] = scores.get(brand, 0) + weight
                    sources.setdefault(brand, []).append(source_name)

        # Metadata detection
        meta_keys = ["og:site_name", "og:title", "title", "description", "keywords"]
        meta_text = " ".join(
            dom.metatags.get(k, "") for k in meta_keys if k in dom.metatags
        )
        for brand, pattern in self._brand_patterns.items():
            if pattern.search(meta_text):
                scores[brand] = scores.get(brand, 0) + 35.0
                sources.setdefault(brand, []).append("metadata")

        # Asset URL detection (logo paths)
        asset_text = " ".join(a.url + " " + a.filename for a in dom.assets)
        for brand, pattern in self._brand_patterns.items():
            if pattern.search(asset_text):
                scores[brand] = scores.get(brand, 0) + 25.0
                sources.setdefault(brand, []).append("assets")

        if not scores:
            logger.info("brand_detection_no_match")
            return None

        best_brand = max(scores, key=lambda k: scores[k])
        confidence = min(scores[best_brand], 100.0)

        result = BrandFinding(
            brand=best_brand,
            confidence=confidence,
            detection_sources=sources.get(best_brand, []),
        )

        logger.info(
            "brand_detection_complete",
            brand=best_brand,
            confidence=confidence,
        )
        return result
