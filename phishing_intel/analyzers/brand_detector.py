"""Brand detection analyzer.

Component responsibility
------------------------
Identify the impersonated brand/target of a phishing page and emit a
:class:`~phishing_intel.models.findings.BrandDetection` with the winning
``target_brand``, its category and per-candidate scores.

Detection sources
-----------------
* Visible text (title + meta tags + link/asset filenames).
* Logo / asset filenames (e.g. ``itau-logo.png``).
* Domain / URL tokens.
* Meta-tag content (``og:site_name``, ``application-name``, ...).

The brand catalogue is data-driven (``_BRANDS``) and covers the categories
requested by the spec: financial institutions, loyalty programs, marketplaces,
telecoms/carriers and fintechs, with a BR-first focus.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import BrandDetection, DOMAnalysis

logger = get_logger(__name__)


# Brand catalogue: canonical name -> (category, [keyword patterns]).
# Keywords are matched case-insensitively as whole-ish tokens against the
# aggregated page text. Extend this table to broaden coverage.
_BRANDS: Dict[str, tuple[str, List[str]]] = {
    # --- Loyalty programs ---
    "livelo": ("loyalty_program", ["livelo"]),
    "smiles": ("loyalty_program", ["smiles"]),
    "latam_pass": ("loyalty_program", ["latam pass", "latampass"]),
    "dotz": ("loyalty_program", ["dotz"]),
    # --- Financial institutions (banks) ---
    "itau": ("financial_institution", ["itau", "itaú", "itaubank"]),
    "bradesco": ("financial_institution", ["bradesco"]),
    "santander": ("financial_institution", ["santander"]),
    "banco_do_brasil": ("financial_institution", ["banco do brasil", "bancodobrasil", "bb.com.br"]),
    "caixa": ("financial_institution", ["caixa economica", "caixa econômica", "caixa.gov"]),
    "sicoob": ("financial_institution", ["sicoob"]),
    # --- Fintechs ---
    "nubank": ("fintech", ["nubank", "nu bank"]),
    "picpay": ("fintech", ["picpay"]),
    "mercado_pago": ("fintech", ["mercado pago", "mercadopago"]),
    "inter": ("fintech", ["banco inter", "bancointer"]),
    "c6_bank": ("fintech", ["c6 bank", "c6bank"]),
    # --- Marketplaces ---
    "mercado_livre": ("marketplace", ["mercado livre", "mercadolivre", "mercadolibre"]),
    "amazon": ("marketplace", ["amazon"]),
    "magalu": ("marketplace", ["magalu", "magazine luiza", "magazineluiza"]),
    "americanas": ("marketplace", ["americanas"]),
    "shopee": ("marketplace", ["shopee"]),
    # --- Telecom / carriers ---
    "vivo": ("carrier", ["vivo.com", "telefonica vivo"]),
    "claro": ("carrier", ["claro.com", "claro brasil"]),
    "tim": ("carrier", ["tim.com.br", "tim brasil"]),
    "oi": ("carrier", ["oi.com.br"]),
    # --- International tech (common phishing targets) ---
    "microsoft": ("technology", ["microsoft", "office365", "outlook"]),
    "google": ("technology", ["google", "gmail"]),
    "apple": ("technology", ["apple id", "icloud", "appleid"]),
    "paypal": ("fintech", ["paypal"]),
}


class BrandDetector:
    """Detect the impersonated brand of a phishing page."""

    def _aggregate_text(self, dom: DOMAnalysis, url: Optional[str]) -> str:
        """Concatenate every text source into one lowercased search corpus.

        Business rule: brand cues are scattered across the title, meta tags,
        asset/script filenames and the URL itself, so we search them together
        while still tracking *where* a match came from for the signals list.
        """

        parts: List[str] = []
        if dom.title:
            parts.append(dom.title)
        parts.extend(dom.meta_tags.values())
        parts.extend(dom.filenames)
        parts.extend(dom.assets)
        parts.extend(dom.css_classes)
        parts.extend(dom.html_ids)
        if url:
            parts.append(url)
        return " \n ".join(parts).lower()

    def detect(self, dom: DOMAnalysis, url: Optional[str] = None) -> BrandDetection:
        """Detect the target brand.

        Parameters
        ----------
        dom:
            DOM analysis of the page.
        url:
            The page URL (its tokens are a strong brand signal).

        Returns
        -------
        BrandDetection
        """

        corpus = self._aggregate_text(dom, url)
        url_lower = (url or "").lower()
        candidates: Dict[str, int] = {}
        signals: List[str] = []

        for brand, (category, keywords) in _BRANDS.items():
            score = 0
            for keyword in keywords:
                if keyword in corpus:
                    # Base score for any textual mention.
                    score += 40
                    signals.append(f"{brand}: matched '{keyword}' in page text")
                    # A match in the URL/domain is a much stronger indicator.
                    if keyword.replace(" ", "") in url_lower.replace(" ", ""):
                        score += 40
                        signals.append(f"{brand}: matched '{keyword}' in URL")
            if score:
                candidates[brand] = min(100, score)

        if not candidates:
            logger.info("brand.detected", brand=None, confidence=0)
            return BrandDetection(
                target_brand=None,
                category=None,
                confidence=0,
                candidates={},
                signals=["no known brand cues detected"],
            )

        target_brand = max(candidates, key=lambda k: candidates[k])
        detection = BrandDetection(
            target_brand=target_brand,
            category=_BRANDS[target_brand][0],
            confidence=candidates[target_brand],
            candidates=candidates,
            signals=signals,
        )
        logger.info(
            "brand.detected",
            brand=target_brand,
            category=detection.category,
            confidence=detection.confidence,
        )
        return detection
