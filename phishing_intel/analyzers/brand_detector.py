"""Target brand detector for phishing pages.

The detector ships with common Brazilian financial, loyalty, marketplace,
telecom, and fintech aliases and can be extended from configuration.
"""

from __future__ import annotations

from phishing_intel.models.findings import BrandFinding, DomFinding, JavaScriptFinding


DEFAULT_BRANDS: dict[str, list[str]] = {
    "itau": ["itau", "itaú", "personnalite"],
    "bradesco": ["bradesco"],
    "santander": ["santander"],
    "nubank": ["nubank", "nu bank"],
    "livelo": ["livelo"],
    "latam_pass": ["latam pass", "latam"],
    "mercado_livre": ["mercado livre", "mercadolivre", "mercado pago", "mercadopago"],
    "claro": ["claro"],
    "vivo": ["vivo"],
    "tim": ["tim"],
}


class BrandDetector:
    """Detect likely target brand from visible and structural signals."""

    def __init__(self, brands: dict[str, list[str]] | None = None) -> None:
        """Create a detector with default aliases plus optional overrides."""

        self.brands = brands or DEFAULT_BRANDS

    def detect(self, dom: DomFinding, javascript: JavaScriptFinding, html: str = "") -> BrandFinding:
        """Return the highest-confidence target brand finding."""

        haystack = " ".join(
            [
                html,
                " ".join(dom.assets),
                " ".join(dom.scripts),
                " ".join(dom.metatags.values()),
                " ".join(javascript.hardcoded_urls),
            ]
        ).lower()
        candidates: list[BrandFinding] = []
        for brand, aliases in self.brands.items():
            signals = [alias for alias in aliases if alias.lower() in haystack]
            if signals:
                confidence = min(95, 45 + (len(signals) * 20))
                candidates.append(BrandFinding(target_brand=brand, confidence=confidence, signals=signals))
        return max(candidates, key=lambda finding: finding.confidence) if candidates else BrandFinding()
