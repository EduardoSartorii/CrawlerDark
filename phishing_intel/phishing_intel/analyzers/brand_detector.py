"""Brand detector using textual and asset-based heuristics."""

from __future__ import annotations

from phishing_intel.models.findings import BrandDetectionResult, DomAnalysisResult


class BrandDetector:
    """Detects likely impersonated brand from static phishing content."""

    BRAND_KEYWORDS: dict[str, tuple[str, ...]] = {
        "itau": ("itau", "itaú", "itaucard"),
        "livelo": ("livelo", "pontos livelo"),
        "nubank": ("nubank", "nu pagamentos", "roxinho"),
        "mercado_livre": ("mercado livre", "mercadopago", "mercado pago"),
        "claro": ("claro", "minha claro"),
        "vivo": ("vivo", "meu vivo"),
    }

    def detect(self, dom: DomAnalysisResult, raw_html: str) -> BrandDetectionResult:
        """Return best candidate target brand and confidence."""

        corpus = " ".join(
            [
                raw_html.lower(),
                " ".join(dom.assets).lower(),
                " ".join(dom.metatags.values()).lower(),
            ]
        )
        best_brand = "unknown"
        best_score = 0.2
        for brand, hints in self.BRAND_KEYWORDS.items():
            hits = sum(1 for hint in hints if hint in corpus)
            if hits:
                confidence = min(0.95, 0.35 + hits * 0.2)
                if confidence > best_score:
                    best_brand = brand
                    best_score = confidence
        return BrandDetectionResult(target_brand=best_brand, confidence=round(best_score, 2))
