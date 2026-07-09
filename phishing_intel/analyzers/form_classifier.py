"""Phishing objective classifier based on HTML form semantics.

The classifier combines field names, labels, placeholders, and page text using
business heuristics common in phishing triage. Scores are intentionally simple
and explainable for analyst review.
"""

from __future__ import annotations

import re

from phishing_intel.models.findings import ClassificationFinding, DomFinding


class FormClassifier:
    """Classify phishing objectives from normalized DOM forms."""

    RULES: dict[str, list[str]] = {
        "otp_harvesting": [r"\botp\b", r"2fa", r"mfa", r"token", r"codigo", r"c[oó]digo"],
        "card_harvesting": [r"card", r"cart[aã]o", r"ccnum", r"cvv", r"validade", r"expiry"],
        "credential_harvesting": [r"password", r"senha", r"login", r"user(name)?", r"email"],
        "identity_theft": [r"cpf", r"rg", r"documento", r"birth", r"nascimento", r"identity"],
        "account_takeover": [r"recuper", r"verify", r"verificar", r"bloquead", r"account", r"conta"],
    }

    def classify(self, dom: DomFinding) -> ClassificationFinding:
        """Return the most likely phishing objective for a DOM finding."""

        text = self._signals_text(dom)
        scores: dict[str, list[str]] = {}
        for phishing_type, patterns in self.RULES.items():
            matches = [pattern for pattern in patterns if re.search(pattern, text, re.IGNORECASE)]
            if matches:
                scores[phishing_type] = matches
        if not scores:
            return ClassificationFinding(
                phishing_type="generic_data_collection",
                confidence=45 if dom.forms else 25,
                matched_signals=[],
            )
        winner = max(scores, key=lambda key: len(scores[key]))
        confidence = min(95, 45 + (len(scores[winner]) * 15) + (10 if dom.forms else 0))
        return ClassificationFinding(
            phishing_type=winner, confidence=confidence, matched_signals=sorted(scores[winner])
        )

    def _signals_text(self, dom: DomFinding) -> str:
        """Concatenate fields, metadata, and comments for heuristic matching."""

        values: list[str] = []
        for form in dom.forms:
            values.extend([form.action or "", form.method])
            for field in form.fields:
                values.extend(
                    [
                        field.name or "",
                        field.field_type or "",
                        field.placeholder or "",
                        field.label or "",
                        field.element_id or "",
                    ]
                )
        values.extend(dom.metatags.values())
        values.extend(dom.comments)
        return " ".join(values).lower()
