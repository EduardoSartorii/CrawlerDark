"""
Phishing form classifier.

Classifies phishing pages by objective type using regex heuristics,
HTML field analysis, labels, and placeholders.

Architectural Responsibility:
    Determines phishing campaign objective (credential harvesting,
    OTP, card data, etc.) to drive MISP taxonomy mapping.

Classification Types:
    - Account Takeover
    - Credential Harvesting
    - Identity Theft
    - Card Harvesting
    - OTP Harvesting
    - Generic Data Collection
"""

from __future__ import annotations

import re

import structlog

from phishing_intel.models.findings import DOMFinding, FormField, PhishingType

logger = structlog.get_logger(__name__)


class FormClassifier:
    """
    Heuristic phishing type classifier.

    Analyzes form fields, labels, placeholders, and page text
    to determine the phishing campaign objective.
    """

    # Field patterns for each phishing type
    PATTERNS: dict[PhishingType, list[re.Pattern[str]]] = {
        PhishingType.OTP_HARVESTING: [
            re.compile(p, re.IGNORECASE)
            for p in [
                r"otp",
                r"one.?time",
                r"verification.?code",
                r"codigo",
                r"token.?sms",
                r"2fa",
                r"mfa",
                r"authenticator",
                r"codigo.?seguranca",
                r"codigo.?verificacao",
            ]
        ],
        PhishingType.CARD_HARVESTING: [
            re.compile(p, re.IGNORECASE)
            for p in [
                r"card.?number",
                r"credit.?card",
                r"cvv",
                r"cvc",
                r"expir",
                r"cartao",
                r"numero.?cartao",
                r"validade",
                r"bandeira",
            ]
        ],
        PhishingType.IDENTITY_THEFT: [
            re.compile(p, re.IGNORECASE)
            for p in [
                r"cpf",
                r"rg",
                r"ssn",
                r"social.?security",
                r"date.?of.?birth",
                r"nascimento",
                r"data.?nasc",
                r"nome.?completo",
                r"full.?name",
                r"documento",
                r"identidade",
            ]
        ],
        PhishingType.ACCOUNT_TAKEOVER: [
            re.compile(p, re.IGNORECASE)
            for p in [
                r"confirm.?password",
                r"new.?password",
                r"reset.?password",
                r"change.?password",
                r"atualizar.?senha",
                r"nova.?senha",
                r"redefinir",
            ]
        ],
        PhishingType.CREDENTIAL_HARVESTING: [
            re.compile(p, re.IGNORECASE)
            for p in [
                r"password",
                r"senha",
                r"login",
                r"username",
                r"usuario",
                r"email",
                r"e-mail",
                r"sign.?in",
                r"entrar",
                r"acessar",
            ]
        ],
    }

    # Scoring weights per signal type
    FIELD_WEIGHT = 3
    LABEL_WEIGHT = 2
    PLACEHOLDER_WEIGHT = 2
    NAME_WEIGHT = 2

    def classify(self, dom: DOMFinding, page_text: str = "") -> PhishingType:
        """
        Classify phishing type from DOM analysis.

        Args:
            dom: DOM analysis finding with forms.
            page_text: Optional additional visible page text.

        Returns:
            Classified PhishingType.
        """
        logger.info("form_classification_start", form_count=len(dom.forms))

        scores: dict[PhishingType, float] = {pt: 0.0 for pt in PhishingType}

        # Analyze all form fields
        for form in dom.forms:
            for field in form.fields:
                field_text = self._field_text(field)
                for phishing_type, patterns in self.PATTERNS.items():
                    for pattern in patterns:
                        if pattern.search(field_text):
                            scores[phishing_type] += self.FIELD_WEIGHT

        # Analyze page text
        if page_text:
            for phishing_type, patterns in self.PATTERNS.items():
                for pattern in patterns:
                    if pattern.search(page_text):
                        scores[phishing_type] += self.LABEL_WEIGHT

        # Determine winner
        best_type = max(scores, key=lambda k: scores[k])
        best_score = scores[best_type]

        if best_score == 0:
            result = PhishingType.GENERIC_DATA_COLLECTION
        else:
            result = best_type

        logger.info(
            "form_classification_complete",
            phishing_type=result.value,
            score=best_score,
        )
        return result

    def _field_text(self, field: FormField) -> str:
        """Concatenate all field identifiers for pattern matching."""
        parts = [
            field.name,
            field.field_type,
            field.id,
            field.placeholder,
            field.label,
            field.css_class,
            field.autocomplete,
        ]
        return " ".join(p for p in parts if p).lower()
