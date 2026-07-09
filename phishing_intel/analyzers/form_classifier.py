"""Form / phishing-type classifier.

Component responsibility
------------------------
Classify the *objective* of a phishing page by inspecting its forms, fields,
labels and placeholders. Produces a
:class:`~phishing_intel.models.findings.PhishingClassification` naming the
primary objective plus every detected objective with an individual confidence.

Detection strategy
-------------------
A hybrid of regex, field-``type`` heuristics and keyword matching against
field ``name``/``id``/``placeholder``/``label`` values. Portuguese and English
keywords are included because the platform targets BR-focused fraud (Livelo,
Itaú, ...) as well as international brands.

Objectives detected
--------------------
account_takeover, credential_harvesting, identity_theft, card_harvesting,
otp_harvesting, generic_data_collection.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import (
    DOMAnalysis,
    PhishingClassification,
    PhishingType,
)

logger = get_logger(__name__)


# Each objective maps to a list of compiled regexes. A match against any field
# text (name/id/placeholder/label) contributes to that objective's score.
# Patterns are intentionally broad but anchored on discriminating tokens.
_KEYWORD_PATTERNS: Dict[PhishingType, List[re.Pattern[str]]] = {
    PhishingType.CREDENTIAL_HARVESTING: [
        re.compile(r"\b(user|username|usuario|login|email|e-mail)\b", re.I),
        re.compile(r"\b(pass|password|senha|passwd|pwd)\b", re.I),
    ],
    PhishingType.CARD_HARVESTING: [
        re.compile(r"\b(card|cartao|cartão|credit|credito|crédito)\b", re.I),
        re.compile(r"\b(cvv|cvc|cvv2|security\s*code|codigo\s*seguranca)\b", re.I),
        re.compile(r"\b(expir|validade|vencimento|mm\/?aa|mm\/?yy)\b", re.I),
        re.compile(r"\b(card\s*number|numero\s*cartao|pan)\b", re.I),
    ],
    PhishingType.OTP_HARVESTING: [
        re.compile(r"\b(otp|token|2fa|mfa|one[\s-]*time)\b", re.I),
        re.compile(r"\b(codigo|código|code|sms|authenticator|autenticador)\b", re.I),
        re.compile(r"\b(pin)\b", re.I),
    ],
    PhishingType.IDENTITY_THEFT: [
        re.compile(r"\b(cpf|cnpj|rg|ssn|passport|passaporte)\b", re.I),
        re.compile(r"\b(birth|nascimento|dob|data\s*de\s*nascimento)\b", re.I),
        re.compile(r"\b(mother|mae|mãe|nome\s*da\s*mae)\b", re.I),
        re.compile(r"\b(address|endereco|endereço|cep|zip)\b", re.I),
    ],
}

# Regex identifying account-recovery / login-verification wording, which signals
# an Account Takeover objective (as opposed to plain credential harvesting).
_ATO_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"\b(verify|verificar|confirm|confirmar|recover|recuperar)\b", re.I),
    re.compile(r"\b(unlock|desbloquear|reactivate|reativar|update\s*account)\b", re.I),
    re.compile(r"\b(account|conta)\b", re.I),
]


class FormClassifier:
    """Classify the phishing objective(s) of a page from its DOM analysis."""

    def _field_texts(self, dom: DOMAnalysis) -> List[str]:
        """Collect every discriminating text token from all form fields.

        Business rule: kit authors name fields meaningfully ("cpf", "senha",
        "cvv") because the backend PHP expects those keys, so field metadata is
        a high-signal, low-noise classification source.
        """

        texts: List[str] = []
        for form in dom.forms:
            for field in form.fields:
                for value in (field.name, field.id, field.placeholder, field.label, field.type):
                    if value:
                        texts.append(value)
        return texts

    def _score_password_types(self, dom: DOMAnalysis) -> Tuple[int, List[str]]:
        """Count ``type=password`` inputs (strong credential-harvest signal)."""

        signals: List[str] = []
        count = 0
        for form in dom.forms:
            for field in form.fields:
                if (field.type or "").lower() == "password":
                    count += 1
        if count:
            signals.append(f"{count} password input(s) present")
        return count, signals

    def classify(self, dom: DOMAnalysis) -> PhishingClassification:
        """Classify the phishing objective of a page.

        Returns
        -------
        PhishingClassification
            Primary objective + per-objective confidences + explanatory signals.
        """

        texts = self._field_texts(dom)
        blob = " \n ".join(texts).lower()
        detected: Dict[PhishingType, int] = {}
        signals: List[str] = []

        # --- Keyword-driven objectives -------------------------------------
        for phishing_type, patterns in _KEYWORD_PATTERNS.items():
            hits = 0
            for pattern in patterns:
                if pattern.search(blob):
                    hits += 1
            if hits:
                # Each matched sub-pattern is worth 30 points, capped at 95.
                score = min(95, hits * 30)
                detected[phishing_type] = score
                signals.append(f"{phishing_type.value}: matched {hits} keyword group(s)")

        # --- Password inputs reinforce credential harvesting ----------------
        pwd_count, pwd_signals = self._score_password_types(dom)
        if pwd_count:
            current = detected.get(PhishingType.CREDENTIAL_HARVESTING, 0)
            detected[PhishingType.CREDENTIAL_HARVESTING] = min(99, current + 40)
            signals.extend(pwd_signals)

        # --- Account Takeover: credentials + recovery/verification wording --
        page_blob = blob + " " + " ".join(dom.meta_tags.values()).lower()
        ato_hits = sum(1 for p in _ATO_PATTERNS if p.search(page_blob))
        if PhishingType.CREDENTIAL_HARVESTING in detected and ato_hits >= 2:
            detected[PhishingType.ACCOUNT_TAKEOVER] = min(90, 30 + ato_hits * 20)
            signals.append(f"account_takeover: {ato_hits} recovery/verification cue(s)")

        # --- Fallback: any form at all is at least generic collection -------
        if not detected and dom.forms:
            detected[PhishingType.GENERIC_DATA_COLLECTION] = 40
            signals.append("generic_data_collection: form present without specific cues")

        if not detected:
            # No forms and no cues -> low-confidence generic classification.
            classification = PhishingClassification(
                primary_type=PhishingType.GENERIC_DATA_COLLECTION,
                detected_types={},
                signals=["no forms or fields detected"],
                confidence=0,
            )
            logger.info("form.classified", primary=classification.primary_type.value, confidence=0)
            return classification

        # The primary objective is the highest-scoring detected type.
        primary_type = max(detected, key=lambda k: detected[k])
        classification = PhishingClassification(
            primary_type=primary_type,
            detected_types=detected,
            signals=signals,
            confidence=detected[primary_type],
        )
        logger.info(
            "form.classified",
            primary=primary_type.value,
            confidence=classification.confidence,
            types=[t.value for t in detected],
        )
        return classification
