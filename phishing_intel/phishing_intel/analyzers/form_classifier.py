"""Classifier for phishing objective based on form semantics."""

from __future__ import annotations

import re

from phishing_intel.models.findings import DomAnalysisResult, PhishingType


class FormClassifier:
    """Classifies phishing intent from HTML form fields and labels."""

    CARD_FIELDS = re.compile(r"(card|cvv|cvc|expiry|exp|billing|credit)", re.IGNORECASE)
    OTP_FIELDS = re.compile(r"(otp|token|2fa|one[-_ ]?time|verification code)", re.IGNORECASE)
    CREDENTIAL_FIELDS = re.compile(r"(password|passwd|login|username|email)", re.IGNORECASE)
    IDENTITY_FIELDS = re.compile(r"(cpf|ssn|rg|passport|mother|address|birth)", re.IGNORECASE)
    ACCOUNT_TAKEOVER = re.compile(r"(unlock|restore|recover|reactivate|suspended|verify account)", re.IGNORECASE)

    def classify(self, dom_result: DomAnalysisResult, raw_html: str) -> PhishingType:
        """Return the most likely phishing objective."""

        bag = " ".join(
            [
                raw_html,
                " ".join(name for form in dom_result.forms for name in form.input_names),
                " ".join(dom_result.comments),
                " ".join(dom_result.metatags.values()),
            ]
        ).lower()

        if self.CARD_FIELDS.search(bag):
            return PhishingType.CARD_HARVESTING
        if self.OTP_FIELDS.search(bag):
            return PhishingType.OTP_HARVESTING
        if self.IDENTITY_FIELDS.search(bag):
            return PhishingType.IDENTITY_THEFT
        if self.ACCOUNT_TAKEOVER.search(bag):
            return PhishingType.ACCOUNT_TAKEOVER
        if self.CREDENTIAL_FIELDS.search(bag):
            return PhishingType.CREDENTIAL_HARVESTING
        return PhishingType.GENERIC_DATA_COLLECTION
