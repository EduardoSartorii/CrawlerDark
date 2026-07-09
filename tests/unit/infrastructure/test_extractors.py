"""
Unit Tests — IOC and Credential Extractors
============================================

Tests for the IOCExtractor, CredentialExtractor, and CardExtractor.
All tests are pure Python — no network, no database.
"""

from __future__ import annotations

import pytest

from threat_hunting.infrastructure.extractors.ioc_extractor import IOCExtractor
from threat_hunting.infrastructure.extractors.credential_extractor import CredentialExtractor
from threat_hunting.infrastructure.extractors.card_extractor import CardExtractor
from threat_hunting.core.domain.value_objects.indicator_type import IndicatorType


class TestIOCExtractor:
    """Tests for the IOCExtractor."""

    def setup_method(self):
        self.extractor = IOCExtractor(source_tag="test")

    def test_extract_ipv4(self):
        text = "Malicious IP: 185.220.101.45 was observed sending traffic."
        indicators = self.extractor.extract(text)
        ips = [i for i in indicators if i.type == IndicatorType.IP]
        assert any(i.value == "185.220.101.45" for i in ips)

    def test_extract_filters_private_ip(self):
        text = "Gateway 192.168.1.1 and 10.0.0.1 are internal"
        indicators = self.extractor.extract(text)
        ips = [i for i in indicators if i.type == IndicatorType.IP]
        assert not any(i.value.startswith("192.168") for i in ips)
        assert not any(i.value.startswith("10.") for i in ips)

    def test_extract_email(self):
        text = "Contact hacker@evil.com for ransom"
        indicators = self.extractor.extract(text)
        emails = [i for i in indicators if i.type == IndicatorType.EMAIL]
        assert any(i.value == "hacker@evil.com" for i in emails)

    def test_extract_sha256(self):
        hash_val = "a" * 64
        text = f"Malware hash: {hash_val}"
        indicators = self.extractor.extract(text)
        hashes = [i for i in indicators if i.type == IndicatorType.SHA256]
        assert any(i.value == hash_val for i in hashes)

    def test_extract_url(self):
        text = "Download from https://malicious.example.com/payload.exe"
        indicators = self.extractor.extract(text)
        urls = [i for i in indicators if i.type == IndicatorType.URL]
        assert any("malicious.example.com" in i.value for i in urls)

    def test_extract_onion_url(self):
        text = "The site is available at zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion"
        indicators = self.extractor.extract(text)
        onions = [i for i in indicators if i.type == IndicatorType.ONION_URL]
        assert len(onions) >= 1

    def test_extract_cve(self):
        text = "Exploiting CVE-2024-12345 in the wild"
        indicators = self.extractor.extract(text)
        cves = [i for i in indicators if i.type == IndicatorType.CVE]
        assert any("CVE-2024-12345" in i.value.upper() for i in cves)

    def test_extract_cpf(self):
        text = "CPF: 123.456.789-09 encontrado no vazamento"
        indicators = self.extractor.extract(text)
        cpfs = [i for i in indicators if i.type == IndicatorType.CPF]
        assert len(cpfs) >= 1

    def test_deduplication(self):
        text = "IP 1.2.3.4 and IP 1.2.3.4 and IP 1.2.3.4"
        indicators = self.extractor.extract(text)
        ips = [i for i in indicators if i.type == IndicatorType.IP and i.value == "1.2.3.4"]
        assert len(ips) == 1

    def test_empty_text_returns_empty(self):
        assert self.extractor.extract("") == []

    def test_count_by_type(self):
        text = "ips: 1.2.3.4 8.8.8.8 and email test@example.com"
        counts = self.extractor.count_by_type(text)
        assert counts.get("ip", 0) >= 2
        assert counts.get("email", 0) >= 1


class TestCredentialExtractor:
    """Tests for the CredentialExtractor."""

    def setup_method(self):
        self.extractor = CredentialExtractor()

    def test_extract_email_password(self):
        text = "user@example.com:password123\nadmin@company.com:s3cr3t!"
        creds = self.extractor.extract(text)
        assert len(creds) >= 2
        usernames = [c.username for c in creds]
        assert "user@example.com" in usernames

    def test_extract_email_with_domain(self):
        text = "victim@gmail.com:mypassword"
        creds = self.extractor.extract(text)
        assert len(creds) == 1
        assert creds[0].domain == "gmail.com"
        assert creds[0].is_email

    def test_count(self):
        text = "\n".join(f"user{i}@test.com:pass{i}" for i in range(100))
        count = self.extractor.count(text)
        assert count == 100

    def test_empty_text(self):
        assert self.extractor.extract("") == []

    def test_max_results_respected(self):
        text = "\n".join(f"user{i}@test.com:pass{i}" for i in range(1000))
        creds = self.extractor.extract(text, max_results=50)
        assert len(creds) <= 50


class TestCardExtractor:
    """Tests for the CardExtractor with Luhn validation."""

    def setup_method(self):
        self.extractor = CardExtractor()

    def test_extract_valid_visa(self):
        # Valid Visa test card from Stripe documentation
        text = "Card: 4242424242424242"
        cards = self.extractor.extract(text)
        assert len(cards) >= 1
        assert cards[0].card_brand == "visa"

    def test_rejects_invalid_luhn(self):
        # Invalid card number (fails Luhn check)
        text = "Card: 4242424242424241"
        cards = self.extractor.extract(text)
        assert len(cards) == 0

    def test_pan_is_masked(self):
        text = "Card 4242424242424242 was found"
        cards = self.extractor.extract(text)
        if cards:
            assert "****" in cards[0].pan_masked
            assert cards[0].pan_masked.endswith("4242")

    def test_empty_text(self):
        assert self.extractor.extract("") == []

    def test_count(self):
        text = "Cards: 4242424242424242 and 5555555555554444"
        count = self.extractor.count(text)
        assert count >= 1  # At least the Visa is valid


class TestRateLimiter:
    """Tests for the RateLimiter."""

    def test_invalid_rate_raises(self):
        from threat_hunting.infrastructure.opsec.rate_limiter import RateLimiter
        with pytest.raises(ValueError):
            RateLimiter(rate_rps=0)

    def test_initial_tokens_at_capacity(self):
        from threat_hunting.infrastructure.opsec.rate_limiter import RateLimiter
        limiter = RateLimiter(rate_rps=10.0, burst_multiplier=2.0)
        assert limiter.available_tokens == 20.0
