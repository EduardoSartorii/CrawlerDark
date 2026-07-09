"""Unit tests for IOC extractor."""

from threat_hunting.core.contracts.services import ParsedData
from threat_hunting.infrastructure.extractors.ioc import IocExtractor


def test_extract_email():
    extractor = IocExtractor()
    parsed = ParsedData(fields={}, content="Contact admin@example.com for details")
    result = extractor.extract(parsed)
    emails = [i for i in result.indicators if i["type"] == "email"]
    assert len(emails) >= 1
    assert "admin@example.com" in emails[0]["value"]


def test_extract_ip():
    extractor = IocExtractor()
    parsed = ParsedData(fields={}, content="Server at 192.168.1.1 was compromised")
    result = extractor.extract(parsed)
    ips = [i for i in result.indicators if i["type"] == "ip"]
    assert any("192.168.1.1" in i["value"] for i in ips)


def test_extract_url():
    extractor = IocExtractor()
    parsed = ParsedData(fields={}, content="Visit https://evil.com/malware for payload")
    result = extractor.extract(parsed)
    urls = [i for i in result.indicators if i["type"] == "url"]
    assert len(urls) >= 1
