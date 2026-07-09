"""IOCExtractor — extrai IPs, domínios, URLs, emails, hashes, CVEs, ASNs."""

from __future__ import annotations

import re
from typing import ClassVar

from ...core.domain.entities import Finding, Indicator
from ...core.domain.value_objects import Confidence, IndicatorType

_IP_V4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
_IP_V6 = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b")
_DOMAIN = re.compile(
    r"\b(?=.{4,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,63})\b"
)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_ASN = re.compile(r"\bAS\d{1,10}\b")

# TLDs comuns para reduzir falso-positivo em regex de domínio
_COMMON_TLDS: ClassVar[set[str]] = {
    "com", "net", "org", "io", "co", "br", "gov", "edu", "info", "biz",
    "us", "uk", "de", "fr", "cn", "ru", "onion", "app", "dev", "xyz",
    "cloud", "top", "site", "ai", "me",
}


class IOCExtractor:
    """Implementa ``ExtractorPort`` extraindo IOCs textuais.

    Nunca extrai IPs privados (RFC1918, 169.254, 127.0.0.0/8).
    """

    async def extract(self, finding: Finding) -> Finding:
        haystack = self._haystack(finding)
        for ip in set(_IP_V4.findall(haystack)):
            if not self._is_public_ip(ip):
                continue
            finding.add_indicator(
                Indicator(type=IndicatorType.IP, value=ip, confidence=Confidence(85))
            )
        for match in set(_IP_V6.findall(haystack)):
            finding.add_indicator(
                Indicator(type=IndicatorType.IP, value=match, confidence=Confidence(70))
            )
        for url in set(_URL.findall(haystack)):
            finding.add_indicator(
                Indicator(type=IndicatorType.URL, value=url, confidence=Confidence(90))
            )
        for email in set(_EMAIL.findall(haystack)):
            finding.add_indicator(
                Indicator(type=IndicatorType.EMAIL, value=email, confidence=Confidence(90))
            )
        # Ordem importa: SHA256 antes de SHA1 antes de MD5 (evita colisão).
        for h in set(_SHA256.findall(haystack)):
            finding.add_indicator(
                Indicator(type=IndicatorType.HASH_SHA256, value=h, confidence=Confidence(95))
            )
        remaining = _SHA256.sub("", haystack)
        for h in set(_SHA1.findall(remaining)):
            finding.add_indicator(
                Indicator(type=IndicatorType.HASH_SHA1, value=h, confidence=Confidence(90))
            )
        remaining = _SHA1.sub("", remaining)
        for h in set(_MD5.findall(remaining)):
            finding.add_indicator(
                Indicator(type=IndicatorType.HASH_MD5, value=h, confidence=Confidence(80))
            )
        for cve in set(m.upper() for m in _CVE.findall(haystack)):
            finding.add_indicator(
                Indicator(type=IndicatorType.CVE, value=cve, confidence=Confidence(95))
            )
        for asn in set(_ASN.findall(haystack)):
            finding.add_indicator(
                Indicator(type=IndicatorType.ASN, value=asn.upper(), confidence=Confidence(85))
            )
        # Domínios: filtramos por TLD conhecida para reduzir ruído.
        for dom in set(_DOMAIN.findall(haystack)):
            tld = dom.rsplit(".", 1)[-1].lower()
            if tld not in _COMMON_TLDS:
                continue
            if dom.lower() in {i.value.lower() for i in finding.indicators}:
                continue
            finding.add_indicator(
                Indicator(type=IndicatorType.DOMAIN, value=dom, confidence=Confidence(70))
            )
        return finding

    @staticmethod
    def _haystack(finding: Finding) -> str:
        parts = [finding.title, finding.description]
        parts.extend(str(v) for v in finding.normalized_data.values() if isinstance(v, str))
        parts.extend(str(v) for v in finding.raw_data.values() if isinstance(v, str))
        return "\n".join(p for p in parts if p)

    @staticmethod
    def _is_public_ip(ip: str) -> bool:
        octets = ip.split(".")
        if octets[0] == "10":
            return False
        if octets[0] == "127":
            return False
        if octets[0] == "0":
            return False
        if octets[0] == "169" and octets[1] == "254":
            return False
        if octets[0] == "172" and 16 <= int(octets[1]) <= 31:
            return False
        if octets[0] == "192" and octets[1] == "168":
            return False
        return True
