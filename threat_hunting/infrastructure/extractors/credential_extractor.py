"""CredentialExtractor — extrai user:password, chaves API, JWTs, PEMs."""

from __future__ import annotations

import re

from ...core.domain.entities import Finding, Indicator
from ...core.domain.value_objects import Confidence, IndicatorType

_USERPASS = re.compile(r"([A-Za-z0-9._%+-]{2,64})\s*:\s*([^\s:]{4,64})")
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_JWT = re.compile(r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+")
_PEM = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")


class CredentialExtractor:
    """Extrai credenciais textuais de baixo/médio risco de falso positivo."""

    async def extract(self, finding: Finding) -> Finding:
        haystack = self._haystack(finding)

        for k in set(_AWS_KEY.findall(haystack)):
            finding.add_indicator(
                Indicator(type=IndicatorType.CREDENTIAL, value=f"aws_access_key:{k}",
                          confidence=Confidence(95), tags={"aws", "credential"})
            )
        for j in set(_JWT.findall(haystack)):
            finding.add_indicator(
                Indicator(type=IndicatorType.CREDENTIAL, value=f"jwt:{j[:32]}...",
                          confidence=Confidence(80), tags={"jwt", "credential"})
            )
        if _PEM.search(haystack):
            finding.add_indicator(
                Indicator(type=IndicatorType.CREDENTIAL, value="private-key-pem",
                          confidence=Confidence(99), tags={"key", "pem"})
            )
        # user:pass — só marca até 20 por finding para não inflar
        matches = _USERPASS.findall(haystack)
        for user, pwd in matches[:20]:
            if "@" in user or user.isnumeric():
                continue
            finding.add_indicator(
                Indicator(
                    type=IndicatorType.CREDENTIAL,
                    value=f"userpass:{user}",
                    confidence=Confidence(45),
                    tags={"userpass"},
                    context={"password_hint": pwd[:2] + "***"},
                )
            )
        return finding

    @staticmethod
    def _haystack(finding: Finding) -> str:
        return "\n".join(
            [finding.title, finding.description]
            + [str(v) for v in finding.normalized_data.values() if isinstance(v, str)]
        )
