"""DocumentExtractor — CPF/CNPJ com validação dos dígitos verificadores."""

from __future__ import annotations

import re

from ...core.domain.entities import Finding, Indicator
from ...core.domain.value_objects import Confidence, IndicatorType

_CPF = re.compile(r"\b(\d{3}\.\d{3}\.\d{3}-\d{2})\b")
_CNPJ = re.compile(r"\b(\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2})\b")


def _cpf_valid(cpf: str) -> bool:
    digits = [int(d) for d in cpf if d.isdigit()]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for i in range(9, 11):
        total = sum(digits[j] * ((i + 1) - j) for j in range(i))
        check = (total * 10) % 11
        if check == 10:
            check = 0
        if check != digits[i]:
            return False
    return True


def _cnpj_valid(cnpj: str) -> bool:
    digits = [int(d) for d in cnpj if d.isdigit()]
    if len(digits) != 14 or len(set(digits)) == 1:
        return False
    weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights2 = [6] + weights1
    for pos, weights in ((12, weights1), (13, weights2)):
        total = sum(digits[i] * weights[i] for i in range(pos))
        check = total % 11
        check = 0 if check < 2 else 11 - check
        if check != digits[pos]:
            return False
    return True


class DocumentExtractor:
    async def extract(self, finding: Finding) -> Finding:
        text = "\n".join([finding.title, finding.description])
        for cpf in set(_CPF.findall(text)):
            if _cpf_valid(cpf):
                finding.add_indicator(
                    Indicator(
                        type=IndicatorType.CPF,
                        value=cpf,
                        confidence=Confidence(95),
                        tags={"cpf", "pii"},
                    )
                )
        for cnpj in set(_CNPJ.findall(text)):
            if _cnpj_valid(cnpj):
                finding.add_indicator(
                    Indicator(
                        type=IndicatorType.CNPJ,
                        value=cnpj,
                        confidence=Confidence(95),
                        tags={"cnpj", "pii"},
                    )
                )
        return finding
