"""Unit tests for the indicator extractor and validators."""

from __future__ import annotations

import pytest

from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.infrastructure.extractors.indicator_extractor import IndicatorExtractor
from threat_hunting.infrastructure.extractors.validators import (
    cnpj_valid,
    cpf_valid,
    ipv4_valid,
    luhn_valid,
)


@pytest.fixture
def extractor() -> IndicatorExtractor:
    return IndicatorExtractor()


def test_extract_common_iocs(extractor):
    text = (
        "contact admin@acme-corp.com at 45.133.1.55 via evil-acme[.]com "
        "md5 44d88612fea8a8f36de82e1278abb02f CVE-2021-44228"
    )
    found = {i.type for i in extractor.extract(text)}
    assert IndicatorType.EMAIL in found
    assert IndicatorType.IPV4 in found
    assert IndicatorType.MD5 in found
    assert IndicatorType.CVE in found
    assert IndicatorType.DOMAIN in found


def test_extract_defanged_url(extractor):
    found = {i.value for i in extractor.extract("visit hxxps://bad[.]site/path")}
    assert "https://bad.site/path" in found


def test_extract_validates_documents(extractor):
    text = "CPF 529.982.247-25 CNPJ 11.222.333/0001-81 card 4111111111111111"
    types = {i.type for i in extractor.extract(text)}
    assert IndicatorType.CPF in types
    assert IndicatorType.CNPJ in types
    assert IndicatorType.CREDIT_CARD in types


def test_invalid_documents_are_rejected(extractor):
    # Invalid CPF / card should not be extracted as such.
    text = "CPF 111.111.111-11 card 1234567890123456"
    types = {i.type for i in extractor.extract(text)}
    assert IndicatorType.CPF not in types
    assert IndicatorType.CREDIT_CARD not in types


def test_extract_empty_text(extractor):
    assert extractor.extract("") == []


def test_extract_many_deduplicates(extractor):
    result = extractor.extract_many(["1.2.3.4", "1.2.3.4 and 5.6.7.8"])
    values = sorted(i.value for i in result if i.type is IndicatorType.IPV4)
    assert values == ["1.2.3.4", "5.6.7.8"]


@pytest.mark.parametrize("card,ok", [("4111111111111111", True), ("4111111111111112", False)])
def test_luhn(card, ok):
    assert luhn_valid(card) is ok


@pytest.mark.parametrize("value,ok", [("0.0.0.0", True), ("256.1.1.1", False), ("a.b.c.d", False)])
def test_ipv4(value, ok):
    assert ipv4_valid(value) is ok


def test_cpf_and_cnpj():
    assert cpf_valid("529.982.247-25")
    assert not cpf_valid("529.982.247-24")
    assert cnpj_valid("11.222.333/0001-81")
    assert not cnpj_valid("11.222.333/0001-80")
