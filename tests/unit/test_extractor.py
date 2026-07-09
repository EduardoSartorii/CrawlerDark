"""Unit tests for the regex IOC extractor (including validation)."""

from __future__ import annotations

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.infrastructure.extractors.ioc_extractor import RegexIOCExtractor


def _extract(text: str) -> dict[IndicatorType, list[str]]:
    record = RawRecord(source="s", connector="c", content=text)
    out: dict[IndicatorType, list[str]] = {}
    for ind in RegexIOCExtractor().extract(record):
        out.setdefault(ind.type, []).append(ind.value)
    return out


def test_extracts_common_iocs() -> None:
    text = (
        "visit http://evil.example.com from 8.8.8.8, hash "
        "44d88612fea8a8f36de82e1278abb02f and CVE-2024-3094"
    )
    found = _extract(text)
    assert found[IndicatorType.URL] == ["http://evil.example.com"]
    assert "8.8.8.8" in found[IndicatorType.IPV4]
    assert found[IndicatorType.MD5] == ["44d88612fea8a8f36de82e1278abb02f"]
    assert found[IndicatorType.CVE] == ["CVE-2024-3094"]


def test_valid_credit_card_passes_luhn_invalid_rejected() -> None:
    assert IndicatorType.CREDIT_CARD in _extract("card 4111 1111 1111 1111")
    assert IndicatorType.CREDIT_CARD not in _extract("num 4111 1111 1111 1112")


def test_valid_cpf_and_cnpj_validation() -> None:
    assert IndicatorType.CPF in _extract("CPF 529.982.247-25")
    assert IndicatorType.CPF not in _extract("CPF 111.111.111-11")
    assert IndicatorType.CNPJ in _extract("CNPJ 11.222.333/0001-81")


def test_credential_pair_not_confused_with_url() -> None:
    found = _extract("login user@x.com:secret at http://a.example.com/p")
    assert any(":secret" in v for v in found[IndicatorType.CREDENTIAL])
    assert all("http" not in v for v in found[IndicatorType.CREDENTIAL])
