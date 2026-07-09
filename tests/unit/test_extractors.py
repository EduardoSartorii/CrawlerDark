"""Testes dos extractors (IOC, credenciais, cartões, wallets, docs)."""

from __future__ import annotations

import pytest

from threat_hunting.core.domain.builders import FindingBuilder
from threat_hunting.core.domain.value_objects import IndicatorType, SourceRef
from threat_hunting.infrastructure.extractors import (
    CardExtractor,
    CompositeExtractor,
    CredentialExtractor,
    DocumentExtractor,
    IOCExtractor,
    WalletExtractor,
)


def _finding(text: str):
    return (
        FindingBuilder()
        .title("test")
        .description(text)
        .source(SourceRef(source="t", connector="ut"))
        .build()
    )


class TestIOCExtractor:
    async def test_extracts_ips_urls_hashes_emails_cves(self):
        f = _finding(
            "Contact john@evil.example about CVE-2024-12345. "
            "Malware hash: 44d88612fea8a8f36de82e1278abb02f "
            "Server 8.8.8.8 hosted https://malicious.example/x?q=1"
        )
        f = await IOCExtractor().extract(f)
        types = {i.type for i in f.indicators}
        assert IndicatorType.EMAIL in types
        assert IndicatorType.IP in types
        assert IndicatorType.URL in types
        assert IndicatorType.CVE in types
        assert IndicatorType.HASH_MD5 in types

    async def test_ignores_private_ips(self):
        f = _finding("192.168.1.1 talks to 10.0.0.5 and 172.16.5.5")
        f = await IOCExtractor().extract(f)
        assert not any(i.type is IndicatorType.IP for i in f.indicators)


class TestCredentialExtractor:
    async def test_detects_aws_key(self):
        f = _finding("token = 'AKIAIOSFODNN7EXAMPLE' # never commit")
        f = await CredentialExtractor().extract(f)
        assert any("aws_access_key" in i.value for i in f.indicators)

    async def test_detects_pem_marker(self):
        f = _finding("-----BEGIN RSA PRIVATE KEY-----")
        f = await CredentialExtractor().extract(f)
        assert any(i.value == "private-key-pem" for i in f.indicators)


class TestCardExtractor:
    async def test_luhn_valid_pan_detected_and_masked(self):
        f = _finding("Card: 4111 1111 1111 1111")
        f = await CardExtractor().extract(f)
        pans = [i for i in f.indicators if i.type is IndicatorType.CARD_PAN]
        assert len(pans) == 1
        assert pans[0].value.startswith("411111") and pans[0].value.endswith("1111")

    async def test_luhn_invalid_ignored(self):
        f = _finding("Card: 4111 1111 1111 1112")
        f = await CardExtractor().extract(f)
        assert not any(i.type is IndicatorType.CARD_PAN for i in f.indicators)


class TestWalletExtractor:
    async def test_btc_and_eth(self):
        f = _finding("BTC: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 ETH: 0x" + "a" * 40)
        f = await WalletExtractor().extract(f)
        types = {i.type for i in f.indicators}
        assert IndicatorType.WALLET_BTC in types
        assert IndicatorType.WALLET_ETH in types


class TestDocumentExtractor:
    async def test_cpf_valid(self):
        f = _finding("CPF: 123.456.789-09")
        f = await DocumentExtractor().extract(f)
        assert any(i.type is IndicatorType.CPF for i in f.indicators)

    async def test_cnpj_valid(self):
        # 45.723.174/0001-10 is a valid demo CNPJ
        f = _finding("CNPJ: 45.723.174/0001-10")
        f = await DocumentExtractor().extract(f)
        assert any(i.type is IndicatorType.CNPJ for i in f.indicators)

    async def test_invalid_cpf_ignored(self):
        f = _finding("CPF: 111.111.111-11")
        f = await DocumentExtractor().extract(f)
        assert not any(i.type is IndicatorType.CPF for i in f.indicators)


class TestCompositeExtractor:
    async def test_composite_chains_all_extractors(self):
        text = "email a@b.com key AKIAIOSFODNN7EXAMPLE card 4111 1111 1111 1111"
        f = _finding(text)
        composite = CompositeExtractor(
            [IOCExtractor(), CredentialExtractor(), CardExtractor(), WalletExtractor(), DocumentExtractor()]
        )
        f = await composite.extract(f)
        types = {i.type for i in f.indicators}
        assert IndicatorType.EMAIL in types
        assert IndicatorType.CREDENTIAL in types
        assert IndicatorType.CARD_PAN in types
