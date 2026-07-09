"""IndicatorType — tipos suportados de observáveis técnicos (IOCs)."""

from __future__ import annotations

from enum import Enum


class IndicatorType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    EMAIL = "EMAIL"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    CVE = "CVE"
    ASN = "ASN"
    CERTIFICATE = "CERTIFICATE"
    WALLET_BTC = "WALLET_BTC"
    WALLET_ETH = "WALLET_ETH"
    CARD_PAN = "CARD_PAN"
    CPF = "CPF"
    CNPJ = "CNPJ"
    USERNAME = "USERNAME"
    TELEGRAM_HANDLE = "TELEGRAM_HANDLE"
    GITHUB_HANDLE = "GITHUB_HANDLE"
    CREDENTIAL = "CREDENTIAL"
    OTHER = "OTHER"
