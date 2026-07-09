"""Extractors — extração de IOCs, credenciais, cartões, wallets, docs.

Implementam ``ExtractorPort``. Usados pelo ``ExtractStage`` do pipeline.
"""

from .card_extractor import CardExtractor
from .composite_extractor import CompositeExtractor
from .credential_extractor import CredentialExtractor
from .document_extractor import DocumentExtractor
from .ioc_extractor import IOCExtractor
from .wallet_extractor import WalletExtractor

__all__ = [
    "CardExtractor",
    "CompositeExtractor",
    "CredentialExtractor",
    "DocumentExtractor",
    "IOCExtractor",
    "WalletExtractor",
]
