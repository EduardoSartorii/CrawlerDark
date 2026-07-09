"""Camada de persistência (SQLAlchemy).

Responsabilidade
----------------
Definir o esquema relacional (ORM), o gerenciamento de sessões/engine e os
repositórios que encapsulam as operações de leitura/escrita. O restante da
plataforma nunca fala SQL diretamente — sempre via repositórios.
"""

from __future__ import annotations

from phishing_intel.database.models import (
    Base,
    CampaignORM,
    CertificateORM,
    FingerprintORM,
    InfrastructureORM,
    MispEventORM,
    PhishingSiteORM,
)
from phishing_intel.database.repositories import (
    CampaignRepository,
    CertificateRepository,
    FingerprintRepository,
    InfrastructureRepository,
    MispEventRepository,
    PhishingSiteRepository,
    RepositoryBundle,
)
from phishing_intel.database.session import Database

__all__ = [
    "Base",
    "CampaignORM",
    "CampaignRepository",
    "CertificateORM",
    "CertificateRepository",
    "Database",
    "FingerprintORM",
    "FingerprintRepository",
    "InfrastructureORM",
    "InfrastructureRepository",
    "MispEventORM",
    "MispEventRepository",
    "PhishingSiteORM",
    "PhishingSiteRepository",
    "RepositoryBundle",
]
