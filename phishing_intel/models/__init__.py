"""Modelos de domínio (Pydantic) trafegados pelo pipeline.

Responsabilidade
----------------
Definir estruturas de dados tipadas e validadas que representam os
resultados de cada etapa da análise (findings), a infraestrutura extraída
e as campanhas correlacionadas. Estes modelos são a *linguagem comum* entre
coletores, analisadores, correlacionadores e a camada de enriquecimento.
"""

from __future__ import annotations

from phishing_intel.models.campaign import (
    AttributionSignal,
    Campaign,
    ConfidenceLevel,
    FingerprintBundle,
)
from phishing_intel.models.findings import (
    AnalysisResult,
    BrandDetection,
    DomForm,
    DomStructure,
    ExfiltrationDestination,
    ExfiltrationKind,
    JavaScriptFindings,
    PhishingType,
)
from phishing_intel.models.infrastructure import (
    CertificateInfo,
    DnsRecords,
    InfrastructureInfo,
)

__all__ = [
    "AnalysisResult",
    "AttributionSignal",
    "BrandDetection",
    "Campaign",
    "CertificateInfo",
    "ConfidenceLevel",
    "DnsRecords",
    "DomForm",
    "DomStructure",
    "ExfiltrationDestination",
    "ExfiltrationKind",
    "FingerprintBundle",
    "InfrastructureInfo",
    "JavaScriptFindings",
    "PhishingType",
]
