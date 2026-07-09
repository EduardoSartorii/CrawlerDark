"""
Infrastructure correlation module.

Correlates phishing incidents by shared hosting infrastructure
(IP, ASN, provider) for operator and campaign attribution.

Architectural Responsibility:
    Links incidents through network-level indicators complementing
    content-based fingerprint correlation.
"""

from __future__ import annotations

from typing import Any

import structlog

from phishing_intel.database.repositories import InfrastructureRepository, PhishingSiteRepository
from phishing_intel.database.session import get_session
from phishing_intel.models.findings import AnalysisResult, InfrastructureFinding

logger = structlog.get_logger(__name__)


class InfrastructureCorrelator:
    """Infrastructure-based incident correlation."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def find_related(
        self, infrastructure: InfrastructureFinding
    ) -> list[dict[str, Any]]:
        """
        Find incidents sharing infrastructure with given finding.

        Args:
            infrastructure: Infrastructure metadata to correlate.

        Returns:
            List of related incident summaries with match type.
        """
        logger.info(
            "infrastructure_correlation_start",
            ip=infrastructure.ip,
            asn=infrastructure.asn,
        )

        related: list[dict[str, Any]] = []

        with get_session() as session:
            repo = InfrastructureRepository(session)

            if infrastructure.ip:
                records = repo.get_by_ip(infrastructure.ip)
                for rec in records:
                    related.append({
                        "match_type": "ip",
                        "value": infrastructure.ip,
                        "domain": rec.domain,
                    })

            if infrastructure.asn:
                records = repo.get_by_asn(infrastructure.asn)
                for rec in records:
                    related.append({
                        "match_type": "asn",
                        "value": infrastructure.asn,
                        "ip": rec.ip,
                        "provider": rec.provider,
                    })

        logger.info("infrastructure_correlation_complete", matches=len(related))
        return related

    def correlate_batch(
        self, results: list[AnalysisResult]
    ) -> dict[str, list[str]]:
        """
        Group analysis results by shared infrastructure.

        Args:
            results: List of analysis results.

        Returns:
            Mapping of infrastructure key to related URLs.
        """
        groups: dict[str, list[str]] = {}

        for result in results:
            if not result.infrastructure:
                continue
            infra = result.infrastructure
            keys = []
            if infra.ip:
                keys.append(f"ip:{infra.ip}")
            if infra.asn:
                keys.append(f"asn:{infra.asn}")
            if infra.hosting_provider:
                keys.append(f"provider:{infra.hosting_provider}")

            for key in keys:
                groups.setdefault(key, []).append(result.url)

        return groups
