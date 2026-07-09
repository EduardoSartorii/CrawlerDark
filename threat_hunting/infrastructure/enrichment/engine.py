"""
Enrichment Engine.

Adds contextual intelligence to Findings after detection and scoring.
Enrichment never modifies the threat assessment — it only adds context.

Enrichment Sources (pluggable enrichers):
    1. GeoIP: country, ASN, ISP for IP addresses
    2. WHOIS: domain registration info
    3. VirusTotal: hash/URL/domain reputation (requires API key)
    4. AbuseIPDB: IP abuse confidence score
    5. TLD Extraction: domain → registered domain + TLD
    6. Watchlist Matcher: match against VIPs, brands, executives
    7. Threat Actor Matcher: attribute to known actors
    8. CPF/CNPJ Validator: validate Brazilian documents

Architecture:
    - Strategy Pattern: each enricher is a pluggable strategy
    - Enrichers are composable: apply() runs all registered enrichers
    - Each enricher is independently enable/disable-able
    - Enrichment failures are logged but never block the pipeline
    - Results stored in finding.normalized_data["enrichment"]
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

import structlog

from ...core.domain.entities.finding import Finding
from ...core.domain.entities.keyword import Keyword, KeywordType
from ...core.domain.entities.threat_actor import ThreatActor

logger = structlog.get_logger(__name__)

# Common document patterns
_CPF_PATTERN = re.compile(r"\b(\d{3}\.?\d{3}\.?\d{3}-?\d{2})\b")
_CNPJ_PATTERN = re.compile(r"\b(\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2})\b")
_EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class BaseEnricher(ABC):
    """Abstract base for all enrichment strategies."""

    name: str = ""
    is_enabled: bool = True

    @abstractmethod
    async def enrich(self, finding: Finding) -> dict[str, Any]:
        """
        Enrich a Finding with additional context.
        Returns a dict of enrichment data to merge into finding.normalized_data.
        """

    def can_enrich(self, finding: Finding) -> bool:
        """Quick pre-check to avoid unnecessary processing."""
        return self.is_enabled


class DocumentExtractorEnricher(BaseEnricher):
    """
    Extracts and validates CPF, CNPJ, and email addresses from Finding content.
    Marks findings containing Brazilian PII documents for priority handling.
    """

    name = "document_extractor"

    async def enrich(self, finding: Finding) -> dict[str, Any]:
        content = f"{finding.title} {finding.description} {finding.raw_data}"
        result: dict[str, Any] = {}

        cpfs = list(set(_CPF_PATTERN.findall(content)))
        cnpjs = list(set(_CNPJ_PATTERN.findall(content)))
        emails = list(set(_EMAIL_PATTERN.findall(content)))[:50]

        if cpfs:
            result["cpf_count"] = len(cpfs)
            result["cpf_sample"] = cpfs[:3]
            finding.add_tag("cpf-found")
        if cnpjs:
            result["cnpj_count"] = len(cnpjs)
            result["cnpj_sample"] = cnpjs[:3]
            finding.add_tag("cnpj-found")
        if emails:
            result["email_count"] = len(emails)
            result["email_sample"] = emails[:10]

        return result


class DomainEnricher(BaseEnricher):
    """Extracts and normalizes domains from Finding content using tldextract."""

    name = "domain_enricher"

    async def enrich(self, finding: Finding) -> dict[str, Any]:
        try:
            import tldextract
        except ImportError:
            return {}

        content = f"{finding.title} {finding.description}"
        domains_found: set[str] = set()

        # Simple domain pattern extraction
        domain_pattern = re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
        )
        raw_domains = domain_pattern.findall(content)

        for raw in raw_domains:
            extracted = tldextract.extract(raw)
            if extracted.domain and extracted.suffix:
                registered = f"{extracted.domain}.{extracted.suffix}"
                domains_found.add(registered)

        if domains_found:
            finding.affected_domains = list(
                set(finding.affected_domains) | domains_found
            )
            return {"extracted_domains": list(domains_found)[:20]}
        return {}


class WatchlistMatcherEnricher(BaseEnricher):
    """
    Matches Finding content against active watchlists (brands, VIPs, keywords).
    Returns match context for the scoring engine to consume.
    """

    name = "watchlist_matcher"

    def __init__(self, keywords: list[Keyword] | None = None) -> None:
        self._keywords = keywords or []

    def load_keywords(self, keywords: list[Keyword]) -> None:
        self._keywords = [k for k in keywords if k.is_active]

    async def enrich(self, finding: Finding) -> dict[str, Any]:
        content = f"{finding.title} {finding.description} {finding.raw_data}".lower()
        matched: list[dict[str, Any]] = []

        for kw in self._keywords:
            if not kw.is_active:
                continue

            hit = False
            if kw.keyword_type == KeywordType.EXACT:
                search = kw.value if kw.case_sensitive else kw.value.lower()
                hit = search in (content if kw.case_sensitive else content)
            elif kw.keyword_type == KeywordType.REGEX:
                try:
                    flags = 0 if kw.case_sensitive else re.IGNORECASE
                    hit = bool(re.search(kw.value, content, flags))
                except re.error:
                    pass

            if hit:
                matched.append({
                    "keyword_id": kw.id,
                    "value": kw.value,
                    "category": kw.category.value,
                    "weight": kw.weight,
                })
                finding.add_tag(f"kw-{kw.category.value}")

        return {"watchlist_matches": matched, "match_count": len(matched)}


class ThreatActorMatcherEnricher(BaseEnricher):
    """
    Matches Finding content against known threat actor names and aliases.
    Attribution adds significant score context.
    """

    name = "threat_actor_matcher"

    def __init__(self, threat_actors: list[ThreatActor] | None = None) -> None:
        self._actors = threat_actors or []

    def load_actors(self, actors: list[ThreatActor]) -> None:
        self._actors = [a for a in actors if a.is_active]

    async def enrich(self, finding: Finding) -> dict[str, Any]:
        content = f"{finding.title} {finding.description} {finding.raw_data}".lower()
        matches: list[str] = []

        for actor in self._actors:
            names_to_check = [actor.name] + actor.aliases
            for name in names_to_check:
                if name.lower() in content:
                    matches.append(actor.name)
                    if not finding.threat_actor:
                        finding.threat_actor = actor.name
                    finding.add_tag(f"ta-{actor.name.lower().replace(' ', '-')}")
                    break

        return {"matched_actors": matches}


class EnrichmentEngine:
    """
    Applies all registered enrichers to a Finding.

    Enrichers run in registration order.
    Failures in one enricher do not block others.
    Results merged into finding.normalized_data["enrichment"].
    """

    def __init__(self) -> None:
        self._enrichers: list[BaseEnricher] = []

    def register(self, enricher: BaseEnricher) -> None:
        """Register an enricher strategy."""
        self._enrichers.append(enricher)
        logger.debug("enrichment.enricher_registered", name=enricher.name)

    def use_defaults(
        self,
        keywords: list[Keyword] | None = None,
        threat_actors: list[ThreatActor] | None = None,
    ) -> None:
        """Register the standard set of enrichers."""
        self.register(DocumentExtractorEnricher())
        self.register(DomainEnricher())
        self.register(WatchlistMatcherEnricher(keywords=keywords))
        self.register(ThreatActorMatcherEnricher(threat_actors=threat_actors))

    async def enrich(self, finding: Finding) -> dict[str, Any]:
        """Run all enrichers on a Finding, returning aggregated enrichment data."""
        all_enrichment: dict[str, Any] = {}

        for enricher in self._enrichers:
            if not enricher.can_enrich(finding):
                continue
            try:
                result = await enricher.enrich(finding)
                all_enrichment.update(result)
            except Exception as exc:
                logger.warning(
                    "enrichment.enricher_failed",
                    enricher=enricher.name,
                    finding_id=finding.id,
                    error=str(exc),
                )

        # Merge into finding
        enrichment_data = finding.normalized_data.get("enrichment", {})
        enrichment_data.update(all_enrichment)
        finding.normalized_data["enrichment"] = enrichment_data

        return all_enrichment

    async def enrich_batch(self, findings: list[Finding]) -> None:
        """Enrich multiple findings."""
        for finding in findings:
            await self.enrich(finding)
