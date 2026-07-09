"""
Correlation Engine.

Discovers relationships between Findings by identifying shared attributes.
This is how isolated signals become connected intelligence: a domain seen
in a paste, a GitHub repo, and a dark web forum post are linked automatically.

Correlation Strategy:
    1. Extract all correlatable attributes from each Finding
    2. Build an inverted index: attribute_value → [finding_ids]
    3. Findings sharing ≥1 attribute are correlated
    4. A Relationship entity is created for each correlated pair
    5. Correlated findings may trigger campaign/threat actor attribution

Correlatable Attributes:
    - IP addresses, ASNs
    - Domains, subdomains, FQDNs
    - Email addresses
    - Crypto wallets
    - Usernames/handles (Telegram, GitHub, forum)
    - Certificate fingerprints
    - Malware family names
    - Threat actor names/aliases
    - Campaign identifiers
    - File hashes

Design Patterns:
    - Strategy Pattern: each attribute type has its own extractor
    - Graph model: findings are nodes, correlations are edges
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from ...core.domain.entities.finding import Finding, Relationship

logger = structlog.get_logger(__name__)

# IOC extraction patterns
_PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "btc_wallet": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "onion": re.compile(r"\b[a-z2-7]{16,56}\.onion\b"),
}


@dataclass
class CorrelationMatch:
    """A single correlation between two findings."""

    finding_a_id: str
    finding_b_id: str
    shared_attributes: dict[str, list[str]] = field(default_factory=dict)
    relationship_types: list[str] = field(default_factory=list)
    confidence: float = 0.5

    @property
    def total_shared(self) -> int:
        return sum(len(v) for v in self.shared_attributes.values())


@dataclass
class CorrelationResult:
    """Complete correlation result for a batch of findings."""

    finding_count: int
    matches: list[CorrelationMatch] = field(default_factory=list)
    relationships_created: int = 0

    @property
    def correlation_rate(self) -> float:
        if self.finding_count == 0:
            return 0.0
        return len(self.matches) / self.finding_count


class AttributeExtractor:
    """Extracts correlatable attributes from a Finding."""

    def extract(self, finding: Finding) -> dict[str, set[str]]:
        """Return dict of attribute_type → set of values."""
        content = f"{finding.title} {finding.description} {finding.raw_data}".lower()
        attrs: dict[str, set[str]] = defaultdict(set)

        # Pattern-based extraction
        for attr_type, pattern in _PATTERNS.items():
            matches = pattern.findall(content)
            attrs[attr_type].update(m.lower() for m in matches)

        # Structured field extraction
        if finding.threat_actor:
            attrs["threat_actor"].add(finding.threat_actor.lower())
        if finding.campaign:
            attrs["campaign"].add(finding.campaign.lower())
        if finding.malware_family:
            attrs["malware_family"].add(finding.malware_family.lower())
        for brand in finding.affected_brands:
            attrs["brand"].add(brand.lower())
        for domain in finding.affected_domains:
            attrs["domain"].add(domain.lower())

        # Normalize metadata
        norm = finding.normalized_data
        for key in ("telegram_handle", "github_handle", "forum_user", "wallet"):
            if key in norm:
                attrs[key].add(str(norm[key]).lower())

        # Filter noise (single chars, numeric only, etc.)
        return {k: {v for v in vs if len(v) >= 4} for k, vs in attrs.items()}


class CorrelationEngine:
    """
    Correlates findings by shared attributes.

    Usage:
        engine = CorrelationEngine()
        result = engine.correlate(findings_batch)
        # findings now have Relationships attached
    """

    def __init__(
        self,
        min_shared_count: int = 1,
        min_confidence: float = 0.3,
    ) -> None:
        self._min_shared = min_shared_count
        self._min_confidence = min_confidence
        self._extractor = AttributeExtractor()

    def correlate(self, findings: list[Finding]) -> CorrelationResult:
        """
        Run correlation across a batch of findings.
        Attaches Relationship objects to findings that share attributes.
        """
        if len(findings) < 2:
            return CorrelationResult(finding_count=len(findings))

        result = CorrelationResult(finding_count=len(findings))

        # Build inverted index: (attr_type, attr_value) → [finding_idx]
        inverted: dict[tuple[str, str], list[int]] = defaultdict(list)
        all_attrs: list[dict[str, set[str]]] = []

        for i, finding in enumerate(findings):
            attrs = self._extractor.extract(finding)
            all_attrs.append(attrs)
            for attr_type, values in attrs.items():
                for value in values:
                    inverted[(attr_type, value)].append(i)

        # Find correlated pairs
        correlated_pairs: dict[tuple[int, int], CorrelationMatch] = {}

        for (attr_type, attr_value), indices in inverted.items():
            if len(indices) < 2:
                continue
            # All pairs sharing this attribute
            for i in range(len(indices)):
                for j in range(i + 1, len(indices)):
                    a, b = indices[i], indices[j]
                    pair_key = (min(a, b), max(a, b))

                    if pair_key not in correlated_pairs:
                        correlated_pairs[pair_key] = CorrelationMatch(
                            finding_a_id=findings[pair_key[0]].id,
                            finding_b_id=findings[pair_key[1]].id,
                        )
                    match = correlated_pairs[pair_key]
                    if attr_type not in match.shared_attributes:
                        match.shared_attributes[attr_type] = []
                    if attr_value not in match.shared_attributes[attr_type]:
                        match.shared_attributes[attr_type].append(attr_value)

        # Filter by minimum shared count and create relationships
        for (a_idx, b_idx), match in correlated_pairs.items():
            if match.total_shared < self._min_shared:
                continue

            match.confidence = min(0.9, 0.3 + 0.1 * match.total_shared)
            if match.confidence < self._min_confidence:
                continue

            relationship_type = self._infer_relationship_type(match.shared_attributes)
            match.relationship_types.append(relationship_type)
            result.matches.append(match)

            # Attach relationship to both findings
            rel = Relationship(
                source_id=match.finding_a_id,
                target_id=match.finding_b_id,
                relationship_type=relationship_type,
                confidence=match.confidence,
                description=f"Shared: {', '.join(match.shared_attributes.keys())}",
                metadata={"shared_attributes": match.shared_attributes},
            )
            findings[a_idx].add_relationship(rel)
            findings[b_idx].add_relationship(rel)
            result.relationships_created += 1

        logger.info(
            "correlation.complete",
            findings=len(findings),
            correlations=len(result.matches),
            relationships=result.relationships_created,
        )
        return result

    def _infer_relationship_type(self, shared: dict[str, list[str]]) -> str:
        """Infer STIX-style relationship type from shared attribute types."""
        if "threat_actor" in shared:
            return "attributed-to"
        if "campaign" in shared:
            return "part-of-campaign"
        if "malware_family" in shared:
            return "related-to"
        if "ip" in shared or "domain" in shared:
            return "shares-infrastructure"
        if "email" in shared:
            return "shares-identity"
        return "related-to"
