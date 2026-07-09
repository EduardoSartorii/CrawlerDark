"""CorrelationEngine.

Responsibility
--------------
Discover and record relationships between findings within a batch and group
related findings into campaigns. Two findings are correlated when they share at
least one indicator or a common threat-actor tag. The engine:

* adds ``shared_indicator`` / ``same_actor`` relationships on both findings;
* forms :class:`Campaign`s from connected components of the correlation graph.

Correlation is purely in-domain (operates on entities), so it stays independent
of any storage/graph backend.
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.domain.entities.campaign import Campaign
from threat_hunting.core.domain.entities.finding import Finding
from threat_hunting.core.domain.enums import RelationshipType
from threat_hunting.core.domain.value_objects.relationship import Relationship


class CorrelationEngine:
    """Correlates findings by shared indicators/actors and builds campaigns."""

    def __init__(self, *, min_shared_indicators: int = 1) -> None:
        self._min_shared = max(1, min_shared_indicators)

    def _actor_tags(self, finding: Finding) -> set[str]:
        """Return the threat-actor names detected on a finding (lower-cased)."""
        return {
            match.matched.lower()
            for match in finding.detections
            if match.rule_type == "threat_actor"
        }

    def correlate(self, findings: Sequence[Finding]) -> list[Campaign]:
        """Add relationships between findings and return discovered campaigns."""
        n = len(findings)
        parent = list(range(n))  # union-find for connected components

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            parent[find(a)] = find(b)

        for i in range(n):
            for j in range(i + 1, n):
                fi, fj = findings[i], findings[j]
                shared = fi.indicator_keys & fj.indicator_keys
                shared_actors = self._actor_tags(fi) & self._actor_tags(fj)

                linked = False
                if len(shared) >= self._min_shared:
                    for key in sorted(shared):
                        fi.add_relationship(
                            Relationship(
                                source_ref=fi.id,
                                target_ref=fj.id,
                                type=RelationshipType.SHARED_INDICATOR,
                                description=f"shared indicator {key}",
                            )
                        )
                    linked = True
                if shared_actors:
                    fi.add_relationship(
                        Relationship(
                            source_ref=fi.id,
                            target_ref=fj.id,
                            type=RelationshipType.SAME_ACTOR,
                            description=f"shared actor {sorted(shared_actors)}",
                        )
                    )
                    linked = True
                if linked:
                    union(i, j)

        return self._build_campaigns(findings, parent, find)

    def _build_campaigns(self, findings, parent, find) -> list[Campaign]:
        """Group findings by connected component into campaigns (size >= 2)."""
        groups: dict[int, list[int]] = {}
        for idx in range(len(findings)):
            groups.setdefault(find(idx), []).append(idx)

        campaigns: list[Campaign] = []
        for members in groups.values():
            if len(members) < 2:
                continue
            campaign = Campaign(name=f"campaign-{findings[members[0]].id[:8]}")
            indicator_keys: set[str] = set()
            for idx in members:
                finding = findings[idx]
                campaign.add_finding(finding.id)
                indicator_keys |= finding.indicator_keys
                finding.add_tag(f"campaign:{campaign.id[:8]}")
            campaign.indicator_keys = sorted(indicator_keys)
            campaigns.append(campaign)
        return campaigns
