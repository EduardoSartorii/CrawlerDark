"""GraphCorrelationEngine — cria relationships entre findings que compartilham
IOCs, threat actors, domínios, wallets etc.

Complexidade O(n*m) onde n = corpus e m = indicators por finding. Suficiente
para corpus recente (< 5000). Substituível por adapter Neo4j/OpenSearch quando
volume crescer, mantendo o mesmo ``CorrelationEnginePort``.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...core.domain.entities import Finding, Relationship, RelationshipType


class GraphCorrelationEngine:
    def __init__(self, *, max_relationships: int = 20) -> None:
        self._max = max_relationships

    async def correlate(self, finding: Finding, corpus: Sequence[Finding]) -> Finding:
        if not finding.indicators or not corpus:
            return finding
        my_indicators = {(i.type.value, i.value.lower()) for i in finding.indicators}
        my_actors = {t.lower() for t in finding.tags if t.startswith("actor:")}
        added = 0
        for other in corpus:
            if other.id == finding.id:
                continue
            other_indicators = {(i.type.value, i.value.lower()) for i in other.indicators}
            shared = my_indicators & other_indicators
            other_actors = {t.lower() for t in other.tags if t.startswith("actor:")}
            shares_actor = bool(my_actors & other_actors)
            if not shared and not shares_actor:
                continue
            rel_type = (
                RelationshipType.ATTRIBUTED_TO if shares_actor else RelationshipType.RELATED_TO
            )
            finding.add_relationship(
                Relationship(
                    source_id=finding.id,
                    target_id=other.id,
                    type=rel_type,
                    context={
                        "shared_indicators": [f"{t}:{v}" for t, v in sorted(shared)][:10],
                        "shared_actors": sorted(my_actors & other_actors)[:5],
                    },
                )
            )
            added += 1
            if added >= self._max:
                break
        if added:
            finding.record_event(
                "correlated",
                f"correlated with {added} finding(s)",
                {"count": added},
            )
        return finding
