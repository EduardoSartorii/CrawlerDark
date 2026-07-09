"""In-memory storage adapters for repositories and unit of work."""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.contracts import FindingRepositoryPort, RuleRepositoryPort, UnitOfWorkPort
from threat_hunting.domain.entities import Finding
from threat_hunting.domain.rules import DetectionRule, RuleType


class InMemoryFindingRepository(FindingRepositoryPort):
    """In-memory repository used by tests and local CLI runs."""

    def __init__(self) -> None:
        self._items: list[Finding] = []

    def save_many(self, findings: Sequence[Finding]) -> None:
        self._items.extend(findings)

    def list_all(self) -> Sequence[Finding]:
        return list(self._items)


class InMemoryRuleRepository(RuleRepositoryPort):
    """Repository that returns dynamic rules from in-memory definitions."""

    def __init__(self, rule_items: Sequence[dict[str, object]] | None = None) -> None:
        raw_rules = list(rule_items or [])
        if not raw_rules:
            raw_rules = [
                {
                    "rule_id": "default-keyword-1",
                    "name": "credential keyword",
                    "rule_type": RuleType.KEYWORD.value,
                    "expression": "credential",
                },
                {
                    "rule_id": "default-threat-actor-1",
                    "name": "darkspider actor",
                    "rule_type": RuleType.THREAT_ACTOR_MATCH.value,
                    "expression": "darkspider",
                },
            ]
        self._rules = [DetectionRule(**item) for item in raw_rules]

    def load_detection_rules(self) -> Sequence[DetectionRule]:
        return list(self._rules)


class InMemoryUnitOfWork(UnitOfWorkPort):
    """No-op transactional boundary for in-memory repository."""

    def __init__(self, findings: InMemoryFindingRepository) -> None:
        self.findings = findings

    def __enter__(self) -> "InMemoryUnitOfWork":
        return self

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if exc:
            self.rollback()
