"""Builder pattern para ``Finding``. Utilizado por conectores e testes."""

from __future__ import annotations

from typing import Any, Self

from ..entities import Artifact, Finding, Indicator
from ..value_objects import Category, Confidence, Score, Severity, SourceRef, TLP


class FindingBuilder:
    """API fluente para construir ``Finding``s consistentes."""

    def __init__(self) -> None:
        self._title: str | None = None
        self._description: str = ""
        self._source: SourceRef | None = None
        self._connector: str | None = None
        self._category: Category = Category.OTHER
        self._severity: Severity = Severity.INFO
        self._score: Score = Score.zero()
        self._confidence: Confidence = Confidence.medium()
        self._tlp: TLP = TLP.AMBER
        self._raw: dict[str, Any] = {}
        self._normalized: dict[str, Any] = {}
        self._metadata: dict[str, Any] = {}
        self._tags: set[str] = set()
        self._artifacts: list[Artifact] = []
        self._indicators: list[Indicator] = []

    # --- Fluent setters -----------------------------------------------------

    def title(self, value: str) -> Self:
        self._title = value
        return self

    def description(self, value: str) -> Self:
        self._description = value or ""
        return self

    def source(self, value: SourceRef) -> Self:
        self._source = value
        return self

    def connector(self, value: str) -> Self:
        self._connector = value
        return self

    def category(self, value: Category | str) -> Self:
        self._category = Category.coerce(value)
        return self

    def severity(self, value: Severity | str) -> Self:
        self._severity = Severity.from_string(value) if isinstance(value, str) else value
        return self

    def score(self, value: float | Score) -> Self:
        self._score = value if isinstance(value, Score) else Score(float(value))
        return self

    def confidence(self, value: int | Confidence) -> Self:
        self._confidence = value if isinstance(value, Confidence) else Confidence(int(value))
        return self

    def tlp(self, value: TLP | str) -> Self:
        self._tlp = TLP.coerce(value)
        return self

    def raw(self, value: dict[str, Any]) -> Self:
        self._raw = dict(value)
        return self

    def normalized(self, value: dict[str, Any]) -> Self:
        self._normalized = dict(value)
        return self

    def metadata(self, **kwargs: Any) -> Self:
        self._metadata.update(kwargs)
        return self

    def tag(self, *tags: str) -> Self:
        for t in tags:
            if t:
                self._tags.add(t)
        return self

    def artifact(self, artifact: Artifact) -> Self:
        self._artifacts.append(artifact)
        return self

    def indicator(self, indicator: Indicator) -> Self:
        self._indicators.append(indicator)
        return self

    # --- Build --------------------------------------------------------------

    def build(self) -> Finding:
        if self._source is None:
            raise ValueError("FindingBuilder requires .source(...)")
        connector = self._connector or self._source.connector
        finding = Finding(
            title=self._title or "(untitled)",
            description=self._description,
            source=self._source,
            connector=connector,
            category=self._category,
            severity=self._severity,
            score=self._score,
            confidence=self._confidence,
            tlp=self._tlp,
            raw_data=self._raw,
            normalized_data=self._normalized,
            metadata=self._metadata,
            tags=set(self._tags),
        )
        for a in self._artifacts:
            finding.add_artifact(a)
        for i in self._indicators:
            finding.add_indicator(i)
        return finding
