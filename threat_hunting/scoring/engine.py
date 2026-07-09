"""Scoring Engine — configurable weighted scoring.

Responsibility
--------------
Compute Finding score from detection matches, IOC types, source reputation,
VIP/brand context and recurrence. All weights loaded from config/scoring.yaml.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
import yaml

from threat_hunting.core.application.ports import ScoringEnginePort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import FindingCategory, IndicatorType, Severity
from threat_hunting.core.domain.value_objects import Confidence, Score

logger = structlog.get_logger(__name__)

DEFAULT_WEIGHTS: dict[str, float] = {
    "regex_match": 5.0,
    "yara_match": 15.0,
    "sigma_match": 10.0,
    "keyword_match": 3.0,
    "vip_match": 20.0,
    "ioc_match": 12.0,
    "credential": 18.0,
    "card": 22.0,
    "email": 8.0,
    "document": 10.0,
    "cpf": 15.0,
    "cnpj": 15.0,
    "domain": 6.0,
    "threat_actor": 25.0,
    "source_reputation": 5.0,
    "context": 4.0,
    "ioc_count": 2.0,
    "recurrence": 3.0,
    "history": 2.0,
    "blacklist": 30.0,
    "whitelist": -15.0,
    "heuristic": 5.0,
}

CATEGORY_BONUS: dict[str, float] = {
    FindingCategory.CREDENTIAL.value: 10.0,
    FindingCategory.CARD.value: 15.0,
    FindingCategory.LEAK.value: 12.0,
    FindingCategory.DARK_WEB.value: 8.0,
    FindingCategory.VIP_MONITORING.value: 15.0,
    FindingCategory.BRAND_MONITORING.value: 8.0,
    FindingCategory.THREAT_ACTOR.value: 12.0,
}

SOURCE_REPUTATION: dict[str, float] = {
    "darkweb": 10.0,
    "deepweb": 8.0,
    "paste": 6.0,
    "telegram": 5.0,
    "github": 4.0,
    "misp": 7.0,
    "threatfox": 7.0,
    "reddit": 3.0,
    "news": 2.0,
    "rss": 2.0,
}

IOC_TYPE_WEIGHTS: dict[str, float] = {
    IndicatorType.CARD.value: 12.0,
    IndicatorType.CPF.value: 10.0,
    IndicatorType.CNPJ.value: 10.0,
    IndicatorType.EMAIL.value: 5.0,
    IndicatorType.WALLET.value: 8.0,
    IndicatorType.HASH_SHA256.value: 6.0,
    IndicatorType.IP.value: 4.0,
    IndicatorType.DOMAIN.value: 4.0,
    IndicatorType.URL.value: 3.0,
}


class ScoringEngine(ScoringEnginePort):
    """Configurable scoring engine.

    Business rules
    --------------
    - Base score starts at 0.
    - Each matched detection contributes its score_delta (already applied)
      plus type-based weight from config.
    - Category, source reputation, IOC count add bonuses.
    - Final score clamped to [0, 100].
    - Confidence derived from match density.
    """

    def __init__(self, config_path: Path | str | None = None) -> None:
        self._weights = dict(DEFAULT_WEIGHTS)
        self._category_bonus = dict(CATEGORY_BONUS)
        self._source_reputation = dict(SOURCE_REPUTATION)
        self._ioc_weights = dict(IOC_TYPE_WEIGHTS)
        self._severity_floor: dict[str, float] = {
            Severity.INFORMATIONAL.value: 0.0,
            Severity.LOW.value: 15.0,
            Severity.MEDIUM.value: 35.0,
            Severity.HIGH.value: 60.0,
            Severity.CRITICAL.value: 80.0,
        }
        if config_path:
            self._load_config(Path(config_path))

    def _load_config(self, path: Path) -> None:
        if not path.exists():
            logger.warning("scoring.config_missing", path=str(path))
            return
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self._weights.update(data.get("weights", {}))
        self._category_bonus.update(data.get("category_bonus", {}))
        self._source_reputation.update(data.get("source_reputation", {}))
        self._ioc_weights.update(data.get("ioc_type_weights", {}))
        if "severity_floor" in data:
            self._severity_floor.update(data["severity_floor"])
        logger.info("scoring.config_loaded", path=str(path))

    async def score(self, finding: Finding) -> Finding:
        total = float(finding.score)  # may already include detection deltas
        breakdown: dict[str, float] = {"base_from_detections": total}

        # Type-based weight for matched detections
        for match in finding.detections:
            if not match.matched:
                continue
            weight_key = f"{match.rule_type}_match"
            # map rule types to weight keys
            key_map = {
                "regex": "regex_match",
                "yara": "yara_match",
                "sigma": "sigma_match",
                "keyword": "keyword_match",
                "ioc_match": "ioc_match",
                "threat_actor_match": "threat_actor",
                "heuristic": "heuristic",
                "whitelist": "whitelist",
                "blacklist": "blacklist",
                "threshold": "ioc_count",
                "composite": "context",
            }
            wkey = key_map.get(match.rule_type, weight_key)
            w = self._weights.get(wkey, 0.0)
            # Avoid double-counting score_delta already applied; add weight once per match
            if match.rule_type == "whitelist":
                total += w  # negative
                breakdown[f"whitelist:{match.rule_id}"] = w
            elif match.score_delta == 0:
                total += w
                breakdown[f"{match.rule_type}:{match.rule_id}"] = w

        # Category bonus
        cat_bonus = self._category_bonus.get(finding.category.value, 0.0)
        total += cat_bonus
        breakdown["category"] = cat_bonus

        # Source reputation
        src = finding.source.lower()
        src_bonus = self._source_reputation.get(src, self._weights.get("source_reputation", 0.0))
        # Also check connector name
        if src not in self._source_reputation:
            src_bonus = self._source_reputation.get(finding.connector.lower(), src_bonus)
        total += src_bonus
        breakdown["source"] = src_bonus

        # IOC type weights
        ioc_bonus = 0.0
        for ind in finding.indicators:
            ioc_bonus += self._ioc_weights.get(ind.type.value, 1.0)
        # Cap IOC contribution
        ioc_bonus = min(ioc_bonus, 40.0)
        total += ioc_bonus
        breakdown["iocs"] = ioc_bonus

        # IOC count recurrence weight
        count_bonus = len(finding.indicators) * self._weights.get("ioc_count", 2.0)
        count_bonus = min(count_bonus, 20.0)
        total += count_bonus
        breakdown["ioc_count"] = count_bonus

        # Severity floor
        floor = self._severity_floor.get(finding.severity.value, 0.0)
        if total < floor:
            breakdown["severity_floor"] = floor - total
            total = floor

        final = Score(value=max(0.0, min(100.0, total)))
        finding.update_score(final)

        # Confidence from match density
        matched = sum(1 for d in finding.detections if d.matched)
        total_rules = max(len(finding.detections), 1)
        conf = min(1.0, 0.3 + (matched / total_rules) * 0.5 + (0.2 if finding.indicators else 0.0))
        finding.update_confidence(Confidence(value=round(conf, 3)))

        finding.normalized_data = {
            **finding.normalized_data,
            "score_breakdown": breakdown,
        }
        logger.debug(
            "scoring.completed",
            finding_id=str(finding.id),
            score=float(final),
            confidence=conf,
        )
        return finding

    def get_weights(self) -> dict[str, Any]:
        return {
            "weights": self._weights,
            "category_bonus": self._category_bonus,
            "source_reputation": self._source_reputation,
            "ioc_type_weights": self._ioc_weights,
        }


__all__ = ["ScoringEngine", "DEFAULT_WEIGHTS"]
