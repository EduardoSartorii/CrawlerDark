"""WeightedScoringEngine — implementa ``ScoringEnginePort``.

Fórmula:
    final = clip(base + sum(component * weight) * severity_multiplier + source_bonus, 0, 100)

Componentes considerados:
* regex_match, yara_match, sigma_match — via timeline "rule.matched".
* vip_match, threat_actor, brand — via tags "watch:*".
* ioc_match — via indicators com tag "ioc-list-hit".
* credential, card, email, document, cpf, cnpj, domain_watch — via tipos de indicators.
* recurrence — placeholder incrementado por hooks futuros.
* indicator_count_step — bônus incremental por qtd de IOCs (cap ~15).
"""

from __future__ import annotations

from ...core.domain.entities import Finding
from ...core.domain.value_objects import IndicatorType, Score, Severity
from ..config.schemas import ScoringConfig


class WeightedScoringEngine:
    def __init__(self, config: ScoringConfig) -> None:
        self._config = config

    async def score(self, finding: Finding) -> Score:
        weights = self._config.weights
        base = float(self._config.base_score)

        # Contagem de matches por engine via timeline
        rule_events = [e for e in finding.timeline if e.kind == "rule.matched"]
        regex_matches = sum(1 for e in rule_events if e.payload.get("engine") == "regex")
        yara_matches = sum(1 for e in rule_events if e.payload.get("engine") == "yara")
        sigma_matches = sum(1 for e in rule_events if e.payload.get("engine") == "sigma")
        ioc_matches = sum(1 for e in rule_events if e.payload.get("engine") == "ioc")

        # Watchlist tags
        tag_names = {t.lower() for t in finding.tags}
        vip_hit = "watch:vip" in tag_names or "watch:executive" in tag_names
        actor_hit = "watch:threat_actor" in tag_names
        brand_hit = "watch:brand" in tag_names
        domain_hit = "watch:domain" in tag_names

        # Indicator types
        type_counts: dict[IndicatorType, int] = {}
        for ind in finding.indicators:
            type_counts[ind.type] = type_counts.get(ind.type, 0) + 1
        cred_count = type_counts.get(IndicatorType.CREDENTIAL, 0)
        card_count = type_counts.get(IndicatorType.CARD_PAN, 0)
        email_count = type_counts.get(IndicatorType.EMAIL, 0)
        cpf_count = type_counts.get(IndicatorType.CPF, 0)
        cnpj_count = type_counts.get(IndicatorType.CNPJ, 0)
        doc_count = cpf_count + cnpj_count

        total = base
        total += weights.get("regex_match", 0.0) * min(regex_matches, 5)
        total += weights.get("yara_match", 0.0) * min(yara_matches, 5)
        total += weights.get("sigma_match", 0.0) * min(sigma_matches, 5)
        total += weights.get("ioc_match", 0.0) * min(ioc_matches, 5)
        if vip_hit:
            total += weights.get("vip_match", 0.0)
        if actor_hit:
            total += weights.get("threat_actor", 0.0)
        if brand_hit:
            total += weights.get("brand", 0.0)
        if domain_hit:
            total += weights.get("domain_watch", 0.0)
        if cred_count:
            total += weights.get("credential", 0.0)
        if card_count:
            total += weights.get("card", 0.0)
        if email_count:
            total += weights.get("email", 0.0)
        if cpf_count:
            total += weights.get("cpf", 0.0)
        if cnpj_count:
            total += weights.get("cnpj", 0.0)
        if doc_count:
            total += weights.get("document", 0.0)

        # Indicator count bonus (capped)
        step = weights.get("indicator_count_step", 0.0)
        total += min(step * max(0, len(finding.indicators) - 1), 15.0)

        # Severity multiplier
        mult = self._config.severity_multiplier.get(finding.severity.name, 1.0)
        total *= mult

        # Source bonus
        source_key = self._infer_source_bucket(finding)
        total += self._config.source_bonus.get(source_key, 0.0)

        cap_max = self._config.cap.get("max", 100.0)
        cap_min = self._config.cap.get("min", 0.0)
        total = max(cap_min, min(cap_max, total))
        return Score(total)

    @staticmethod
    def _infer_source_bucket(finding: Finding) -> str:
        connector = (finding.connector or "").lower()
        source = (finding.source.source or "").lower()
        haystack = f"{connector} {source}"
        if "darkweb" in haystack or "onion" in haystack:
            return "darkweb"
        if "paste" in haystack:
            return "paste_site"
        if "telegram" in haystack:
            return "telegram"
        if "github" in haystack:
            return "github"
        if "forum" in haystack:
            return "forum"
        if "rss" in haystack or "krebs" in haystack or "bleeping" in haystack:
            return "rss"
        if "news" in haystack:
            return "news"
        return "api"
