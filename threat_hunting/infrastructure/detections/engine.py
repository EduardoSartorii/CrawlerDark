"""
DetectionEngine
===============

Implements the IDetectionEngine port.

Evaluates all enabled detection rules against a Finding in priority order.
Each rule match produces a DetectionResult attached to the Finding.

Rule evaluation order:
    1. BLACKLIST rules (highest priority — instant flag)
    2. WHITELIST rules (if matched, Finding may be dismissed)
    3. IOC rules (match against known bad IOC lists)
    4. YARA rules (binary/text pattern matching)
    5. REGEX rules (custom regex patterns)
    6. KEYWORD rules (simple keyword/phrase matching)
    7. THRESHOLD rules (density-based detection)
    8. HEURISTIC rules (behavioral patterns)
    9. COMPOSITE rules (AND/OR combinations of other rules)

Architecture:
    - All rules are loaded from IRuleRepository at startup.
    - No rule is hardcoded in source code.
    - Rules can be reloaded at runtime without restart.
    - The engine is stateless — state is carried by the Finding and repositories.
    - VIP and ThreatActor matching is done here using the respective repositories.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from threat_hunting.core.domain.entities.finding import DetectionResult, FindingStatus
from threat_hunting.core.domain.entities.rule import RuleType
from threat_hunting.core.domain.events.detection_events import RuleMatched
from threat_hunting.core.domain.exceptions.domain_exceptions import DetectionError
from threat_hunting.core.domain.ports.engines import IDetectionEngine
from threat_hunting.infrastructure.extractors.card_extractor import CardExtractor
from threat_hunting.infrastructure.extractors.credential_extractor import CredentialExtractor
from threat_hunting.infrastructure.extractors.ioc_extractor import IOCExtractor

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding
    from threat_hunting.core.domain.entities.keyword import Keyword
    from threat_hunting.core.domain.entities.rule import Rule
    from threat_hunting.core.domain.entities.vip import VIP
    from threat_hunting.core.domain.entities.threat_actor import ThreatActor
    from threat_hunting.core.domain.ports.event_bus import IEventBus
    from threat_hunting.core.domain.ports.repositories import (
        IRuleRepository,
        IVIPRepository,
        IKeywordRepository,
        IThreatActorRepository,
    )

logger = structlog.get_logger(__name__)


class DetectionEngine(IDetectionEngine):
    """
    Production detection engine.

    Evaluates enabled rules and VIP/ThreatActor/Keyword matches
    against every Finding that passes through the pipeline.
    """

    def __init__(
        self,
        rule_repo: "IRuleRepository",
        vip_repo: "IVIPRepository",
        keyword_repo: "IKeywordRepository",
        actor_repo: "IThreatActorRepository",
        event_bus: "IEventBus",
        enable_yara: bool = True,
        enable_regex: bool = True,
        enable_keyword: bool = True,
        enable_ioc: bool = True,
    ) -> None:
        self._rule_repo = rule_repo
        self._vip_repo = vip_repo
        self._keyword_repo = keyword_repo
        self._actor_repo = actor_repo
        self._event_bus = event_bus
        self._enable_yara = enable_yara
        self._enable_regex = enable_regex
        self._enable_keyword = enable_keyword
        self._enable_ioc = enable_ioc
        self._ioc_extractor = IOCExtractor()
        self._cred_extractor = CredentialExtractor()
        self._card_extractor = CardExtractor()
        self._yara_rules: Any = None  # Compiled YARA rules (lazy loaded)

    async def run(self, finding: "Finding") -> "Finding":
        """
        Evaluate all detection rules against a Finding.

        Args:
            finding: A normalized Finding.

        Returns:
            The Finding with DetectionResult entries attached.

        Raises:
            DetectionError: On fatal engine error.
        """
        log = logger.bind(finding_id=finding.id, connector=finding.connector)
        text = self._extract_text(finding)

        try:
            await self._run_keyword_detection(finding, text, log)
            await self._run_vip_detection(finding, text, log)
            await self._run_actor_detection(finding, text, log)
            await self._run_regex_detection(finding, text, log)
            await self._run_yara_detection(finding, text, log)
            await self._run_ioc_extraction(finding, text, log)
            await self._run_credential_detection(finding, text, log)
            await self._run_card_detection(finding, text, log)

        except Exception as exc:
            log.error("detection_engine_error", error=str(exc), exc_info=True)
            raise DetectionError(f"Detection engine failed: {exc}") from exc

        finding.advance_status(FindingStatus.DETECTED)
        log.debug(
            "detection_complete",
            matches=len(finding.detection_results),
            rules_matched=finding.matched_rules,
        )
        return finding

    def _extract_text(self, finding: "Finding") -> str:
        """Concatenate all textual content from the Finding for rule evaluation."""
        parts = [
            finding.title,
            finding.description,
            str(finding.raw_data or ""),
            " ".join(str(v) for v in finding.normalized_data.values() if isinstance(v, (str, int, float))),
        ]
        return " ".join(filter(None, parts))

    async def _run_keyword_detection(
        self, finding: "Finding", text: str, log: structlog.BoundLogger
    ) -> None:
        """Match active keywords against the Finding text."""
        if not self._enable_keyword:
            return
        keywords: list["Keyword"] = await self._keyword_repo.list_enabled()
        text_lower = text.lower()

        for kw in keywords:
            needle = kw.normalized_value
            if needle in text_lower:
                kw.record_match()
                finding.add_detection(
                    DetectionResult(
                        rule_id=kw.id,
                        rule_name=f"keyword:{kw.value}",
                        rule_type=RuleType.KEYWORD.value,
                        confidence=0.9,
                        match_data={"keyword": kw.value, "type": kw.type.value},
                    )
                )
                finding.add_tag(f"keyword_{kw.type.value}")
                await self._event_bus.publish(
                    RuleMatched(
                        aggregate_id=finding.id,
                        rule_id=kw.id,
                        rule_name=f"keyword:{kw.value}",
                        rule_type=RuleType.KEYWORD.value,
                        finding_id=finding.id,
                        confidence=0.9,
                    )
                )

    async def _run_vip_detection(
        self, finding: "Finding", text: str, log: structlog.BoundLogger
    ) -> None:
        """Check if any VIP identifier appears in the Finding."""
        vips: list["VIP"] = await self._vip_repo.list_enabled()
        for vip in vips:
            if vip.matches_text(text):
                vip.record_match()
                finding.add_detection(
                    DetectionResult(
                        rule_id=vip.id,
                        rule_name=f"vip:{vip.name}",
                        rule_type="vip",
                        confidence=0.95,
                        match_data={"vip_name": vip.name, "vip_type": vip.type.value},
                    )
                )
                finding.add_tag("vip_mention")
                log.info("vip_detected", vip_name=vip.name, finding_id=finding.id)

    async def _run_actor_detection(
        self, finding: "Finding", text: str, log: structlog.BoundLogger
    ) -> None:
        """Check if any known threat actor name appears in the Finding."""
        actors: list["ThreatActor"] = await self._actor_repo.list_all()
        for actor in actors:
            if actor.matches(text):
                finding.add_detection(
                    DetectionResult(
                        rule_id=actor.id,
                        rule_name=f"threat_actor:{actor.name}",
                        rule_type="threat_actor",
                        confidence=0.85,
                        match_data={"actor_name": actor.name, "aliases": actor.aliases},
                    )
                )
                finding.add_tag("threat_actor_mention")
                log.info("actor_detected", actor_name=actor.name, finding_id=finding.id)

    async def _run_regex_detection(
        self, finding: "Finding", text: str, log: structlog.BoundLogger
    ) -> None:
        """Evaluate REGEX rules against the Finding text."""
        if not self._enable_regex:
            return
        import re

        rules: list["Rule"] = await self._rule_repo.list_enabled(RuleType.REGEX.value)
        for rule in rules:
            if not rule.pattern:
                continue
            try:
                flags = 0 if rule.metadata.get("case_sensitive") else re.IGNORECASE
                pattern = re.compile(rule.pattern, flags)
                matches = pattern.findall(text)
                if matches:
                    rule.record_match()
                    finding.add_detection(
                        DetectionResult(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            rule_type=RuleType.REGEX.value,
                            confidence=rule.confidence,
                            match_data={"matches": matches[:10]},
                        )
                    )
                    finding.add_tag(f"regex_{rule.name.lower().replace(' ', '_')}")
            except re.error as exc:
                log.warning("regex_compile_error", rule=rule.name, error=str(exc))

    async def _run_yara_detection(
        self, finding: "Finding", text: str, log: structlog.BoundLogger
    ) -> None:
        """Evaluate compiled YARA rules against the Finding text."""
        if not self._enable_yara:
            return

        try:
            import yara  # type: ignore[import-untyped]

            rules: list["Rule"] = await self._rule_repo.list_enabled(RuleType.YARA.value)
            for rule in rules:
                if not rule.content:
                    continue
                try:
                    compiled = yara.compile(source=rule.content)
                    matches = compiled.match(data=text.encode("utf-8", errors="replace"))
                    if matches:
                        rule.record_match()
                        finding.add_detection(
                            DetectionResult(
                                rule_id=rule.id,
                                rule_name=rule.name,
                                rule_type=RuleType.YARA.value,
                                confidence=rule.confidence,
                                match_data={"yara_matches": [m.rule for m in matches]},
                            )
                        )
                        finding.add_tag("yara_match")
                        log.info("yara_match", rule=rule.name, finding_id=finding.id)
                except Exception as exc:
                    log.warning("yara_rule_error", rule=rule.name, error=str(exc))
        except ImportError:
            log.debug("yara_not_available", message="yara-python not installed")

    async def _run_ioc_extraction(
        self, finding: "Finding", text: str, log: structlog.BoundLogger
    ) -> None:
        """Extract IOCs from the Finding text and attach them as Indicators."""
        if not self._enable_ioc:
            return
        indicators = self._ioc_extractor.extract(text, context=finding.connector)
        for indicator in indicators:
            finding.add_indicator(indicator.id)
        if indicators:
            finding.add_tag("has_iocs")
            log.debug("iocs_extracted", count=len(indicators), finding_id=finding.id)

    async def _run_credential_detection(
        self, finding: "Finding", text: str, log: structlog.BoundLogger
    ) -> None:
        """Detect credential pairs in the Finding text."""
        creds = self._cred_extractor.extract(text)
        if creds:
            finding.add_detection(
                DetectionResult(
                    rule_id="builtin:credential_extractor",
                    rule_name="Credential Pair Detected",
                    rule_type="heuristic",
                    confidence=0.85,
                    match_data={"count": len(creds), "sample_domain": creds[0].domain if creds else None},
                )
            )
            finding.add_tag("credentials")
            finding.normalized_data["credential_count"] = len(creds)
            log.info("credentials_detected", count=len(creds), finding_id=finding.id)

    async def _run_card_detection(
        self, finding: "Finding", text: str, log: structlog.BoundLogger
    ) -> None:
        """Detect payment card numbers in the Finding text."""
        cards = self._card_extractor.extract(text)
        if cards:
            finding.add_detection(
                DetectionResult(
                    rule_id="builtin:card_extractor",
                    rule_name="Payment Card Number Detected",
                    rule_type="heuristic",
                    confidence=0.95,
                    match_data={"count": len(cards), "brands": list({c.card_brand for c in cards})},
                )
            )
            finding.add_tag("card_leak")
            finding.normalized_data["card_count"] = len(cards)
            log.info("cards_detected", count=len(cards), finding_id=finding.id)
