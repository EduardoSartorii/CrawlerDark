"""Multi-profile render comparator.

Component responsibility
------------------------
Compare how a page renders across multiple browser/device profiles (desktop
Chrome/Edge/Firefox, Android Chrome, iPhone Safari) to expose cloaking - phishing
kits frequently serve different content to mobile victims. Produces
:class:`~phishing_intel.models.findings.RenderDiff` objects.

Design
------
The comparison itself is a *pure* function over a mapping of
``profile-name -> HTML``: it derives per-profile DOM/asset/script hashes via the
:class:`~phishing_intel.analyzers.dom_analyzer.DOMAnalyzer` and diffs every
profile against a chosen baseline. Fetching the per-profile HTML (network) is the
caller's responsibility, keeping this module testable offline.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer
from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import RenderDiff, RenderProfileResult
from phishing_intel.utils import filename_from_url

logger = get_logger(__name__)


class RenderComparator:
    """Compare DOM/asset/script structure across render profiles."""

    def __init__(self, dom_analyzer: Optional[DOMAnalyzer] = None) -> None:
        self.dom_analyzer = dom_analyzer or DOMAnalyzer()

    def _profile_result(self, profile: str, html: str, base_url: Optional[str]) -> RenderProfileResult:
        """Compute the DOM/asset/script hashes for one profile's HTML."""

        dom = self.dom_analyzer.analyze(html, base_url)
        from phishing_intel.utils import sha256_of_iterable

        asset_names = [n for ref in dom.assets if (n := filename_from_url(ref))]
        script_names = [n for ref in dom.scripts_external if (n := filename_from_url(ref))]
        return RenderProfileResult(
            profile=profile,
            dom_hash=dom.structural_hash,
            asset_hash=sha256_of_iterable(asset_names),
            script_hash=sha256_of_iterable(script_names),
        )

    def compare(
        self,
        profile_htmls: Dict[str, str],
        base_url: Optional[str] = None,
        baseline: Optional[str] = None,
    ) -> List[RenderDiff]:
        """Diff every profile against a baseline profile.

        Parameters
        ----------
        profile_htmls:
            Mapping of profile-name -> fetched HTML.
        base_url:
            The page URL (for internal/external asset resolution).
        baseline:
            Profile to compare the others against. Defaults to the first
            desktop profile present, else the first profile.

        Returns
        -------
        List[RenderDiff]
            One diff per non-baseline profile.
        """

        if len(profile_htmls) < 2:
            # Nothing to compare against.
            return []

        # Pre-compute per-profile structural results and asset/script sets.
        results: Dict[str, RenderProfileResult] = {}
        asset_sets: Dict[str, set[str]] = {}
        script_sets: Dict[str, set[str]] = {}
        for profile, html in profile_htmls.items():
            dom = self.dom_analyzer.analyze(html, base_url)
            asset_sets[profile] = {n for ref in dom.assets if (n := filename_from_url(ref))}
            script_sets[profile] = {
                n for ref in dom.scripts_external if (n := filename_from_url(ref))
            }
            results[profile] = self._profile_result(profile, html, base_url)

        # Choose a baseline: prefer a desktop profile.
        if baseline is None or baseline not in profile_htmls:
            baseline = next(
                (p for p in profile_htmls if p.startswith("desktop")),
                next(iter(profile_htmls)),
            )

        diffs: List[RenderDiff] = []
        base = results[baseline]
        for profile, res in results.items():
            if profile == baseline:
                continue
            diff = RenderDiff(
                profile_a=baseline,
                profile_b=profile,
                dom_differs=(base.dom_hash != res.dom_hash),
                assets_only_in_a=sorted(asset_sets[baseline] - asset_sets[profile]),
                assets_only_in_b=sorted(asset_sets[profile] - asset_sets[baseline]),
                scripts_only_in_a=sorted(script_sets[baseline] - script_sets[profile]),
                scripts_only_in_b=sorted(script_sets[profile] - script_sets[baseline]),
            )
            diffs.append(diff)

        logger.info(
            "render.compared",
            baseline=baseline,
            profiles=list(profile_htmls.keys()),
            differing=[d.profile_b for d in diffs if d.dom_differs],
        )
        return diffs
