"""Unit tests for the multi-profile render comparator."""

from __future__ import annotations

from phishing_intel.render_compare import RenderComparator

_DESKTOP = """<html><body><div><img src="/a/desktop.png"><script src="/js/desk.js"></script></div></body></html>"""
_MOBILE = """<html><body><div><img src="/a/mobile.png"><span></span></div></body></html>"""


def test_compare_detects_differences() -> None:
    diffs = RenderComparator().compare(
        {"desktop_chrome": _DESKTOP, "iphone_safari": _MOBILE},
        base_url="https://x.example",
    )
    assert len(diffs) == 1
    diff = diffs[0]
    assert diff.profile_a == "desktop_chrome"
    assert diff.profile_b == "iphone_safari"
    assert diff.dom_differs is True
    assert "desktop.png" in diff.assets_only_in_a
    assert "mobile.png" in diff.assets_only_in_b
    assert "desk.js" in diff.scripts_only_in_a


def test_identical_profiles_no_dom_diff() -> None:
    diffs = RenderComparator().compare(
        {"desktop_chrome": _DESKTOP, "desktop_edge": _DESKTOP}
    )
    assert diffs[0].dom_differs is False


def test_single_profile_returns_empty() -> None:
    assert RenderComparator().compare({"only": _DESKTOP}) == []
