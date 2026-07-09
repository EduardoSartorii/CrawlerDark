"""Testes do comparador multi-perfil (analyzers.profile_comparator)."""

from __future__ import annotations

from analyzers.profile_comparator import build_profile_snapshot, compare_profiles


def test_snapshot_extracts_structural_hash_assets_and_scripts() -> None:
    html = """
    <html><body>
        <img src="/assets/logo.png">
        <script src="/assets/app.js"></script>
    </body></html>
    """
    snapshot = build_profile_snapshot("desktop_chrome", html)
    assert snapshot.profile_name == "desktop_chrome"
    assert snapshot.asset_urls == ["/assets/logo.png"]
    assert snapshot.script_hashes == ["app.js"]
    assert len(snapshot.structural_hash) == 64


def test_compare_profiles_detects_dom_and_asset_differences() -> None:
    desktop_html = """
    <html><body>
        <form method="POST"><input type="text" name="user"><input type="password" name="pass"></form>
        <img src="/assets/desktop-logo.png">
    </body></html>
    """
    mobile_html = """
    <html><body>
        <form method="POST"><input type="text" name="user"></form>
        <img src="/assets/mobile-logo.png">
    </body></html>
    """
    snapshots = {
        "desktop_chrome": build_profile_snapshot("desktop_chrome", desktop_html),
        "iphone_safari": build_profile_snapshot("iphone_safari", mobile_html),
    }

    diffs = compare_profiles(snapshots, baseline_profile="desktop_chrome")
    assert len(diffs) == 1
    diff = diffs[0]
    assert diff.baseline_profile == "desktop_chrome"
    assert diff.compared_profile == "iphone_safari"
    assert diff.dom_differs is True
    assert "/assets/desktop-logo.png" in diff.assets_diff
    assert "/assets/mobile-logo.png" in diff.assets_diff


def test_compare_profiles_identical_content_yields_no_dom_diff() -> None:
    html = "<html><body><p>Static content</p></body></html>"
    snapshots = {
        "desktop_chrome": build_profile_snapshot("desktop_chrome", html),
        "android_chrome": build_profile_snapshot("android_chrome", html),
    }
    diffs = compare_profiles(snapshots, baseline_profile="desktop_chrome")
    assert diffs[0].dom_differs is False
    assert diffs[0].assets_diff == []


def test_compare_profiles_returns_empty_when_baseline_missing() -> None:
    snapshots = {"android_chrome": build_profile_snapshot("android_chrome", "<html></html>")}
    diffs = compare_profiles(snapshots, baseline_profile="desktop_chrome")
    assert diffs == []
