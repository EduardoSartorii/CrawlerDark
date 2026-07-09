"""Testes do coletor de HTML (collectors.html_collector)."""

from __future__ import annotations

import pytest
import requests
import responses

from collectors.html_collector import HtmlCollectionError, fetch_html, fetch_html_multi_profile
from config.settings import CollectorSettings, RenderProfile


@pytest.fixture()
def collector_settings() -> CollectorSettings:
    return CollectorSettings(
        http_timeout_seconds=5,
        max_redirects=3,
        retry_attempts=1,
        user_agent_default="phishing-intel-test/1.0",
        render_profiles=[
            RenderProfile(name="desktop_chrome", user_agent="UA-Desktop"),
            RenderProfile(name="iphone_safari", user_agent="UA-Iphone"),
        ],
    )


@responses.activate
def test_fetch_html_returns_collected_html(collector_settings: CollectorSettings) -> None:
    responses.add(responses.GET, "https://phish.example/login", body="<html>ok</html>", status=200)

    result = fetch_html("https://phish.example/login", collector_settings)

    assert result.status_code == 200
    assert result.html == "<html>ok</html>"
    assert result.profile_name == "default"


@responses.activate
def test_fetch_html_uses_custom_user_agent(collector_settings: CollectorSettings) -> None:
    responses.add(responses.GET, "https://phish.example/login", body="<html>ok</html>", status=200)

    fetch_html("https://phish.example/login", collector_settings, user_agent="UA-Custom", profile_name="custom")

    assert responses.calls[0].request.headers["User-Agent"] == "UA-Custom"


@responses.activate
def test_fetch_html_raises_after_exhausting_retries(collector_settings: CollectorSettings) -> None:
    responses.add(
        responses.GET,
        "https://unreachable.example/login",
        body=requests.exceptions.ConnectionError("boom"),
    )

    with pytest.raises(HtmlCollectionError):
        fetch_html("https://unreachable.example/login", collector_settings)

    # 1 tentativa inicial + `retry_attempts` (1) = 2 chamadas HTTP no total.
    assert len(responses.calls) == 2


@responses.activate
def test_fetch_html_multi_profile_collects_all_profiles(collector_settings: CollectorSettings) -> None:
    responses.add(responses.GET, "https://phish.example/login", body="<html>desktop</html>", status=200)
    responses.add(responses.GET, "https://phish.example/login", body="<html>mobile</html>", status=200)

    results = fetch_html_multi_profile("https://phish.example/login", collector_settings)

    assert set(results.keys()) == {"desktop_chrome", "iphone_safari"}
