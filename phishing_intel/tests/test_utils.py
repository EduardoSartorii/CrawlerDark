"""Unit tests for the shared utility helpers."""

from __future__ import annotations

from phishing_intel.utils import (
    dedupe_preserve_order,
    extract_domain,
    extract_urls,
    filename_from_url,
    is_external_url,
    sha256_bytes,
    sha256_of_iterable,
    sha256_text,
)


def test_sha256_text_is_stable_and_hex() -> None:
    digest = sha256_text("hello")
    assert digest == sha256_text("hello")
    assert len(digest) == 64


def test_sha256_bytes_matches_text() -> None:
    assert sha256_bytes(b"hello") == sha256_text("hello")


def test_sha256_of_iterable_is_order_independent() -> None:
    # Ordering/duplicates must not change the resulting hash.
    assert sha256_of_iterable(["a", "b"]) == sha256_of_iterable(["b", "a", "a"])


def test_extract_domain_variants() -> None:
    assert extract_domain("https://Login.Example.com/path") == "login.example.com"
    assert extract_domain("login.example.com/x") == "login.example.com"
    assert extract_domain("") is None


def test_is_external_url() -> None:
    assert is_external_url("https://evil.com/a", "good.com") is True
    assert is_external_url("https://good.com/a", "good.com") is False
    assert is_external_url("/relative/path", "good.com") is False
    # No base domain -> any absolute URL is "external".
    assert is_external_url("https://x.com", None) is True


def test_filename_from_url() -> None:
    assert filename_from_url("https://x.com/js/app.min.js") == "app.min.js"
    assert filename_from_url("https://x.com/") is None


def test_extract_urls_dedupes_and_strips_trailing_punct() -> None:
    text = "go to https://a.com/x. and https://a.com/x. plus https://b.com/y)"
    urls = extract_urls(text)
    assert "https://a.com/x" in urls
    assert "https://b.com/y" in urls
    assert len(urls) == 2


def test_dedupe_preserve_order() -> None:
    assert dedupe_preserve_order(["a", "b", "a", "", "c"]) == ["a", "b", "c"]
