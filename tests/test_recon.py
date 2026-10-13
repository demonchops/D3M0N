"""http_probe()'s own tool-level boundary: scope enforcement only ever
validates a target's hostname, never its path/query, so http_probe has to
refuse a query string/fragment itself rather than issue it as a live
request -- otherwise it's a GET-based request-tampering primitive for any
caller that can hand it a URL (reflected XSS/SSTI/open-redirect/IDOR-by-
parameter-change), authenticated session included if one is configured."""

import requests

import d3m0n.tools.recon as recon_mod
from d3m0n.config import Settings


def test_query_string_target_rejected_without_making_request(monkeypatch):
    called = {"hit": False}

    def fake_get(*a, **k):
        called["hit"] = True
        raise AssertionError("must not issue a real request for a query-string target")

    monkeypatch.setattr(requests, "get", fake_get)

    result = recon_mod.http_probe(
        "https://example.com/search?q=<script>alert(document.domain)</script>"
    )

    assert not called["hit"]
    assert "error" in result


def test_fragment_target_rejected_without_making_request(monkeypatch):
    called = {"hit": False}

    def fake_get(*a, **k):
        called["hit"] = True
        raise AssertionError("must not issue a real request for a fragment target")

    monkeypatch.setattr(requests, "get", fake_get)

    result = recon_mod.http_probe("https://example.com/page#frag")

    assert not called["hit"]
    assert "error" in result


def test_bare_url_without_query_still_probed(monkeypatch):
    monkeypatch.setattr(recon_mod, "SETTINGS", Settings(session_headers={}))

    class FakeResp:
        status_code = 200
        headers = {"Server": "nginx"}
        text = "<title>hi</title>"
        url = "https://example.com/dashboard"

    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        return FakeResp()

    monkeypatch.setattr(requests, "get", fake_get)

    result = recon_mod.http_probe("https://example.com/dashboard")

    assert captured["url"] == "https://example.com/dashboard"
    assert result["status"] == 200
    assert "error" not in result
