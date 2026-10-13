"""cors_check: flag classification per probe, and credential redaction."""

import requests

import d3m0n.tools.cors_check as cors_mod
from d3m0n.config import Settings


class FakeResp:
    def __init__(self, status=200, acao=None, acac=None):
        self.status_code = status
        self.headers = {}
        if acao is not None:
            self.headers["Access-Control-Allow-Origin"] = acao
        if acac is not None:
            self.headers["Access-Control-Allow-Credentials"] = acac


def test_flags_reflected_arbitrary_origin_with_credentials(monkeypatch):
    monkeypatch.setattr(cors_mod, "SETTINGS", Settings(session_headers={}))

    def fake_get(url, headers=None, **kwargs):
        origin = headers.get("Origin")
        # Server naively reflects whatever Origin is sent, with credentials.
        return FakeResp(acao=origin, acac="true")

    monkeypatch.setattr(requests, "get", fake_get)
    result = cors_mod.cors_check("https://example.com")

    assert "reflects_arbitrary_origin_with_credentials" in result["flags"]


def test_flags_reflected_arbitrary_origin_without_credentials(monkeypatch):
    monkeypatch.setattr(cors_mod, "SETTINGS", Settings(session_headers={}))

    def fake_get(url, headers=None, **kwargs):
        origin = headers.get("Origin")
        return FakeResp(acao=origin)  # reflects, but no credentials flag

    monkeypatch.setattr(requests, "get", fake_get)
    result = cors_mod.cors_check("https://example.com")

    assert "reflects_arbitrary_origin" in result["flags"]
    assert "reflects_arbitrary_origin_with_credentials" not in result["flags"]


def test_flags_null_origin_allowed(monkeypatch):
    monkeypatch.setattr(cors_mod, "SETTINGS", Settings(session_headers={}))

    def fake_get(url, headers=None, **kwargs):
        if headers.get("Origin") == "null":
            return FakeResp(acao="null")
        return FakeResp(acao=None)

    monkeypatch.setattr(requests, "get", fake_get)
    result = cors_mod.cors_check("https://example.com")

    assert "allows_null_origin" in result["flags"]


def test_flags_subdomain_pattern_weakness(monkeypatch):
    monkeypatch.setattr(cors_mod, "SETTINGS", Settings(session_headers={}))

    def fake_get(url, headers=None, **kwargs):
        origin = headers.get("Origin")
        if origin.startswith("https://evil-") or origin.endswith(".evil.invalid"):
            return FakeResp(acao=origin)
        return FakeResp(acao=None)

    monkeypatch.setattr(requests, "get", fake_get)
    result = cors_mod.cors_check("https://example.com")

    assert "subdomain_prefix_pattern_weakness" in result["flags"]
    assert "subdomain_suffix_pattern_weakness" in result["flags"]


def test_no_flags_on_strict_cors(monkeypatch):
    monkeypatch.setattr(cors_mod, "SETTINGS", Settings(session_headers={}))

    def fake_get(url, headers=None, **kwargs):
        origin = headers.get("Origin")
        # Only the legitimate same-origin probe is ever allowed.
        if origin == "https://example.com":
            return FakeResp(acao=origin)
        return FakeResp(acao=None)

    monkeypatch.setattr(requests, "get", fake_get)
    result = cors_mod.cors_check("https://example.com")

    assert result["flags"] == []


def test_connection_failure_redacts_session_values(monkeypatch):
    monkeypatch.setattr(cors_mod, "SETTINGS", Settings(session_headers={"Cookie": "s=SECRETABC"}))

    def fake_get(*a, **k):
        raise requests.ConnectionError("failed near s=SECRETABC")

    monkeypatch.setattr(requests, "get", fake_get)
    result = cors_mod.cors_check("https://example.com")

    assert "SECRETABC" not in repr(result)
    assert all("error" in p for p in result["probes"])
    assert "REDACTED" in result["probes"][0]["error"]


def test_session_headers_included_in_probes(monkeypatch):
    monkeypatch.setattr(cors_mod, "SETTINGS", Settings(session_headers={"Cookie": "sid=abc"}))
    captured = {}

    def fake_get(url, headers=None, **kwargs):
        captured["headers"] = headers
        return FakeResp()

    monkeypatch.setattr(requests, "get", fake_get)
    cors_mod.cors_check("https://example.com")

    assert captured["headers"]["Cookie"] == "sid=abc"
    assert "Origin" in captured["headers"]
