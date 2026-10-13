"""js_secrets_scan: fixed-pattern matching only (never an arbitrary
response-content oracle), dedup, and redaction."""

import requests

import d3m0n.tools.js_secrets as js_mod
from d3m0n.config import Settings


class FakeResp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


def test_detects_aws_key(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp("const cfg = {key: 'AKIAABCDEFGHIJKLMNOP'};")
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    types = {f["type"] for f in result["findings"]}
    assert "aws_access_key_id" in types


def test_detects_jwt(monkeypatch):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(f"var token = '{jwt}';"))
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    types = {f["type"] for f in result["findings"]}
    assert "jwt" in types


def test_detects_embedded_admin_path(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp("fetch('/internal/debug-panel')")
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    types = {f["type"] for f in result["findings"]}
    assert "embedded_api_path" in types


def test_no_matches_on_clean_file(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp("function add(a, b) { return a + b; }")
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    assert result["finding_count"] == 0


def test_dedup_within_pattern(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp("AKIAABCDEFGHIJKLMNOP and again AKIAABCDEFGHIJKLMNOP"),
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    aws_matches = [f for f in result["findings"] if f["type"] == "aws_access_key_id"]
    assert len(aws_matches) == 1


def test_connection_failure_redacts_session_values(monkeypatch):
    monkeypatch.setattr(js_mod, "SETTINGS", Settings(session_headers={"Cookie": "s=SECRET999"}))

    def fake_get(*a, **k):
        raise requests.ConnectionError("failed near s=SECRET999")

    monkeypatch.setattr(requests, "get", fake_get)
    result = js_mod.js_secrets_scan("https://example.com/app.js")

    assert "SECRET999" not in result["error"]
    assert "REDACTED" in result["error"]
