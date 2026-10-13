"""idor_check: the three-way session comparison, its character-allowlist
boundary (including the percent-encoding bypass that the equivalent check
in recon.py's http_probe doesn't need to worry about, since idor_check
explicitly supports query strings), and credential redaction."""

import requests

import d3m0n.tools.idor_check as idor_mod
from d3m0n.config import Settings


def test_plain_path_id_accepted(monkeypatch):
    monkeypatch.setattr(
        idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}, session_headers_b={})
    )

    class FakeResp:
        status_code = 200
        text = "order #4471"

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = idor_mod.idor_check("https://example.com/api/orders/4471")
    assert "error" not in result["as_session_a"]


def test_plain_query_id_accepted(monkeypatch):
    monkeypatch.setattr(
        idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}, session_headers_b={})
    )

    class FakeResp:
        status_code = 200
        text = "ok"

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = idor_mod.idor_check("https://example.com/account?user_id=550e8400-e29b-4")
    assert "error" not in result["as_session_a"]


def test_raw_payload_in_query_rejected_without_request(monkeypatch):
    monkeypatch.setattr(idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}))

    def fake_get(*a, **k):
        raise AssertionError("must not issue a real request for a payload-shaped target")

    monkeypatch.setattr(requests, "get", fake_get)

    result = idor_mod.idor_check(
        "https://example.com/search?q=<script>alert(document.domain)</script>"
    )
    assert "error" in result


def test_payload_in_path_rejected_too(monkeypatch):
    # The character check covers the whole path+query, not just query
    # values -- a payload stuffed into the PATH must be caught as well.
    monkeypatch.setattr(idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}))

    def fake_get(*a, **k):
        raise AssertionError("must not issue a real request for a payload-shaped path")

    monkeypatch.setattr(requests, "get", fake_get)

    result = idor_mod.idor_check("https://example.com/<script>alert(1)</script>")
    assert "error" in result


def test_single_percent_encoded_payload_rejected(monkeypatch):
    # %3Cscript%3E decodes to <script> -- the check must catch this by
    # looking at the DECODED text, not the raw (allowed-looking) characters.
    monkeypatch.setattr(idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}))

    def fake_get(*a, **k):
        raise AssertionError("must not issue a real request for an encoded payload")

    monkeypatch.setattr(requests, "get", fake_get)

    result = idor_mod.idor_check(
        "https://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    )
    assert "error" in result


def test_double_percent_encoded_payload_rejected(monkeypatch):
    # %253C decodes ONCE to %3C (still encoded), and only decodes to the
    # literal "<" on a SECOND pass -- a single-pass unquote would miss this.
    monkeypatch.setattr(idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}))

    def fake_get(*a, **k):
        raise AssertionError("must not issue a real request for a double-encoded payload")

    monkeypatch.setattr(requests, "get", fake_get)

    result = idor_mod.idor_check("https://example.com/search?q=%253Cscript%253E")
    assert "error" in result


def test_fragment_rejected(monkeypatch):
    monkeypatch.setattr(idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}))

    def fake_get(*a, **k):
        raise AssertionError("must not issue a real request for a target with a fragment")

    monkeypatch.setattr(requests, "get", fake_get)

    result = idor_mod.idor_check("https://example.com/page#frag")
    assert "error" in result


def test_no_session_a_configured_returns_error(monkeypatch):
    monkeypatch.setattr(idor_mod, "SETTINGS", Settings(session_headers={}, session_headers_b={}))
    result = idor_mod.idor_check("https://example.com/api/orders/4471")
    assert "error" in result


def test_three_way_comparison_with_similarity(monkeypatch):
    monkeypatch.setattr(
        idor_mod,
        "SETTINGS",
        Settings(
            session_headers={"Cookie": "session=alice"},
            session_headers_b={"Cookie": "session=bob"},
        ),
    )

    class FakeResp:
        def __init__(self, text, status=200):
            self.text = text
            self.status_code = status

    def fake_get(url, headers=None, **kwargs):
        if headers and headers.get("Cookie") == "session=alice":
            return FakeResp("alice's private order #4471, total $500")
        if headers and headers.get("Cookie") == "session=bob":
            # Bob sees the SAME data Alice does -- the IDOR case.
            return FakeResp("alice's private order #4471, total $500")
        return FakeResp("403 Forbidden", status=403)

    monkeypatch.setattr(requests, "get", fake_get)
    result = idor_mod.idor_check("https://example.com/api/orders/4471")

    assert result["as_session_a"]["status"] == 200
    assert result["as_session_b"]["status"] == 200
    assert result["as_anonymous"]["status"] == 403
    assert result["a_vs_b_body_similarity"] == 1.0


def test_missing_session_b_notes_two_way_only(monkeypatch):
    monkeypatch.setattr(
        idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}, session_headers_b={})
    )

    class FakeResp:
        status_code = 200
        text = "ok"

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = idor_mod.idor_check("https://example.com/api/orders/4471")

    assert "error" in result["as_session_b"]
    assert "a_vs_b_body_similarity" not in result


def test_connection_failure_redacts_session_values(monkeypatch):
    monkeypatch.setattr(
        idor_mod,
        "SETTINGS",
        Settings(session_headers={"Cookie": "session=SUPER-SECRET-TOKEN"}, session_headers_b={}),
    )

    def fake_get(*a, **k):
        raise requests.ConnectionError("failed talking to session=SUPER-SECRET-TOKEN somehow")

    monkeypatch.setattr(requests, "get", fake_get)
    result = idor_mod.idor_check("https://example.com/api/orders/4471")

    assert "SUPER-SECRET-TOKEN" not in repr(result)
    assert "REDACTED" in result["as_session_a"]["error"]
