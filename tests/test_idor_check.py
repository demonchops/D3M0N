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
        headers = {}

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
        headers = {}

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
            self.headers = {}

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
        headers = {}

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


def test_find_numeric_id_prefers_last_path_segment():
    found = idor_mod._find_numeric_id("https://example.com/api/users/12/orders/4471")
    assert found is not None
    original, substitute = found
    assert original == 4471
    assert substitute(4472) == "https://example.com/api/users/12/orders/4472"


def test_find_numeric_id_falls_back_to_id_shaped_query():
    found = idor_mod._find_numeric_id("https://example.com/account?user_id=5521&tab=billing")
    assert found is not None
    original, substitute = found
    assert original == 5521
    assert "user_id=5522" in substitute(5522)
    assert "tab=billing" in substitute(5522)


def test_find_numeric_id_ignores_valid_invalid_false_match():
    # "valid"/"invalid" end with "id" but must NOT be treated as an id key.
    found = idor_mod._find_numeric_id("https://example.com/check?valid=404&other=1")
    assert found is None


def test_find_numeric_id_none_for_uuid_only():
    found = idor_mod._find_numeric_id(
        "https://example.com/orders/550e8400-e29b-41d4-a716-446655440000"
    )
    assert found is None


def test_enumerate_range_probes_correct_offsets(monkeypatch):
    monkeypatch.setattr(idor_mod.time, "sleep", lambda *_: None)
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
            self.headers = {}

    def fake_get(url, headers=None, **kwargs):
        return FakeResp(f"content for {url}")

    monkeypatch.setattr(requests, "get", fake_get)
    result = idor_mod.idor_check("https://example.com/orders/100", enumerate_range=3)

    probes = result["enumeration"]["probes"]
    probed_ids = sorted(p["id"] for p in probes)
    # offsets -3..-1, 1..3 -> ids 97,98,99,101,102,103 -- the original (100)
    # itself must NOT be re-probed here, it's already the main comparison.
    assert probed_ids == [97, 98, 99, 101, 102, 103]
    assert 100 not in probed_ids


def test_enumerate_range_clamped_to_max(monkeypatch):
    monkeypatch.setattr(idor_mod.time, "sleep", lambda *_: None)
    monkeypatch.setattr(
        idor_mod,
        "SETTINGS",
        Settings(session_headers={"Cookie": "a=1"}, session_headers_b={"Cookie": "b=1"}),
    )

    class FakeResp:
        status_code = 200
        text = "ok"
        headers = {}

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = idor_mod.idor_check("https://example.com/orders/100", enumerate_range=999)

    assert result["enumeration"]["probed_range"] == idor_mod.MAX_ENUMERATE_RANGE
    assert len(result["enumeration"]["probes"]) == idor_mod.MAX_ENUMERATE_RANGE * 2


def test_enumerate_skips_negative_ids(monkeypatch):
    monkeypatch.setattr(idor_mod.time, "sleep", lambda *_: None)
    monkeypatch.setattr(
        idor_mod,
        "SETTINGS",
        Settings(session_headers={"Cookie": "a=1"}, session_headers_b={"Cookie": "b=1"}),
    )

    class FakeResp:
        status_code = 200
        text = "ok"
        headers = {}

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = idor_mod.idor_check("https://example.com/orders/2", enumerate_range=5)

    probed_ids = [p["id"] for p in result["enumeration"]["probes"]]
    assert all(pid >= 0 for pid in probed_ids)
    assert -1 not in probed_ids and -3 not in probed_ids


def test_enumerate_without_numeric_id_notes_why(monkeypatch):
    monkeypatch.setattr(
        idor_mod,
        "SETTINGS",
        Settings(session_headers={"Cookie": "a=1"}, session_headers_b={"Cookie": "b=1"}),
    )

    class FakeResp:
        status_code = 200
        text = "ok"
        headers = {}

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = idor_mod.idor_check(
        "https://example.com/orders/550e8400-e29b-41d4-a716-446655440000", enumerate_range=5
    )

    assert "note" in result["enumeration"]
    assert "probes" not in result["enumeration"]


def test_enumerate_range_zero_means_off(monkeypatch):
    monkeypatch.setattr(
        idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}, session_headers_b={})
    )

    class FakeResp:
        status_code = 200
        text = "ok"
        headers = {}

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = idor_mod.idor_check("https://example.com/orders/100")

    assert "enumeration" not in result


# --- method support (GET/HEAD/OPTIONS unconditionally, POST/PUT/PATCH/
# DELETE gated behind SETTINGS.allow_mutating_idor_checks) ---


def test_head_method_allowed_without_gate(monkeypatch):
    monkeypatch.setattr(
        idor_mod,
        "SETTINGS",
        Settings(session_headers={"Cookie": "a=1"}, session_headers_b={}, allow_mutating_idor_checks=False),
    )

    class FakeResp:
        status_code = 200
        text = ""
        headers = {}

    captured = {}

    def fake_request(method, url, **kwargs):
        captured["method"] = method
        return FakeResp()

    monkeypatch.setattr(requests, "request", fake_request)
    result = idor_mod.idor_check("https://example.com/api/orders/4471", method="head")

    assert "error" not in result["as_session_a"]
    assert captured["method"] == "HEAD"
    assert result["method"] == "HEAD"


def test_options_method_surfaces_allow_header(monkeypatch):
    monkeypatch.setattr(
        idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}, session_headers_b={})
    )

    class FakeResp:
        status_code = 200
        text = ""
        headers = {"Allow": "GET, HEAD, OPTIONS"}

    monkeypatch.setattr(requests, "request", lambda *a, **k: FakeResp())
    result = idor_mod.idor_check("https://example.com/api/orders/4471", method="OPTIONS")

    assert result["as_session_a"]["allow_header"] == "GET, HEAD, OPTIONS"


def test_post_refused_without_gate(monkeypatch):
    monkeypatch.setattr(
        idor_mod,
        "SETTINGS",
        Settings(session_headers={"Cookie": "a=1"}, session_headers_b={}, allow_mutating_idor_checks=False),
    )

    def fail(*a, **k):
        raise AssertionError("must not send a mutating request without the operator opt-in")

    monkeypatch.setattr(requests, "get", fail)
    monkeypatch.setattr(requests, "request", fail)

    result = idor_mod.idor_check("https://example.com/api/orders/4471", method="POST")

    assert "error" in result
    assert "D3M0N_ALLOW_MUTATING_IDOR_CHECKS" in result["error"]


def test_post_allowed_with_gate_sends_body(monkeypatch):
    monkeypatch.setattr(
        idor_mod,
        "SETTINGS",
        Settings(
            session_headers={"Cookie": "session=alice"},
            session_headers_b={"Cookie": "session=bob"},
            allow_mutating_idor_checks=True,
        ),
    )

    class FakeResp:
        status_code = 200
        text = "updated"
        headers = {}

    captured_calls = []

    def fake_request(method, url, **kwargs):
        captured_calls.append({"method": method, "url": url, **kwargs})
        return FakeResp()

    monkeypatch.setattr(requests, "request", fake_request)
    result = idor_mod.idor_check(
        "https://example.com/api/orders/4471",
        method="PATCH",
        body='{"status": "shipped"}',
        content_type="application/json",
    )

    assert "error" not in result["as_session_a"]
    assert all(c["method"] == "PATCH" for c in captured_calls)
    assert all(c["data"] == b'{"status": "shipped"}' for c in captured_calls)
    assert all(c["headers"]["Content-Type"] == "application/json" for c in captured_calls)


def test_unknown_method_rejected_without_request(monkeypatch):
    monkeypatch.setattr(idor_mod, "SETTINGS", Settings(session_headers={"Cookie": "a=1"}))

    def fail(*a, **k):
        raise AssertionError("must not send a request for an unsupported method")

    monkeypatch.setattr(requests, "get", fail)
    monkeypatch.setattr(requests, "request", fail)

    result = idor_mod.idor_check("https://example.com/api/orders/4471", method="TRACE")
    assert "error" in result


def test_body_too_large_rejected_without_request(monkeypatch):
    monkeypatch.setattr(
        idor_mod,
        "SETTINGS",
        Settings(session_headers={"Cookie": "a=1"}, allow_mutating_idor_checks=True),
    )

    def fail(*a, **k):
        raise AssertionError("must not send a request when the body exceeds the cap")

    monkeypatch.setattr(requests, "get", fail)
    monkeypatch.setattr(requests, "request", fail)

    result = idor_mod.idor_check(
        "https://example.com/api/orders/4471",
        method="POST",
        body="x" * (idor_mod.MAX_BODY_CHARS + 1),
    )
    assert "error" in result


def test_enumeration_always_uses_get_even_with_mutating_base_method(monkeypatch):
    monkeypatch.setattr(idor_mod.time, "sleep", lambda *_: None)
    monkeypatch.setattr(
        idor_mod,
        "SETTINGS",
        Settings(
            session_headers={"Cookie": "session=alice"},
            session_headers_b={"Cookie": "session=bob"},
            allow_mutating_idor_checks=True,
        ),
    )

    class FakeResp:
        def __init__(self, text="ok", status=200):
            self.text = text
            self.status_code = status
            self.headers = {}

    monkeypatch.setattr(requests, "request", lambda *a, **k: FakeResp())
    get_calls = []
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_calls.append(a) or FakeResp())

    result = idor_mod.idor_check(
        "https://example.com/orders/100", enumerate_range=2, method="POST", body="{}"
    )

    # The 3 base requests went via requests.request (POST); every
    # enumeration probe must have gone via requests.get (always GET),
    # never requests.request, regardless of the base call's method.
    assert len(get_calls) == 4  # offsets -2,-1,1,2
    assert len(result["enumeration"]["probes"]) == 4
