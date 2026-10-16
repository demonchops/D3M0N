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


# --- structured match objects + confidence + entropy ---


def test_finding_has_full_structured_shape(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp("const cfg = {key: 'AKIAABCDEFGHIJKLMNOP'};")
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    finding = next(f for f in result["findings"] if f["type"] == "aws_access_key_id")

    assert set(finding) == {"type", "match", "confidence", "entropy", "position", "context"}
    assert finding["confidence"] in ("high", "medium", "low")
    assert isinstance(finding["entropy"], float)
    assert isinstance(finding["position"], int)
    assert "AKIA" in finding["context"]


def test_aws_key_base_confidence_is_high_for_random_looking_value(monkeypatch):
    # A real-shaped, non-sequential, high-entropy suffix -- the kind an
    # actual generated AWS key would have.
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp("AKIAQZ8MXNRT4WPL7GKD"))
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    finding = next(f for f in result["findings"] if f["type"] == "aws_access_key_id")
    assert finding["confidence"] == "high"
    assert finding["entropy"] >= js_mod._LOW_ENTROPY_THRESHOLD


def test_private_key_header_and_path_have_no_entropy_score(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp("-----BEGIN RSA PRIVATE KEY-----\nfetch('/admin/panel')"),
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    header = next(f for f in result["findings"] if f["type"] == "private_key_header")
    path = next(f for f in result["findings"] if f["type"] == "embedded_api_path")

    assert header["entropy"] is None
    assert header["confidence"] == "high"
    assert path["entropy"] is None
    assert path["confidence"] == "low"


def test_generic_api_key_low_entropy_value_downgraded_from_medium(monkeypatch):
    # Passes the regex (16-64 alnum/-/_), isn't caught by the repeated-
    # character check (3 distinct chars) or the sequential-run check
    # (a->b->c->a is only 2/3 consecutive-pairs-step-by-1, below the 0.8
    # threshold), and has no placeholder keyword -- but is still clearly
    # low-entropy (a repeating 3-char pattern) and should surface at
    # lower confidence rather than get thrown away.
    low_entropy_value = "abcabcabcabcabcabc"  # 18 chars
    assert not js_mod._looks_like_placeholder(low_entropy_value)
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(f"api_key: '{low_entropy_value}'"),
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    finding = next(f for f in result["findings"] if f["type"] == "generic_api_key_assignment")

    assert finding["entropy"] < js_mod._LOW_ENTROPY_THRESHOLD
    assert finding["confidence"] == "low"  # medium base, downgraded one tier


def test_entropy_scored_on_captured_value_not_whole_assignment_text(monkeypatch):
    # The "secret" keyword itself must not pollute the entropy
    # calculation -- only group(2), the actual value.
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp("secret: 'Zx9Qp2Lm7Rk4Wv8T'")
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    finding = next(f for f in result["findings"] if f["type"] == "generic_api_key_assignment")
    assert finding["entropy"] == js_mod._shannon_entropy("Zx9Qp2Lm7Rk4Wv8T")


# --- placeholder filtering (keyword, repeated-char, sequential-run) ---


def test_keyword_placeholder_filtered_out_of_findings(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp("api_key: 'your-api-key-goes-here-1234'")
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")

    assert result["finding_count"] == 0
    assert result["filtered_placeholder_count"] == 1
    assert result["filtered_placeholder_examples"][0]["type"] == "generic_api_key_assignment"


def test_aws_canonical_example_key_filtered(monkeypatch):
    # AWS's own documentation's example access key -- the single most
    # common real-world AWS "secret" you'll find in public JS.
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp("AKIAIOSFODNN7EXAMPLE"))
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    assert result["finding_count"] == 0
    assert result["filtered_placeholder_count"] == 1


def test_repeated_character_value_filtered(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp("api_key: 'AAAAAAAAAAAAAAAAAAAA'")
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    assert result["finding_count"] == 0
    assert result["filtered_placeholder_count"] == 1


def test_sequential_run_value_filtered(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp("api_key: 'abcdefghijklmnopqrstuv'")
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    assert result["finding_count"] == 0
    assert result["filtered_placeholder_count"] == 1


def test_filtered_placeholders_never_silently_vanish(monkeypatch):
    # The whole point of "filtering" here is exclusion from `findings`,
    # not deletion -- it must stay auditable.
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp("api_key: 'your-api-key-goes-here-1234'")
    )
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    assert len(result["filtered_placeholder_examples"]) == 1
    assert "your-api-key" in result["filtered_placeholder_examples"][0]["match"]


def test_embedded_api_path_never_placeholder_filtered(monkeypatch):
    # A path isn't a "secret" -- placeholder heuristics don't apply to it
    # even if it happens to contain a word like "sample".
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp("fetch('/api/sample-data')"))
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    types = {f["type"] for f in result["findings"]}
    assert "embedded_api_path" in types
    assert result["filtered_placeholder_count"] == 0


# --- context snippets ---


def test_context_snippet_surrounds_match_and_collapses_whitespace(monkeypatch):
    body = "const  x = 1;\n\n  const cfg = {key: 'AKIAABCDEFGHIJKLMNOP'};\n\nmore(); "
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(body))
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    finding = next(f for f in result["findings"] if f["type"] == "aws_access_key_id")

    assert "AKIAABCDEFGHIJKLMNOP" in finding["context"]
    assert "\n" not in finding["context"]
    assert "  " not in finding["context"]  # collapsed to single spaces


def test_context_snippet_redacts_session_headers(monkeypatch):
    monkeypatch.setattr(
        js_mod, "SETTINGS", Settings(session_headers={"Cookie": "sid=MYSECRETSESSION"})
    )
    body = "// sid=MYSECRETSESSION seen near here -- AKIAABCDEFGHIJKLMNOP"
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(body))
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    finding = next(f for f in result["findings"] if f["type"] == "aws_access_key_id")

    assert "MYSECRETSESSION" not in finding["context"]


def test_position_points_at_match_start(monkeypatch):
    body = "xxxxxxxxxx" + "AKIAABCDEFGHIJKLMNOP"
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(body))
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    finding = next(f for f in result["findings"] if f["type"] == "aws_access_key_id")
    assert finding["position"] == 10


# --- minified-JS heuristic ---


def test_minified_heuristic_flags_one_long_dense_line(monkeypatch):
    minified_body = "function a(b,c){return b+c}var " + "x=1;" * 500  # one dense line
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(minified_body))
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    assert result["minified_heuristic"]["is_likely_minified"] is True


def test_minified_heuristic_does_not_flag_normal_formatted_code(monkeypatch):
    normal_body = "\n".join(
        [
            "function add(a, b) {",
            "    // adds two numbers",
            "    return a + b;",
            "}",
            "",
            "module.exports = { add };",
        ]
    )
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(normal_body))
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    assert result["minified_heuristic"]["is_likely_minified"] is False


def test_minified_heuristic_on_empty_body_does_not_crash(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp(""))
    result = js_mod.js_secrets_scan("https://example.com/app.js")
    assert result["minified_heuristic"]["is_likely_minified"] is False
    assert result["minified_heuristic"]["line_count"] == 0


# --- entropy helper itself ---


def test_shannon_entropy_zero_for_empty_string():
    assert js_mod._shannon_entropy("") == 0.0


def test_shannon_entropy_zero_for_single_repeated_character():
    assert js_mod._shannon_entropy("aaaaaaaaaa") == 0.0


def test_shannon_entropy_higher_for_diverse_string():
    assert js_mod._shannon_entropy("aB3xQ9zK7m") > js_mod._shannon_entropy("aaaaaaaaaa")
