"""Burp Scanner REST API wrapper, fully mocked — no live Burp instance
needed to verify the request/response handling logic itself."""

import base64

import requests

import d3m0n.tools.burp_scanner as burp_mod
from d3m0n.config import Settings


class FakeResponse:
    def __init__(
        self, status_code=200, headers=None, json_data=None, text="", url="", json_error=None
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self._json_data = json_data or {}
        self.text = text
        self.url = url
        self._json_error = json_error

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._json_data


def test_not_configured_returns_clear_error(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url=None))
    result = burp_mod.burp_scan("example.com")
    assert "error" in result
    assert "not configured" in result["error"]


def test_connection_failure_returns_clear_error(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))

    def fake_post(*a, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "post", fake_post)
    result = burp_mod.burp_scan("example.com")
    assert "error" in result
    assert "Could not reach Burp" in result["error"]


def test_successful_scan_parses_and_strips_issues(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))

    post_resp = FakeResponse(
        status_code=201,
        headers={"Location": "/v0.1/scan/42"},
        url="http://127.0.0.1:1337/v0.1/scan",
    )
    get_resp = FakeResponse(
        status_code=200,
        json_data={
            "scan_status": "succeeded",
            "issue_events": [
                {
                    "issue": {
                        "name": "Reflected XSS",
                        "severity": "High",
                        "confidence": "Firm",
                        "path": "/search",
                        "description": "<p>The value of <b>q</b> is reflected   unescaped.</p>",
                        "remediation": "<p>Encode output.</p>",
                    }
                }
            ],
        },
    )

    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com", paths=["/search"])

    assert result["status"] == "succeeded"
    assert result["issue_count"] == 1
    issue = result["issues"][0]
    assert issue["name"] == "Reflected XSS"
    assert issue["severity"] == "High"
    # HTML tags stripped, whitespace collapsed.
    assert "<" not in issue["description"]
    assert "  " not in issue["description"]
    assert "reflected unescaped" in issue["description"]


def test_multiple_paths_batched_into_one_task(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))

    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/7"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(status_code=200, json_data={"scan_status": "succeeded", "issue_events": []})

    captured = {}

    def fake_post(url, json=None, **kwargs):
        captured["body"] = json
        return post_resp

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com", paths=["/search", "/admin", "api/v1/users"])

    # One task, one urls list with all three paths on the one host.
    assert captured["body"]["urls"] == [
        "https://example.com/search",
        "https://example.com/admin",
        "https://example.com/api/v1/users",
    ]
    assert result["scan_urls"] == captured["body"]["urls"]


def test_scan_config_name_forwarded(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(status_code=200, json_data={"scan_status": "succeeded", "issue_events": []})
    captured = {}

    def fake_post(url, json=None, **kwargs):
        captured["body"] = json
        return post_resp

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com", scan_config_name="authenticated-scan")

    assert captured["body"]["scan_configurations"] == [
        {"name": "authenticated-scan", "type": "NamedConfiguration"}
    ]
    assert result["scan_config_used"] == "authenticated-scan"


def test_configured_login_sent_but_never_echoed_back(monkeypatch):
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(
            burp_api_url="http://127.0.0.1:1337",
            burp_login_username="testuser@example.com",
            burp_login_password="super-secret-pw",
        ),
    )
    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(status_code=200, json_data={"scan_status": "succeeded", "issue_events": []})
    captured = {}

    def fake_post(url, json=None, **kwargs):
        captured["body"] = json
        return post_resp

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com")

    # The credential DOES go to Burp itself...
    assert captured["body"]["application_logins"] == [
        {"username": "testuser@example.com", "password": "super-secret-pw"}
    ]
    # ...but never comes back out in the result (which flows into the LLM
    # conversation and the saved JSON report).
    assert result["auto_login_used"] is True
    result_text = repr(result)
    assert "super-secret-pw" not in result_text
    assert "testuser@example.com" not in result_text


def test_login_error_body_withheld(monkeypatch):
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(
            burp_api_url="http://127.0.0.1:1337",
            burp_login_username="testuser",
            burp_login_password="super-secret-pw",
        ),
    )
    post_resp = FakeResponse(
        status_code=400, text="bad request for user=testuser pw=super-secret-pw", url="x"
    )
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)

    result = burp_mod.burp_scan("example.com")
    assert "super-secret-pw" not in result["error"]


def test_timeout_reports_timed_out_status(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))

    post_resp = FakeResponse(
        status_code=201,
        headers={"Location": "/v0.1/scan/1"},
        url="http://127.0.0.1:1337/v0.1/scan",
    )
    get_resp = FakeResponse(status_code=200, json_data={"scan_status": "running", "issue_events": []})

    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com", timeout_s=0, poll_interval_s=0)
    assert result["status"] == "timed_out"
    assert result["issue_count"] == 0


def test_connection_failure_redacts_api_key_from_error(monkeypatch):
    # D3M0N_BURP_API_KEY is embedded directly in every request path this
    # module builds (_base_url), and requests/urllib3 exceptions stringify
    # to include the attempted URL -- so an unredacted error leaks the key
    # straight into the LLM conversation and the saved findings report.
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(burp_api_url="http://127.0.0.1:1337", burp_api_key="TOTALLY-SECRET-BURP-API-KEY-999"),
    )

    def fake_post(*a, **k):
        raise requests.ConnectionError(
            "HTTPConnectionPool(host='127.0.0.1', port=1337): Max retries exceeded with url: "
            "/TOTALLY-SECRET-BURP-API-KEY-999/v0.1/scan"
        )

    monkeypatch.setattr(requests, "post", fake_post)
    result = burp_mod.burp_scan("example.com")
    assert "error" in result
    assert "TOTALLY-SECRET-BURP-API-KEY-999" not in result["error"]
    assert "REDACTED" in result["error"]


def test_poll_connection_failure_redacts_api_key_from_error(monkeypatch):
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(burp_api_url="http://127.0.0.1:1337", burp_api_key="POLL-PHASE-SECRET-KEY-777"),
    )
    post_resp = FakeResponse(
        status_code=201,
        headers={"Location": "42"},  # relative -- resolves to .../POLL-PHASE-SECRET-KEY-777/v0.1/42
        url="http://127.0.0.1:1337/POLL-PHASE-SECRET-KEY-777/v0.1/scan",
    )
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)

    def fake_get(*a, **k):
        raise requests.ConnectionError(
            "HTTPConnectionPool(host='127.0.0.1', port=1337): Max retries exceeded with url: "
            "/POLL-PHASE-SECRET-KEY-777/v0.1/42"
        )

    monkeypatch.setattr(requests, "get", fake_get)
    result = burp_mod.burp_scan("example.com")
    assert "error" in result
    assert "POLL-PHASE-SECRET-KEY-777" not in result["error"]
    assert "REDACTED" in result["error"]


def test_poll_non_json_body_returns_error_not_raise(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))

    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(
        status_code=200,
        text="<html>502 Bad Gateway</html>",
        json_error=ValueError("Expecting value: line 1 column 1 (char 0)"),
    )

    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com")
    assert "error" in result
    assert "non-JSON" in result["error"]


def test_poll_json_body_not_an_object_returns_error(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))

    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(status_code=200, json_data=["unexpected", "array"])

    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com")
    assert "error" in result


def test_missing_location_header_returns_error(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    post_resp = FakeResponse(status_code=201, headers={}, url="http://127.0.0.1:1337/v0.1/scan")
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)

    result = burp_mod.burp_scan("example.com")
    assert "error" in result
    assert "task location" in result["error"]


# --- severity normalization ---


def _scan_with_one_issue(monkeypatch, issue: dict):
    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(
        status_code=200,
        json_data={"scan_status": "succeeded", "issue_events": [{"issue": issue}]},
    )
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)
    return burp_mod.burp_scan("example.com")


def test_severity_score_mapping(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    for label, expected in [
        ("Critical", 4),
        ("High", 3),
        ("Medium", 2),
        ("Low", 1),
        ("Information", 0),
    ]:
        result = _scan_with_one_issue(monkeypatch, {"name": "x", "severity": label})
        assert result["issues"][0]["severity"] == label
        assert result["issues"][0]["severity_score"] == expected


def test_unrecognized_severity_scores_none_not_guessed(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    result = _scan_with_one_issue(monkeypatch, {"name": "x", "severity": "Apocalyptic"})
    assert result["issues"][0]["severity_score"] is None


# --- context extraction ---


def test_context_extracted_from_evidence(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    issue = {
        "name": "SQL injection",
        "severity": "High",
        "evidence": [
            {
                "request_response": {
                    "request": {"method": "POST", "path": "/login"},
                    "response": {"status_code": 500, "body": "Internal error: syntax near 'OR 1=1'"},
                }
            }
        ],
    }
    result = _scan_with_one_issue(monkeypatch, issue)
    context = result["issues"][0]["context"]
    assert context["request_method"] == "POST"
    assert context["request_path"] == "/login"
    assert context["response_status"] == 500
    assert "syntax near" in context["response_snippet"]


def test_context_tries_alternate_field_names(monkeypatch):
    # "url" instead of "path", "status" instead of "status_code" --
    # exercising the fallback-key logic rather than one fixed shape.
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    issue = {
        "name": "x",
        "evidence": [
            {
                "request_response": {
                    "request": {"method": "GET", "url": "https://example.com/account?id=5"},
                    "response": {"status": 200, "body": "ok"},
                }
            }
        ],
    }
    result = _scan_with_one_issue(monkeypatch, issue)
    context = result["issues"][0]["context"]
    assert context["request_path"] == "https://example.com/account?id=5"
    assert context["response_status"] == 200


def test_context_decodes_base64_response_body(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    encoded = base64.b64encode(b"<html>leaked stack trace</html>").decode("ascii")
    issue = {
        "name": "x",
        "evidence": [{"request_response": {"request": {}, "response": {"body": encoded}}}],
    }
    result = _scan_with_one_issue(monkeypatch, issue)
    assert "leaked stack trace" in result["issues"][0]["context"]["response_snippet"]


def test_context_missing_evidence_leaves_fields_none_not_crash(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    result = _scan_with_one_issue(monkeypatch, {"name": "x", "severity": "Low"})
    context = result["issues"][0]["context"]
    assert context == {
        "request_method": None,
        "request_path": None,
        "response_status": None,
        "response_snippet": None,
    }


def test_context_malformed_evidence_shapes_do_not_crash(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    for bad_evidence in (
        "not a list",
        [{"request_response": "not a dict"}],
        [{"request_response": {"request": "not a dict", "response": None}}],
        [{"no_request_response_key": True}],
        [123, None, "junk"],
    ):
        result = _scan_with_one_issue(monkeypatch, {"name": "x", "evidence": bad_evidence})
        assert result["issues"][0]["context"]["request_method"] is None


# --- credential redaction: login password reachable via evidence/context ---


def test_login_password_redacted_from_context_response_snippet(monkeypatch):
    # The single likeliest real leak path: a login-form issue whose
    # evidence IS the login POST, body-and-all.
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(
            burp_api_url="http://127.0.0.1:1337",
            burp_login_username="alice@example.com",
            burp_login_password="Tr0ub4dor&3",
        ),
    )
    issue = {
        "name": "Login form missing CSRF token",
        "evidence": [
            {
                "request_response": {
                    "request": {"method": "POST", "path": "/login"},
                    "response": {
                        "body": "echo of request: user=alice@example.com&pass=Tr0ub4dor&3"
                    },
                }
            }
        ],
    }
    result = _scan_with_one_issue(monkeypatch, issue)
    snippet = result["issues"][0]["context"]["response_snippet"]
    assert "Tr0ub4dor&3" not in snippet
    assert "alice@example.com" not in snippet
    assert "REDACTED" in snippet


def test_login_password_redacted_from_description_and_remediation(monkeypatch):
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(
            burp_api_url="http://127.0.0.1:1337",
            burp_login_username="alice@example.com",
            burp_login_password="Tr0ub4dor&3",
        ),
    )
    issue = {
        "name": "x",
        "description": "<p>Request used password Tr0ub4dor&3 in plaintext.</p>",
        "remediation": "<p>Contact alice@example.com to rotate Tr0ub4dor&3.</p>",
    }
    result = _scan_with_one_issue(monkeypatch, issue)
    found = result["issues"][0]
    assert "Tr0ub4dor&3" not in found["description"]
    assert "Tr0ub4dor&3" not in found["remediation"]
    assert "alice@example.com" not in found["remediation"]


def test_session_header_values_redacted_from_context(monkeypatch):
    # Defense in depth -- an operator could reuse the same session cookie
    # value across tools even though burp_scan doesn't send it itself.
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(
            burp_api_url="http://127.0.0.1:1337",
            session_headers={"Cookie": "sid=REUSED-SESSION-TOKEN"},
        ),
    )
    issue = {
        "name": "x",
        "evidence": [
            {
                "request_response": {
                    "request": {},
                    "response": {"body": "seen: sid=REUSED-SESSION-TOKEN"},
                }
            }
        ],
    }
    result = _scan_with_one_issue(monkeypatch, issue)
    assert "REUSED-SESSION-TOKEN" not in result["issues"][0]["context"]["response_snippet"]


def test_launch_error_without_login_still_redacts_api_key(monkeypatch):
    # Previously this path echoed resp.text completely unredacted when no
    # login credential was configured.
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(burp_api_url="http://127.0.0.1:1337", burp_api_key="LAUNCH-ERROR-KEY-123"),
    )
    post_resp = FakeResponse(
        status_code=400,
        text="bad request near /LAUNCH-ERROR-KEY-123/v0.1/scan",
        url="http://127.0.0.1:1337/LAUNCH-ERROR-KEY-123/v0.1/scan",
    )
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)

    result = burp_mod.burp_scan("example.com")
    assert "LAUNCH-ERROR-KEY-123" not in result["error"]
    assert "REDACTED" in result["error"]


def test_non_json_poll_body_redacts_api_key(monkeypatch):
    # Previously poll.text was embedded in this error message unredacted.
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(burp_api_url="http://127.0.0.1:1337", burp_api_key="POLL-BODY-KEY-456"),
    )
    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(
        status_code=200,
        text="error near /POLL-BODY-KEY-456/ in response",
        json_error=ValueError("Expecting value"),
    )
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com")
    assert "POLL-BODY-KEY-456" not in result["error"]
    assert "REDACTED" in result["error"]


# --- minified content warning ---


def test_minified_description_flagged(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    minified_description = "<script>" + "a=1;b=2;c=3;" * 200 + "</script>"  # one dense line
    result = _scan_with_one_issue(monkeypatch, {"name": "x", "description": minified_description})
    warning = result["issues"][0]["minified_content_warning"]
    assert warning["any"] is True
    assert "description" in warning["fields"]


def test_normal_description_not_flagged_minified(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    result = _scan_with_one_issue(
        monkeypatch, {"name": "x", "description": "<p>The value of q is reflected unescaped.</p>"}
    )
    warning = result["issues"][0]["minified_content_warning"]
    assert warning["any"] is False
    assert warning["fields"] == []


def test_minified_response_body_flagged(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    dense_body = "function a(b,c){return b+c}" + "x=1;" * 500
    issue = {
        "name": "x",
        "evidence": [{"request_response": {"request": {}, "response": {"body": dense_body}}}],
    }
    result = _scan_with_one_issue(monkeypatch, issue)
    warning = result["issues"][0]["minified_content_warning"]
    assert warning["any"] is True
    assert "response_body" in warning["fields"]


# --- scan metadata block ---


def test_scan_metadata_unauthenticated(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(status_code=200, json_data={"scan_status": "succeeded", "issue_events": []})
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com", paths=["/a", "/b"])
    meta = result["scan_metadata"]
    assert meta["authenticated"] is False
    assert meta["auth_method"] == "none"
    assert meta["paths_requested"] == ["/a", "/b"]
    assert meta["scan_config_name"] is None


def test_scan_metadata_named_configuration_counts_as_authenticated(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(status_code=200, json_data={"scan_status": "succeeded", "issue_events": []})
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com", scan_config_name="my-auth-config")
    meta = result["scan_metadata"]
    assert meta["authenticated"] is True
    assert meta["auth_method"] == "named_scan_configuration"


def test_scan_metadata_application_login_auth_method(monkeypatch):
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(
            burp_api_url="http://127.0.0.1:1337",
            burp_login_username="u",
            burp_login_password="p",
        ),
    )
    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(status_code=200, json_data={"scan_status": "succeeded", "issue_events": []})
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com")
    meta = result["scan_metadata"]
    assert meta["authenticated"] is True
    assert meta["auth_method"] == "application_login"


def test_scan_metadata_passes_through_burp_scan_metrics_when_present(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(
        status_code=200,
        json_data={
            "scan_status": "succeeded",
            "issue_events": [],
            "scan_metrics": {"crawl_and_audit_progress": 100, "requests_made": 842},
        },
    )
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com")
    assert result["scan_metadata"]["burp_scan_metrics"] == {
        "crawl_and_audit_progress": 100,
        "requests_made": 842,
    }


def test_scan_metadata_burp_scan_metrics_none_when_absent(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    post_resp = FakeResponse(
        status_code=201, headers={"Location": "/v0.1/scan/1"}, url="http://127.0.0.1:1337/v0.1/scan"
    )
    get_resp = FakeResponse(status_code=200, json_data={"scan_status": "succeeded", "issue_events": []})
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)
    monkeypatch.setattr(requests, "get", lambda *a, **k: get_resp)

    result = burp_mod.burp_scan("example.com")
    assert result["scan_metadata"]["burp_scan_metrics"] is None


# --- truncation happens after redaction, not before ---


def test_long_description_redacted_before_truncation(monkeypatch):
    # If truncation happened first, a credential split across the cut
    # could leave its surviving half unredacted.
    monkeypatch.setattr(
        burp_mod,
        "SETTINGS",
        Settings(burp_api_url="http://127.0.0.1:1337", burp_login_password="TAIL-SECRET-VALUE"),
    )
    padding = "x" * (burp_mod._DESCRIPTION_LIMIT - 5)
    description = f"<p>{padding} TAIL-SECRET-VALUE more text after the old 600-char cut</p>"
    result = _scan_with_one_issue(monkeypatch, {"name": "x", "description": description})
    assert "TAIL-SECRET-VALUE" not in result["issues"][0]["description"]
