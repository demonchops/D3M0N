"""Burp Scanner REST API wrapper, fully mocked — no live Burp instance
needed to verify the request/response handling logic itself."""

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
