"""Burp Scanner REST API wrapper, fully mocked — no live Burp instance
needed to verify the request/response handling logic itself."""

import requests

import d3m0n.tools.burp_scanner as burp_mod
from d3m0n.config import Settings


class FakeResponse:
    def __init__(self, status_code=200, headers=None, json_data=None, text="", url=""):
        self.status_code = status_code
        self.headers = headers or {}
        self._json_data = json_data or {}
        self.text = text
        self.url = url

    def json(self):
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

    result = burp_mod.burp_scan("example.com", path="/search")

    assert result["status"] == "succeeded"
    assert result["issue_count"] == 1
    issue = result["issues"][0]
    assert issue["name"] == "Reflected XSS"
    assert issue["severity"] == "High"
    # HTML tags stripped, whitespace collapsed.
    assert "<" not in issue["description"]
    assert "  " not in issue["description"]
    assert "reflected unescaped" in issue["description"]


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


def test_missing_location_header_returns_error(monkeypatch):
    monkeypatch.setattr(burp_mod, "SETTINGS", Settings(burp_api_url="http://127.0.0.1:1337"))
    post_resp = FakeResponse(status_code=201, headers={}, url="http://127.0.0.1:1337/v0.1/scan")
    monkeypatch.setattr(requests, "post", lambda *a, **k: post_resp)

    result = burp_mod.burp_scan("example.com")
    assert "error" in result
    assert "task location" in result["error"]
