"""D3M0N_SESSION_HEADERS: parsing, and that it reaches the real tool calls
while being redacted out of anything a tool RETURNS."""

import requests

import d3m0n.tools.fuzz as fuzz_mod
import d3m0n.tools.recon as recon_mod
import d3m0n.tools.vuln as vuln_mod
from d3m0n.config import Settings, _parse_session_headers


def test_parse_session_headers_basic():
    headers = _parse_session_headers("Cookie: sessionid=abc123\nX-CSRF-Token: xyz")
    assert headers == {"Cookie": "sessionid=abc123", "X-CSRF-Token": "xyz"}


def test_parse_session_headers_ignores_blank_and_malformed_lines():
    headers = _parse_session_headers("Cookie: a=b\n\n   \nnot-a-header-line\nAuthorization: Bearer t")
    assert headers == {"Cookie": "a=b", "Authorization": "Bearer t"}


def test_parse_session_headers_none_or_empty():
    assert _parse_session_headers(None) == {}
    assert _parse_session_headers("") == {}


def test_http_probe_sends_configured_headers(monkeypatch):
    monkeypatch.setattr(
        recon_mod, "SETTINGS", Settings(session_headers={"Cookie": "sessionid=abc123"})
    )
    captured = {}

    class FakeResp:
        status_code = 200
        headers = {}
        text = "<title>hi</title>"
        url = "https://example.com"

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return FakeResp()

    monkeypatch.setattr(requests, "get", fake_get)
    recon_mod.http_probe("example.com")

    assert captured["headers"] == {"Cookie": "sessionid=abc123"}


def test_http_probe_passes_none_when_no_session_configured(monkeypatch):
    monkeypatch.setattr(recon_mod, "SETTINGS", Settings(session_headers={}))
    captured = {}

    class FakeResp:
        status_code = 200
        headers = {}
        text = ""
        url = "https://example.com"

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return FakeResp()

    monkeypatch.setattr(requests, "get", fake_get)
    recon_mod.http_probe("example.com")

    assert captured["headers"] is None


def test_nuclei_scan_includes_real_header_but_redacts_in_result(monkeypatch):
    monkeypatch.setattr(vuln_mod, "SETTINGS", Settings(session_headers={"Cookie": "sid=supersecret"}))
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/nuclei")

    captured_cmd = {}

    class FakeProc:
        stdout = ""
        stderr = ""
        returncode = 0

    def fake_run(cmd, **kwargs):
        captured_cmd["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)

    result = vuln_mod.nuclei_scan("example.com")

    # The REAL subprocess call must carry the real header value...
    assert "-H" in captured_cmd["cmd"]
    assert "Cookie: sid=supersecret" in captured_cmd["cmd"]
    # ...but it must never appear in what the tool returns.
    assert "supersecret" not in result["command"]
    assert "REDACTED" in result["command"]


def test_ffuf_scan_includes_real_header_but_redacts_in_result(monkeypatch):
    monkeypatch.setattr(fuzz_mod, "SETTINGS", Settings(session_headers={"Cookie": "sid=supersecret"}))
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/ffuf")

    captured_cmd = {}

    class FakeProc:
        stdout = "{}"
        stderr = ""
        returncode = 0

    def fake_run(cmd, **kwargs):
        captured_cmd["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)

    result = fuzz_mod.ffuf_scan("example.com")

    assert "-H" in captured_cmd["cmd"]
    assert "Cookie: sid=supersecret" in captured_cmd["cmd"]
    assert "supersecret" not in result["command"]
    assert "REDACTED" in result["command"]


def test_no_header_flags_added_when_nothing_configured(monkeypatch):
    monkeypatch.setattr(vuln_mod, "SETTINGS", Settings(session_headers={}))
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/nuclei")
    captured_cmd = {}

    class FakeProc:
        stdout = ""
        stderr = ""
        returncode = 0

    def fake_run(cmd, **kwargs):
        captured_cmd["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    vuln_mod.nuclei_scan("example.com")

    assert "-H" not in captured_cmd["cmd"]
