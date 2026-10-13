"""Runtime settings for the agent."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _parse_session_headers(raw: str | None) -> dict[str, str]:
    """Parse "Name: value" lines (one per header) into a dict.

    Blank lines and lines without a ':' are ignored rather than erroring —
    this is meant to tolerate a value pasted straight out of a browser/Burp
    without careful cleanup.
    """
    headers: dict[str, str] = {}
    if not raw:
        return headers
    for line in raw.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if name and value:
            headers[name] = value
    return headers


@dataclass(frozen=True)
class Settings:
    model: str = os.environ.get("D3M0N_MODEL", "claude-sonnet-5")
    max_steps: int = int(os.environ.get("D3M0N_MAX_STEPS", "25"))
    tool_timeout_s: int = int(os.environ.get("D3M0N_TOOL_TIMEOUT", "30"))
    output_dir: str = os.environ.get("D3M0N_OUTPUT_DIR", "./d3m0n_runs")
    max_result_chars: int = int(os.environ.get("D3M0N_MAX_RESULT_CHARS", "4000"))
    anthropic_api_key: str | None = os.environ.get("ANTHROPIC_API_KEY")
    # Burp Suite Professional/Enterprise's REST API (Settings > Suite > REST
    # API in Burp). Community Edition has no Scanner/REST API — see
    # tools/burp_traffic.py for a Community-compatible alternative.
    burp_api_url: str | None = os.environ.get("D3M0N_BURP_API_URL")
    burp_api_key: str | None = os.environ.get("D3M0N_BURP_API_KEY")
    # Burp's own form-based auto-login during a scan (its documented
    # "application_logins" REST API field) — a real credential, so it's
    # config-only like everything else here, never an LLM tool parameter.
    burp_login_username: str | None = os.environ.get("D3M0N_BURP_LOGIN_USERNAME")
    burp_login_password: str | None = os.environ.get("D3M0N_BURP_LOGIN_PASSWORD")
    # Authenticated scanning for the tools this project drives directly
    # (http_probe, nuclei_scan, ffuf_scan): one "Name: value" HTTP header
    # per line, e.g. "Cookie: sessionid=abc123" or a CSRF header on a
    # second line. This is a live credential for YOUR OWN test account —
    # configured once here, never seen or set by the LLM, and redacted out
    # of anything a tool returns (see tools/vuln.py's/fuzz.py's
    # _redacted_command). Treat it with the same care as an API key: don't
    # commit it, don't share a report/transcript generated while it's set
    # without checking what's in it first.
    session_headers: dict[str, str] = field(
        default_factory=lambda: _parse_session_headers(os.environ.get("D3M0N_SESSION_HEADERS"))
    )
    # A SECOND test account's session, used only by tools/idor_check.py to
    # compare whether a different identity can see the first session's
    # data (broken access control / IDOR). Same format, same credential-
    # hygiene rules as session_headers above — never an LLM parameter,
    # redacted out of anything returned.
    session_headers_b: dict[str, str] = field(
        default_factory=lambda: _parse_session_headers(os.environ.get("D3M0N_SESSION_HEADERS_B"))
    )


SETTINGS = Settings()
