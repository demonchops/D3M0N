"""Burp Suite Professional/Enterprise REST API integration — Scanner only.

This drives Burp's own Scanner (passive + active vulnerability detection)
against a target already inside the confirmed scope, and reports back
whatever issues Burp's engine finds. It never executes a PoC, never
confirms exploitability beyond what Burp itself asserts, and never sends
anything beyond what Burp's Scanner sends on its own as part of a normal
scan. Confirming or exploiting a finding by hand (e.g. in Repeater) is a
decision and an action for the human operator — the agent's job is to
explain each issue and write out exactly how to go do that manually, not
to do it for you. See agent/prompts.py for how findings get written up.

Requires Burp Suite PROFESSIONAL or ENTERPRISE with the REST API enabled
(Burp > Settings > Suite > REST API in current Burp; User options > Misc >
REST API in older versions) and reachable from wherever this process runs.
Community Edition has no Scanner and no REST API at all — for that, use
`tools/burp_traffic.py` instead, which reviews an exported proxy history
rather than driving a live scan.

Configure via:
    D3M0N_BURP_API_URL          e.g. http://127.0.0.1:1337
    D3M0N_BURP_API_KEY          optional — only if you set one in Burp's REST API settings
    D3M0N_BURP_LOGIN_USERNAME   optional — for Burp's own auto-login during the scan
    D3M0N_BURP_LOGIN_PASSWORD   optional — ditto; a real credential, so config-only,
                                 never an LLM tool parameter, and never echoed back in
                                 any result this module returns

Authenticated scanning: Burp's REST API scan launch supports two documented
mechanisms, both used here:
  - `application_logins` — Burp crawls and fills a login form itself using
    D3M0N_BURP_LOGIN_USERNAME/PASSWORD if both are set. Simple, but only
    works when Burp can actually find and drive the login form.
  - `scan_configurations` — references a Scanner configuration you saved
    by NAME in Burp's own UI ahead of time. This is how to get Burp to add
    a session cookie/header to every request it sends during the scan:
    set up a Project options > Sessions > Session Handling Rule (or a
    macro-based login) in Burp's UI, save it as a named scan configuration,
    and pass that name as `scan_config_name`. The name is just a label
    (not a secret), so it's fine as an LLM-facing tool parameter — the
    actual session value lives only inside Burp's own project, never here.

Note on the issue schema: this parses the commonly documented shape of
Burp's `GET /v0.1/scan/{id}` response (`issue_events[].issue.{name,
severity, confidence, path, description, remediation}`). Field names have
shifted slightly across Burp versions in the past; if your Burp returns a
result this doesn't parse cleanly, the raw issue dict falls back into
`"raw"` on each entry rather than being silently dropped.
"""

from __future__ import annotations

import re
import time
import urllib.parse

import requests

from d3m0n.config import SETTINGS

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _strip_html(value: str | None, limit: int = 600) -> str:
    if not value:
        return ""
    text = _HTML_TAG_RE.sub(" ", value)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return text[:limit]


def _base_url() -> str | None:
    if not SETTINGS.burp_api_url:
        return None
    base = SETTINGS.burp_api_url.rstrip("/")
    if SETTINGS.burp_api_key:
        base = f"{base}/{SETTINGS.burp_api_key}"
    return base


def burp_scan(
    target: str,
    paths: list[str] | None = None,
    scan_config_name: str | None = None,
    timeout_s: int = 300,
    poll_interval_s: int = 5,
) -> dict:
    """Launch ONE Burp Scanner task covering target+paths and return its issues.

    `paths` lets you batch everything worth scanning on this host — e.g.
    paths ffuf_scan already discovered — into a single Burp task instead of
    one call per path; defaults to just the root path. `scan_config_name`
    references a Scanner configuration you saved by name in Burp's UI
    (see module docstring) to add authenticated-session handling.

    Returns a clear `"error"` (never raises) if the REST API isn't
    configured, isn't reachable, or doesn't finish before `timeout_s` — in
    the timeout case, whatever issues were found so far are still returned,
    with `"status": "timed_out"`.
    """
    base = _base_url()
    if base is None:
        return {
            "target": target,
            "error": "Burp REST API not configured. Set D3M0N_BURP_API_URL (e.g. "
            "http://127.0.0.1:1337) and, if you set one in Burp, D3M0N_BURP_API_KEY. "
            "Requires Burp Suite PROFESSIONAL or ENTERPRISE with the REST API enabled "
            "(Settings > Suite > REST API) — Community Edition doesn't have this; use "
            "burp_traffic_review on an exported proxy history instead.",
        }

    url = (target if target.startswith(("http://", "https://")) else f"https://{target}").rstrip("/")
    scan_paths = paths or ["/"]
    scan_urls = [url + (p if p.startswith("/") else f"/{p}") for p in scan_paths]

    body: dict = {"urls": scan_urls}
    if scan_config_name:
        body["scan_configurations"] = [{"name": scan_config_name, "type": "NamedConfiguration"}]
    using_login = bool(SETTINGS.burp_login_username and SETTINGS.burp_login_password)
    if using_login:
        body["application_logins"] = [
            {"username": SETTINGS.burp_login_username, "password": SETTINGS.burp_login_password}
        ]

    try:
        resp = requests.post(f"{base}/v0.1/scan", json=body, timeout=15)
    except requests.RequestException as exc:
        return {
            "target": target,
            "error": f"Could not reach Burp's REST API at {SETTINGS.burp_api_url!r}: {exc}. "
            "Is Burp running with the REST API enabled and reachable from this process?",
        }

    if resp.status_code not in (200, 201):
        # Never echo resp.text when a login credential was in the request
        # body — Burp's own error response is outside our control and
        # could in principle reflect part of the submitted body back.
        detail = "(error body withheld — a login credential was in this request)" if using_login else resp.text[:300]
        return {
            "target": target,
            "error": f"Burp API returned {resp.status_code} starting the scan: {detail}",
        }

    location = resp.headers.get("Location")
    if not location:
        return {"target": target, "error": "Burp API didn't return a scan task location."}
    # Resolve relative-or-absolute Location against the actual request URL
    # rather than guessing Burp's path structure.
    task_url = urllib.parse.urljoin(resp.url, location)

    deadline = time.monotonic() + timeout_s
    status = "unknown"
    data: dict = {}
    while True:
        try:
            poll = requests.get(task_url, timeout=15)
        except requests.RequestException as exc:
            return {"target": target, "error": f"Lost contact with Burp mid-scan: {exc}"}
        if poll.status_code != 200:
            return {
                "target": target,
                "error": f"Burp API returned {poll.status_code} while polling scan status.",
            }
        data = poll.json()
        status = data.get("scan_status", "unknown")
        if status in ("succeeded", "failed", "paused"):
            break
        if time.monotonic() >= deadline:
            status = "timed_out"
            break
        time.sleep(poll_interval_s)

    issues = []
    for event in data.get("issue_events", []):
        issue = event.get("issue")
        if not isinstance(issue, dict):
            continue
        entry = {
            "name": issue.get("name"),
            "severity": issue.get("severity"),
            "confidence": issue.get("confidence"),
            "path": issue.get("path"),
            "description": _strip_html(issue.get("description")),
            "remediation": _strip_html(issue.get("remediation")),
        }
        if entry["name"] is None:
            # Unrecognized shape for this Burp version — keep the raw data
            # rather than silently dropping a real finding.
            entry["raw"] = issue
        issues.append(entry)

    return {
        "target": target,
        "scan_urls": scan_urls,
        "scan_config_used": scan_config_name,
        "auto_login_used": using_login,
        "status": status,
        "issue_count": len(issues),
        "issues": issues,
    }
