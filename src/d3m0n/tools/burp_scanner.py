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
severity, confidence, path, description, remediation, evidence}`). Field
names have shifted slightly across Burp versions in the past; if your Burp
returns a result this doesn't parse cleanly, the raw issue dict falls back
into `"raw"` on each entry rather than being silently dropped. The same
caveat applies, more so, to per-issue `context` extraction below — Burp's
evidence/request-response shape is less consistently documented than the
issue fields themselves, so every field there is tried under a couple of
plausible names and left `None` rather than guessed when none match.

Each kept issue is a stable, structured object, not a grab-bag of
whatever Burp happened to send:
  severity_score   severity normalized to an integer (critical=4, high=3,
                    medium=2, low=1, information=0; None if Burp reports
                    something this doesn't recognize) — alongside the
                    original `severity` string, never instead of it.
  context           best-effort request method/path, response status,
                    and a small sanitized response-body snippet, pulled
                    from the issue's first evidence entry.
  minified_content_warning  flags when description/remediation/the
                    response-body snippet looks minified (long line,
                    little whitespace) — same heuristic as
                    tools/js_secrets.py's minified check. A reflected-XSS
                    issue's evidence can literally BE page markup, and
                    minified markup reads as a wall of text; this is
                    informational, not a confidence signal.

Credential redaction (`_redact_all`) runs on every piece of Burp-sourced
text this module hands back — error messages, the scan-launch failure
detail, issue descriptions/remediation, and the extracted context/evidence
snippet — covering the Burp REST API key, the configured Burp login
username/password, AND (defense in depth, since an operator could easily
reuse the same session cookie value across tools) the configured
D3M0N_SESSION_HEADERS values. The login-request evidence for an
authenticated scan is the single likeliest place a real password could
surface verbatim (e.g. a CSRF-on-login-form issue whose evidence IS the
login POST), which is exactly the kind of case `context` extraction now
reaches into — so this redaction has to run on that path specifically,
not just on the top-level error strings it originally covered.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
import urllib.parse

import requests

from d3m0n.config import SETTINGS

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")
_DESCRIPTION_LIMIT = 600
_CONTEXT_SNIPPET_LIMIT = 300

_SEVERITY_SCORES = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "information": 0,
    "info": 0,
}


def _strip_html(value: str | None) -> str:
    """Plain text, whitespace-collapsed to one line, NOT yet truncated —
    callers truncate after redaction (see module docstring: redacting
    before truncating, not after, avoids leaving a credential's other
    half sitting unredacted on either side of a truncation cut)."""
    if not value:
        return ""
    text = _HTML_TAG_RE.sub(" ", value)
    return _WHITESPACE_RE.sub(" ", text).strip()


def _base_url() -> str | None:
    if not SETTINGS.burp_api_url:
        return None
    base = SETTINGS.burp_api_url.rstrip("/")
    if SETTINGS.burp_api_key:
        base = f"{base}/{SETTINGS.burp_api_key}"
    return base


def _redact(text: str) -> str:
    """Replace the configured Burp REST API key wherever it appears in
    `text`. The key is embedded directly in every request path this module
    builds (see _base_url), and requests/urllib3 exceptions stringify to
    include the attempted URL — so an unredacted exception message would
    leak it straight into the LLM conversation and the saved findings
    report. Mirrors fuzz.py's/vuln.py's _redacted_command for session
    headers."""
    key = SETTINGS.burp_api_key
    if not key:
        return text
    return text.replace(key, "***REDACTED-BURP-API-KEY***")


def _redact_all(text: str | None) -> str:
    """`_redact` plus the Burp login username/password and the configured
    session headers (see module docstring) — the full credential-hygiene
    pass, applied to every piece of Burp-sourced text this module returns,
    not just the error-message paths `_redact` alone originally covered."""
    if not text:
        return text or ""
    text = _redact(text)
    for value in (SETTINGS.burp_login_username, SETTINGS.burp_login_password):
        if value:
            text = text.replace(value, "***REDACTED-BURP-LOGIN-CREDENTIAL***")
    for value in SETTINGS.session_headers.values():
        if value:
            text = text.replace(value, "***REDACTED-SESSION-HEADER***")
    return text


def _normalize_severity(severity) -> int | None:
    if not isinstance(severity, str):
        return None
    return _SEVERITY_SCORES.get(severity.strip().lower())


def _looks_minified(raw_text: str | None) -> bool:
    """Same heuristic (and thresholds) as js_secrets.py's minified check:
    a long line with little whitespace. Deliberately run on RAW text,
    before any whitespace-collapsing — collapsed text would look
    "minified" by this measure regardless, making the check meaningless
    on already-cleaned text."""
    if not raw_text:
        return False
    lines = [line for line in raw_text.split("\n") if line.strip()]
    if not lines:
        return False
    max_len = max(len(line) for line in lines)
    whitespace_ratio = sum(1 for c in raw_text if c.isspace()) / len(raw_text)
    return (max_len > 1000 and whitespace_ratio < 0.10) or (
        len(lines) <= 2 and len(raw_text) > 2000
    )


def _decode_body(raw) -> str | None:
    """Burp's REST API has, in some versions, base64-encoded request/
    response bodies inside evidence; other versions/configurations may
    just return plain text. Try strict base64+UTF-8 decode; fall back to
    treating `raw` as already-plain-text on ANY failure, rather than
    assume one shape and risk silently mangling the other."""
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    if not isinstance(raw, str):
        return None
    if not raw:
        return ""
    try:
        return base64.b64decode(raw, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return raw


def _sanitize_snippet(text: str | None) -> str | None:
    if not text:
        return None
    printable = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in text)
    collapsed = _WHITESPACE_RE.sub(" ", printable).strip()
    if not collapsed:
        return None
    return _redact_all(collapsed)[:_CONTEXT_SNIPPET_LIMIT]


def _first_request_response(issue: dict) -> dict | None:
    evidence = issue.get("evidence")
    if not isinstance(evidence, list):
        return None
    for item in evidence:
        if isinstance(item, dict) and isinstance(item.get("request_response"), dict):
            return item["request_response"]
    return None


def _extract_context(issue: dict) -> tuple[dict, str | None]:
    """Best-effort request/response context from the issue's first
    evidence entry (see module docstring on schema uncertainty here).
    Returns (context_dict, raw_response_body_text) — the raw text comes
    back separately, not yet whitespace-collapsed, so _looks_minified can
    inspect it before `context["response_snippet"]` flattens it."""
    context = {
        "request_method": None,
        "request_path": None,
        "response_status": None,
        "response_snippet": None,
    }
    rr = _first_request_response(issue)
    if rr is None:
        return context, None

    request = rr.get("request") if isinstance(rr.get("request"), dict) else {}
    response = rr.get("response") if isinstance(rr.get("response"), dict) else {}

    method = request.get("method")
    if isinstance(method, str):
        context["request_method"] = method

    for key in ("path", "url", "to_url"):
        value = request.get(key)
        if value:
            context["request_path"] = _redact_all(str(value))
            break

    for key in ("status_code", "statusCode", "status"):
        value = response.get(key)
        if value is not None:
            context["response_status"] = value
            break

    raw_body = _decode_body(response.get("body"))
    context["response_snippet"] = _sanitize_snippet(raw_body)
    return context, raw_body


def _auth_method(using_login: bool, scan_config_name: str | None) -> str:
    if using_login and scan_config_name:
        return "application_login+named_scan_configuration"
    if using_login:
        return "application_login"
    if scan_config_name:
        return "named_scan_configuration"
    return "none"


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
            "error": _redact_all(
                f"Could not reach Burp's REST API at {SETTINGS.burp_api_url!r}: {exc}. "
                "Is Burp running with the REST API enabled and reachable from this process?"
            ),
        }

    if resp.status_code not in (200, 201):
        # Never echo resp.text when a login credential was in the request
        # body — Burp's own error response is outside our control and
        # could in principle reflect part of the submitted body back.
        # Even without login creds, redact before truncating (not after —
        # see _strip_html's docstring for why order matters here too).
        detail = (
            "(error body withheld — a login credential was in this request)"
            if using_login
            else _redact_all(resp.text)[:300]
        )
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
            return {
                "target": target,
                "error": _redact_all(f"Lost contact with Burp mid-scan: {exc}"),
            }
        if poll.status_code != 200:
            return {
                "target": target,
                "error": f"Burp API returned {poll.status_code} while polling scan status.",
            }
        try:
            data = poll.json()
        except ValueError as exc:
            # Covers both json.JSONDecodeError and requests.exceptions.
            # JSONDecodeError (a subclass of ValueError either way) --
            # a 200 OK with a non-JSON body (an HTML error/maintenance
            # page from Burp or a proxy in front of it) must not crash a
            # scan that can run for minutes; return a clear error instead.
            return {
                "target": target,
                "error": _redact_all(
                    f"Burp API returned a non-JSON body while polling scan status: {exc}. "
                    f"Body (truncated): {poll.text[:300]!r}"
                ),
            }
        if not isinstance(data, dict):
            return {
                "target": target,
                "error": _redact_all(
                    "Burp API returned a validly-parsed but non-object JSON body while "
                    f"polling scan status: {data!r}"
                )[:400],
            }
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

        description_raw = issue.get("description")
        remediation_raw = issue.get("remediation")
        context, raw_response_body = _extract_context(issue)

        minified_fields = [
            field_name
            for field_name, raw_text in (
                ("description", description_raw),
                ("remediation", remediation_raw),
                ("response_body", raw_response_body),
            )
            if _looks_minified(raw_text)
        ]

        entry = {
            "name": issue.get("name"),
            "severity": issue.get("severity"),
            "severity_score": _normalize_severity(issue.get("severity")),
            "confidence": issue.get("confidence"),
            "path": issue.get("path"),
            "description": _redact_all(_strip_html(description_raw))[:_DESCRIPTION_LIMIT],
            "remediation": _redact_all(_strip_html(remediation_raw))[:_DESCRIPTION_LIMIT],
            "context": context,
            "minified_content_warning": {
                "any": bool(minified_fields),
                "fields": minified_fields,
            },
        }
        if entry["name"] is None:
            # Unrecognized shape for this Burp version — keep the raw data
            # rather than silently dropping a real finding.
            entry["raw"] = issue
        issues.append(entry)

    scan_metrics = data.get("scan_metrics")

    return {
        "target": target,
        "scan_urls": scan_urls,
        "scan_config_used": scan_config_name,
        "auto_login_used": using_login,
        "status": status,
        "issue_count": len(issues),
        "issues": issues,
        "scan_metadata": {
            "target": target,
            "scan_urls": scan_urls,
            "paths_requested": scan_paths,
            "scan_config_name": scan_config_name,
            # A named scan configuration is this tool's own documented
            # mechanism for authenticated-session handling (see module
            # docstring) -- its presence is treated as "authenticated"
            # even though Burp doesn't tell us via this API what's
            # actually inside a given named configuration.
            "authenticated": using_login or bool(scan_config_name),
            "auth_method": _auth_method(using_login, scan_config_name),
            "timeout_s": timeout_s,
            "poll_interval_s": poll_interval_s,
            # Whatever Burp itself reports about the scan's own progress
            # (crawl/audit metrics, phases, etc., version-dependent) --
            # passed through verbatim rather than parsed into named
            # fields this code can't confirm exist on your Burp version.
            "burp_scan_metrics": scan_metrics if isinstance(scan_metrics, dict) else None,
        },
    }
