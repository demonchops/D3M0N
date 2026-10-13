"""Cross-session access-control comparison — IDOR/BAC leads, not verdicts.

Takes ONE resource URL (one you already saw while recon'ing as your
primary session, D3M0N_SESSION_HEADERS) and requests that EXACT same URL
three ways: as your primary session ("A"), as a second configured test
account (D3M0N_SESSION_HEADERS_B, "B"), and with no session at all
(anonymous). Returns all three responses side by side — status, length,
a redacted snippet, and how similar B's body is to A's — for the agent
(and you) to reason about whether B, a different account, is seeing A's
own data. This tool never decides "this is IDOR"; like everything else
in this registry, it gathers evidence and leaves the verdict and any
actual exploitation to a human.

Bounded the same way recon.py's http_probe is, and for the same reason: a
query string lets the caller embed an arbitrary value, so without a
restriction this would be a second GET-based request-tampering primitive
(an adversarial review already found and closed exactly that hole in
http_probe once — see its docstring/tests). `_validate_identifier_shaped`
refuses anything in the path/query that isn't a plain resource-reference
character ONCE FULLY PERCENT-DECODED — checking the decoded form, not the
raw string, specifically so a payload can't hide from the character check
by percent-encoding itself (the same category of mistake as the
DOCTYPE/ENTITY guard being bypassable via UTF-16 before that got fixed:
check the effective content, not one particular encoding of it).

Needs D3M0N_SESSION_HEADERS (session A) configured — without a real
session on at least one side there's nothing to compare. Missing
D3M0N_SESSION_HEADERS_B degrades to a two-way (A vs anonymous) comparison
with a note instead of refusing outright, since "does this even require
auth" is itself a useful data point.
"""

from __future__ import annotations

import difflib
import re
from urllib.parse import unquote, urlparse

import requests

from d3m0n.config import SETTINGS

_SAFE_DECODED_RE = re.compile(r"^[A-Za-z0-9/_.\-~:=&?,]*$")
_SNIPPET_LEN = 300


def _fully_unquote(s: str, max_rounds: int = 5) -> str:
    """Repeatedly percent-decode (bounded) so a double/triple-encoded
    payload can't dodge the character check below by wrapping itself in
    an extra layer of %XX escapes."""
    for _ in range(max_rounds):
        decoded = unquote(s)
        if decoded == s:
            return decoded
        s = decoded
    return s


def _validate_identifier_shaped(url: str) -> str | None:
    """None if `url`'s path+query, once fully percent-decoded, contains
    only plain resource-reference characters; an error string otherwise."""
    parsed = urlparse(url)
    if parsed.fragment:
        return "idor_check refuses a target with a fragment."
    remainder = parsed.path + (("?" + parsed.query) if parsed.query else "")
    decoded = _fully_unquote(remainder)
    if not _SAFE_DECODED_RE.match(decoded):
        return (
            "idor_check refuses this target: its path/query, once decoded, contains "
            "something other than plain resource-reference characters (letters, digits, "
            "/ _ . - ~ : = & ? ,). This tool substitutes sessions for an already-known "
            "resource reference, not arbitrary payload delivery — use burp_scan/"
            "nuclei_scan/burp_traffic_review for anything that needs a crafted parameter "
            "value."
        )
    return None


def _redact_sessions(text: str) -> str:
    """Strip any configured session-header value (either account) from
    `text` — same defense-in-depth pattern as fuzz.py's/vuln.py's/
    burp_scanner.py's redaction helpers."""
    secret_values = [
        v for v in {**SETTINGS.session_headers, **SETTINGS.session_headers_b}.values() if v
    ]
    for value in secret_values:
        text = text.replace(value, "***REDACTED-SESSION-HEADER***")
    return text


def _fetch(url: str, headers: dict[str, str] | None) -> dict:
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, headers=headers or None)
    except requests.RequestException as exc:
        return {"error": _redact_sessions(str(exc))}
    body = resp.text
    return {
        "status": resp.status_code,
        "length": len(body),
        "snippet": _redact_sessions(body[:_SNIPPET_LEN]),
    }


def idor_check(url: str) -> dict:
    """Request `url` as session A, session B, and anonymous; return all three."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    validation_error = _validate_identifier_shaped(url)
    if validation_error:
        return {"url": url, "error": validation_error}

    session_a = SETTINGS.session_headers
    if not session_a:
        return {
            "url": url,
            "error": "D3M0N_SESSION_HEADERS (session A) is not configured — idor_check "
            "needs at least one real session to compare against. See README.",
        }

    result: dict = {
        "url": url,
        "as_session_a": _fetch(url, session_a),
        "as_anonymous": _fetch(url, None),
    }

    session_b = SETTINGS.session_headers_b
    if not session_b:
        result["as_session_b"] = {
            "error": "D3M0N_SESSION_HEADERS_B not configured — only A-vs-anonymous "
            "compared. Set a second test account's session to compare A vs B."
        }
        return result

    result["as_session_b"] = _fetch(url, session_b)

    as_a, as_b = result["as_session_a"], result["as_session_b"]
    if "error" not in as_a and "error" not in as_b:
        result["a_vs_b_body_similarity"] = round(
            difflib.SequenceMatcher(None, as_a["snippet"], as_b["snippet"]).quick_ratio(), 3
        )

    return result
