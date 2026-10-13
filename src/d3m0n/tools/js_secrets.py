"""Regex-based secrets/hidden-endpoint scan over a JS (or any text) file.

Fetches one URL and checks its body against a fixed, hardcoded set of
secret/endpoint patterns (AWS/Google/Slack keys, JWTs, private key
headers, generic api_key-shaped assignments, embedded API paths) — these
are the TARGET's potential secrets, exposed in their own public-ish JS,
not anything of the operator's. A match is a lead worth manual
verification (it could be a placeholder/example/test value), not a
confirmed exposure.

The pattern set is fixed and never varies by caller input — only the
target URL does — so there's no way for a model-chosen URL to turn this
into a "show me whatever's in the response" oracle the way an
unrestricted raw-content-return tool would be (see recon.py's http_probe
docstring for that class of issue): none of these patterns match
arbitrary injected content, only specific real-secret shapes. Reuses the
configured session headers automatically, same as the other recon tools.
"""

from __future__ import annotations

import re

import requests

from d3m0n.config import SETTINGS

_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "private_key_header": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "generic_api_key_assignment": re.compile(
        r"""(?i)(api[_-]?key|secret|token|auth)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,64})[\"']"""
    ),
    "embedded_api_path": re.compile(
        r"""(?:\"|')(/(?:api|internal|admin)/[A-Za-z0-9_/\-]{2,80})(?:\"|')"""
    ),
}

_MAX_MATCHES_PER_PATTERN = 15
_MAX_BODY_CHARS = 3_000_000


def _redact_sessions(text: str) -> str:
    secret_values = [v for v in SETTINGS.session_headers.values() if v]
    for value in secret_values:
        text = text.replace(value, "***REDACTED-SESSION-HEADER***")
    return text


def js_secrets_scan(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True, headers=SETTINGS.session_headers or None
        )
    except requests.RequestException as exc:
        return {"url": url, "error": _redact_sessions(str(exc))}

    body = resp.text[:_MAX_BODY_CHARS]
    findings = []
    for kind, pattern in _PATTERNS.items():
        seen: set[str] = set()
        for match in pattern.finditer(body):
            value = match.group(0)
            if value in seen:
                continue
            seen.add(value)
            findings.append({"type": kind, "match": value[:200]})
            if len(seen) >= _MAX_MATCHES_PER_PATTERN:
                break

    return {
        "url": url,
        "status": resp.status_code,
        "length": len(resp.text),
        "finding_count": len(findings),
        "findings": findings,
    }
