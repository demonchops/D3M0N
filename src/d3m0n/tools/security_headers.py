"""HTTP security-headers + clickjacking check — detection only, zero risk.

GETs one URL and inspects its response headers against a fixed set of
well-known security headers (scheme, HSTS, CSP, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy, Permissions-Policy) plus every Set-Cookie
header's Secure/HttpOnly/SameSite attributes, and separately assesses
whether the page can likely be framed (clickjacking) by checking BOTH
X-Frame-Options and CSP's `frame-ancestors` directive together, since
either one alone is enough to prevent framing in current browsers.

This never sends anything beyond a single plain GET — no crafted payloads,
no alternate Origins/methods, nothing model-composed — so there's no new
request-tampering surface here (see recon.py's http_probe docstring for
that class of issue): the fixed input is the header/attribute NAMES this
checks for, never anything derived from the response or supplied by the
caller. Reuses the configured session headers automatically, same as the
other recon tools, so this can be run against an authenticated page too.

Flags, not verdicts. A missing header is a real, commonly documented
weakness, and this tool says so plainly — but whether it actually matters
for THIS target depends on context the tool can't see (a pure JSON API
with no HTML doesn't need X-Frame-Options the way a page with a login
form does). Each finding carries a `severity` ("high"/"medium"/"low"/
"info") and a short `why` so a human can make that call quickly instead
of treating every missing header as equally urgent.
"""

from __future__ import annotations

import re

import requests

from d3m0n.config import SETTINGS

_HSTS_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_MIN_RECOMMENDED_HSTS_MAX_AGE = 15_552_000  # ~180 days, a commonly cited minimum
_CSP_WEAK_TOKENS = ("unsafe-inline", "unsafe-eval")
_VALID_XFO_VALUES = {"deny", "sameorigin"}
_WEAK_REFERRER_POLICIES = {"unsafe-url"}
_COOKIE_ATTR_EXPLANATIONS = {
    "Secure": "can be sent over plain HTTP, exposing it to network-level interception",
    "HttpOnly": "is readable by JavaScript, so XSS on this origin can steal it directly",
    "SameSite": "has no explicit SameSite (browsers default to Lax, which helps but isn't explicit)",
}


def _redact_sessions(text: str) -> str:
    secret_values = [v for v in SETTINGS.session_headers.values() if v]
    for value in secret_values:
        text = text.replace(value, "***REDACTED-SESSION-HEADER***")
    return text


def _parse_hsts_max_age(value: str) -> int | None:
    match = _HSTS_MAX_AGE_RE.search(value)
    return int(match.group(1)) if match else None


def _parse_csp_directives(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def _check_scheme(is_https: bool) -> dict | None:
    if is_https:
        return None
    return {
        "header": "(scheme)",
        "severity": "high",
        "finding": "plaintext_http",
        "why": "Fetched over plain HTTP, not HTTPS -- headers, cookies, and body content "
        "all travel unencrypted and are visible/tamperable to anyone on the network path.",
    }


def _check_hsts(headers: dict, is_https: bool) -> dict | None:
    if not is_https:
        return None  # already covered by _check_scheme; HSTS isn't meaningful over plain HTTP
    value = headers.get("Strict-Transport-Security")
    if not value:
        return {
            "header": "Strict-Transport-Security",
            "severity": "medium",
            "finding": "missing",
            "why": "No HSTS header -- browsers won't be forced to upgrade to HTTPS on "
            "future visits, leaving a window for a downgrade/SSL-stripping attack.",
        }
    max_age = _parse_hsts_max_age(value)
    if max_age is None:
        return {
            "header": "Strict-Transport-Security",
            "severity": "low",
            "finding": "malformed",
            "value": value[:200],
            "why": "Present but no max-age directive could be parsed out of it -- "
            "browsers may not apply HSTS at all from a malformed header.",
        }
    if max_age < _MIN_RECOMMENDED_HSTS_MAX_AGE:
        return {
            "header": "Strict-Transport-Security",
            "severity": "low",
            "finding": "weak",
            "value": value[:200],
            "why": f"max-age={max_age}s is short (commonly recommended: >= "
            f"{_MIN_RECOMMENDED_HSTS_MAX_AGE}s / ~180 days).",
        }
    return None


def _check_csp(directives: dict[str, list[str]], raw_value: str | None) -> list[dict]:
    if raw_value is None:
        return [
            {
                "header": "Content-Security-Policy",
                "severity": "medium",
                "finding": "missing",
                "why": "No CSP -- no defense-in-depth against XSS/injection beyond "
                "whatever output encoding the app does correctly on its own.",
            }
        ]

    findings = []
    lowered = raw_value.lower()
    weak_tokens = [t for t in _CSP_WEAK_TOKENS if t in lowered]
    if weak_tokens:
        findings.append(
            {
                "header": "Content-Security-Policy",
                "severity": "low",
                "finding": "weak_directive",
                "value": raw_value[:300],
                "why": f"Contains {', '.join(weak_tokens)} -- weakens CSP's XSS protection "
                "by allowing exactly the kind of inline/dynamic script execution CSP "
                "exists to block.",
            }
        )

    script_relevant = directives.get("script-src") or directives.get("default-src") or []
    if "*" in script_relevant:
        findings.append(
            {
                "header": "Content-Security-Policy",
                "severity": "medium",
                "finding": "wildcard_script_source",
                "value": raw_value[:300],
                "why": "script-src/default-src allows '*' -- any host can serve script "
                "into this page, which defeats most of CSP's point.",
            }
        )
    return findings


def _check_nosniff(headers: dict) -> dict | None:
    value = headers.get("X-Content-Type-Options")
    if value and value.strip().lower() == "nosniff":
        return None
    return {
        "header": "X-Content-Type-Options",
        "severity": "low",
        "finding": "missing" if not value else "invalid_value",
        **({"value": value} if value else {}),
        "why": "Without 'nosniff', browsers may MIME-sniff a response into executing it "
        "as something other than its declared Content-Type (e.g. treating an uploaded "
        "file as HTML/JS).",
    }


def _assess_clickjacking(
    headers: dict, csp_directives: dict[str, list[str]]
) -> tuple[dict | None, str | None]:
    """Returns (finding_or_None, protected_by). CSP's frame-ancestors
    directive supersedes X-Frame-Options in current browsers, so it's
    checked first; either one alone is sufficient protection."""
    if "frame-ancestors" in csp_directives:
        return None, "csp-frame-ancestors"

    xfo = headers.get("X-Frame-Options")
    if not xfo:
        return (
            {
                "header": "X-Frame-Options",
                "severity": "medium",
                "finding": "missing",
                "why": "No X-Frame-Options and no CSP frame-ancestors directive -- this "
                "page can likely be embedded in an iframe on another site, enabling "
                "clickjacking (tricking a user into clicking something they can't see, "
                "e.g. a disguised 'transfer funds'/'change email' button).",
            },
            None,
        )

    lowered = xfo.strip().lower()
    if lowered.startswith("allow-from"):
        return (
            {
                "header": "X-Frame-Options",
                "severity": "medium",
                "finding": "unsupported_value",
                "value": xfo,
                "why": "ALLOW-FROM is not honored by current Chrome/Firefox -- they ignore "
                "it entirely, so despite this header being present the page can likely "
                "still be framed in those browsers. Use CSP frame-ancestors instead.",
            },
            None,
        )
    if lowered not in _VALID_XFO_VALUES:
        return (
            {
                "header": "X-Frame-Options",
                "severity": "low",
                "finding": "invalid_value",
                "value": xfo,
                "why": f"Value {xfo!r} isn't DENY/SAMEORIGIN -- some browsers may not "
                "honor it as intended.",
            },
            None,
        )
    return None, "x-frame-options"


def _check_referrer_policy(headers: dict) -> dict | None:
    value = headers.get("Referrer-Policy")
    if not value:
        return {
            "header": "Referrer-Policy",
            "severity": "info",
            "finding": "missing",
            "why": "No explicit Referrer-Policy -- browser defaults are reasonable today, "
            "but full URLs (including any sensitive query params) may still leak to "
            "third parties via the Referer header on outbound links/resource loads.",
        }
    if value.strip().lower() in _WEAK_REFERRER_POLICIES:
        return {
            "header": "Referrer-Policy",
            "severity": "low",
            "finding": "weak",
            "value": value,
            "why": "'unsafe-url' sends the full URL (query string included) as the "
            "referrer on every request, including cross-origin and HTTPS->HTTP "
            "downgrade requests.",
        }
    return None


def _check_permissions_policy(headers: dict) -> dict | None:
    if headers.get("Permissions-Policy"):
        return None
    return {
        "header": "Permissions-Policy",
        "severity": "info",
        "finding": "missing",
        "why": "No Permissions-Policy -- browser features (camera/mic/geolocation/etc.) "
        "aren't explicitly restricted at the HTTP layer. Low impact on its own, but a "
        "cheap defense-in-depth layer to add.",
    }


def _all_set_cookie_headers(resp) -> list[str]:
    """A plain dict-style header lookup collapses multiple Set-Cookie
    headers into one (or silently keeps only one), since cookie values
    routinely contain commas (Expires=Wed, 21 Oct ...) that make naive
    comma-joining unsafe. Prefer the underlying urllib3 header dict's
    getlist(), which keeps each one separate; fall back to the single
    merged value if that path isn't available for any reason."""
    try:
        values = resp.raw.headers.getlist("Set-Cookie")
        if values:
            return list(values)
    except (AttributeError, TypeError):
        pass
    single = resp.headers.get("Set-Cookie")
    return [single] if single else []


def _check_cookie(cookie_header: str) -> dict | None:
    parts = [p.strip() for p in cookie_header.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    # Only parts[0] (NAME=value) names the cookie; every later ";"-
    # separated token is an attribute (Secure, HttpOnly, SameSite=Lax).
    # Checking attribute TOKENS here, rather than substring-searching the
    # raw header text, avoids a false "present" when the cookie's own
    # name/value happens to contain a flag word (e.g. a cookie literally
    # named "secure_session").
    attribute_names = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}

    missing = [
        attr for attr in ("Secure", "HttpOnly", "SameSite") if attr.lower() not in attribute_names
    ]
    if not missing:
        return None
    severity = "medium" if ("Secure" in missing or "HttpOnly" in missing) else "low"
    why = "; ".join(f"missing {attr}: {_COOKIE_ATTR_EXPLANATIONS[attr]}" for attr in missing)
    return {
        "cookie_name": name,
        "severity": severity,
        "missing_attributes": missing,
        "why": why,
    }


def security_headers_check(url: str) -> dict:
    """GET `url` and return a structured list of header/cookie findings
    plus an explicit clickjacking assessment. Detection only -- see
    module docstring on why a finding here is a flag, not a verdict."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    is_https = url.startswith("https://")

    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True, headers=SETTINGS.session_headers or None
        )
    except requests.RequestException as exc:
        return {"url": url, "error": _redact_sessions(str(exc))}

    headers = resp.headers
    csp_directives = _parse_csp_directives(headers.get("Content-Security-Policy", ""))

    findings: list[dict] = []
    for finding in (
        _check_scheme(is_https),
        _check_hsts(headers, is_https),
        *_check_csp(csp_directives, headers.get("Content-Security-Policy")),
        _check_nosniff(headers),
        _check_referrer_policy(headers),
        _check_permissions_policy(headers),
    ):
        if finding:
            findings.append(finding)

    clickjacking_finding, protected_by = _assess_clickjacking(headers, csp_directives)
    if clickjacking_finding:
        findings.append(clickjacking_finding)

    cookie_findings = [
        f for f in (_check_cookie(c) for c in _all_set_cookie_headers(resp)) if f is not None
    ]
    findings.extend(cookie_findings)

    return {
        "url": url,
        "status": resp.status_code,
        "is_https": is_https,
        "findings": findings,
        "finding_count": len(findings),
        "clickjacking": {
            "likely_frameable": clickjacking_finding is not None,
            "protected_by": protected_by,
        },
    }
