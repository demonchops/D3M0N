"""Subdomain takeover check — CNAME fingerprint match + best-effort body
confirmation, GET only.

A "dangling" subdomain happens when a CNAME still points at a
third-party service (GitHub Pages, S3, Heroku, Azure, ...) that the
owner stopped using without removing the DNS record. If that resource
name is unclaimed on the provider's side, anyone can register it there
and have the victim's subdomain start serving THEIR content — a classic,
often high-severity bounty finding.

Two layers, both reported, neither alone treated as a confirmed finding:
1. DNS: does the CNAME chain point at a known takeover-prone provider?
   This is the mechanically reliable part (exact string matching on a
   resolved CNAME).
2. HTTP body fingerprint: fetches the host and checks for that
   provider's known "nothing here"/"unclaimed" response text. This is
   best-effort — provider error pages drift over time, so a
   NON-match is reported as inconclusive, not as "safe"; only a
   confirmed CNAME-to-known-provider match plus a fingerprint hit is
   presented as a real lead.

The fingerprint table is a fixed, hardcoded set (never model-supplied) of
the services most commonly and reliably documented in public subdomain-
takeover research — deliberately a shorter, higher-confidence list
rather than an exhaustive one, since an inaccurate fingerprint causes a
wrong classification, and this project would rather under-flag than
assert something false.
"""

from __future__ import annotations

import dns.resolver
import requests

from d3m0n.config import SETTINGS

_TAKEOVER_FINGERPRINTS: list[dict] = [
    {
        "service": "GitHub Pages",
        "cname_contains": "github.io",
        "body_fingerprint": "There isn't a GitHub Pages site here",
    },
    {"service": "Heroku", "cname_contains": "herokuapp.com", "body_fingerprint": "No such app"},
    {"service": "AWS S3", "cname_contains": "s3.amazonaws.com", "body_fingerprint": "NoSuchBucket"},
    {
        "service": "Azure Web Apps",
        "cname_contains": "azurewebsites.net",
        "body_fingerprint": "404 Web Site not found",
    },
    {
        "service": "Shopify",
        "cname_contains": "myshopify.com",
        "body_fingerprint": "Sorry, this shop is currently unavailable",
    },
    {
        "service": "Tumblr",
        "cname_contains": "domains.tumblr.com",
        "body_fingerprint": "Whatever you were looking for doesn't currently exist",
    },
    {
        "service": "WordPress.com",
        "cname_contains": "wordpress.com",
        "body_fingerprint": "Do you want to register",
    },
    {"service": "Surge.sh", "cname_contains": "surge.sh", "body_fingerprint": "project not found"},
    {
        "service": "Ghost (Ghost.io)",
        "cname_contains": "ghost.io",
        "body_fingerprint": "The thing you were looking for is no longer here",
    },
    {
        "service": "Bitbucket Pages",
        "cname_contains": "bitbucket.io",
        "body_fingerprint": "Repository not found",
    },
    {
        "service": "Fastly",
        "cname_contains": "fastly.net",
        "body_fingerprint": "Fastly error: unknown domain",
    },
]

_MAX_CNAME_HOPS = 5


def _redact_sessions(text: str) -> str:
    secret_values = [v for v in SETTINGS.session_headers.values() if v]
    for value in secret_values:
        text = text.replace(value, "***REDACTED-SESSION-HEADER***")
    return text


def _resolve_cname_chain(hostname: str, max_hops: int = _MAX_CNAME_HOPS) -> list[str]:
    """Follow CNAME records up to max_hops. Stops (doesn't raise) the
    moment resolution fails for any reason — a dangling/dead CNAME target
    failing to resolve further is itself expected, not an error."""
    chain: list[str] = []
    current = hostname
    for _ in range(max_hops):
        try:
            answers = dns.resolver.resolve(current, "CNAME", lifetime=5.0)
        except Exception:  # noqa: BLE001 - any resolver failure just ends the chain
            break
        target = str(answers[0].target).rstrip(".")
        if not target or target in chain:  # guard against a CNAME loop
            break
        chain.append(target)
        current = target
    return chain


def _check_fingerprint(hostname: str, service: dict) -> dict:
    fingerprint = service.get("body_fingerprint")
    last_exc = None
    resp = None
    # A truly dangling resource often has no valid TLS cert left; try
    # HTTPS first but fall back to HTTP rather than give up.
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{hostname}",
                timeout=10,
                allow_redirects=True,
                headers=SETTINGS.session_headers or None,
            )
            break
        except requests.RequestException as exc:
            last_exc = exc
            continue

    if resp is None:
        return {"fingerprint_check": "error", "error": _redact_sessions(str(last_exc))}

    if not fingerprint:
        return {"fingerprint_check": "no_fingerprint_available", "status": resp.status_code}

    matched = fingerprint.lower() in resp.text.lower()
    note = (
        "Body text matches this service's known 'unclaimed' fingerprint -- a real lead, "
        "worth manually verifying (and potentially claiming the resource yourself as proof)."
        if matched
        else "Fingerprint text didn't match, but provider error pages drift over time -- "
        "this is inconclusive, not a clean bill of health, since the CNAME still points at "
        "a known takeover-prone service."
    )
    return {
        "fingerprint_check": "matched" if matched else "not_matched",
        "status": resp.status_code,
        "note": note,
    }


def subdomain_takeover_check(target: str) -> dict:
    hostname = target.strip()
    cname_chain = _resolve_cname_chain(hostname)

    matched_service = next(
        (fp for fp in _TAKEOVER_FINGERPRINTS if any(fp["cname_contains"] in link for link in cname_chain)),
        None,
    )

    if matched_service is None:
        return {"hostname": hostname, "cname_chain": cname_chain, "matches_known_service": False}

    return {
        "hostname": hostname,
        "cname_chain": cname_chain,
        "matches_known_service": True,
        "service": matched_service["service"],
        **_check_fingerprint(hostname, matched_service),
    }
