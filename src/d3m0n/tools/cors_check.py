"""CORS misconfiguration probe — reflected-origin / null-origin / weak
subdomain-pattern checks, GET only.

Sends a fixed, small set of Origin header values (never model-composed —
only the target URL is caller-supplied) and inspects how
Access-Control-Allow-Origin/-Credentials respond:

- Does the server reflect back an arbitrary, unrelated Origin? Combined
  with Allow-Credentials: true, that lets ANY website read this
  authenticated response on a victim's behalf — the classic, most
  commonly reported real-world CORS misconfiguration.
- Does it allow the literal "null" origin (forceable via a sandboxed
  iframe/data: URI)?
- Does a naive prefix/suffix string match let "evil-{host}" or
  "{host}.evil.invalid" through, instead of an exact allowlist?

Each probe carries the configured session headers (if any), since a
credentialed-request CORS misconfiguration is the actually-exploitable
case — an unauthenticated one is much lower severity. Detection only:
reports what each probe got back, classified into flags; it never
confirms exploitability beyond what the response headers show.
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests

from d3m0n.config import SETTINGS

_PROBE_ARBITRARY_ORIGIN = "https://d3m0n-cors-probe.invalid"


def _redact_sessions(text: str) -> str:
    secret_values = [v for v in SETTINGS.session_headers.values() if v]
    for value in secret_values:
        text = text.replace(value, "***REDACTED-SESSION-HEADER***")
    return text


def _probe_origins(hostname: str) -> list[str]:
    return [
        f"https://{hostname}",  # baseline: legitimate same-origin
        _PROBE_ARBITRARY_ORIGIN,  # arbitrary, unrelated origin
        "null",  # the null origin
        f"https://evil-{hostname}",  # naive prefix match?
        f"https://{hostname}.evil.invalid",  # naive suffix match?
    ]


def _classify(probes: list[dict]) -> list[str]:
    flags = []
    by_origin = {p["origin_sent"]: p for p in probes if "error" not in p}

    arbitrary = by_origin.get(_PROBE_ARBITRARY_ORIGIN)
    if arbitrary and arbitrary.get("access_control_allow_origin") == _PROBE_ARBITRARY_ORIGIN:
        creds = str(arbitrary.get("access_control_allow_credentials", "")).lower() == "true"
        flags.append(
            "reflects_arbitrary_origin_with_credentials" if creds else "reflects_arbitrary_origin"
        )

    null_probe = by_origin.get("null")
    if null_probe and null_probe.get("access_control_allow_origin") == "null":
        flags.append("allows_null_origin")

    for p in probes:
        origin = p.get("origin_sent", "")
        acao = p.get("access_control_allow_origin")
        if acao and acao == origin:
            if origin.startswith("https://evil-"):
                flags.append("subdomain_prefix_pattern_weakness")
            elif origin.endswith(".evil.invalid"):
                flags.append("subdomain_suffix_pattern_weakness")

    wildcard = next((p for p in probes if p.get("access_control_allow_origin") == "*"), None)
    if wildcard and str(wildcard.get("access_control_allow_credentials", "")).lower() == "true":
        # Browsers themselves reject this exact combination, so it isn't
        # directly exploitable via a browser — but it signals a broken/
        # non-compliant CORS implementation worth a closer manual look.
        flags.append("wildcard_origin_with_credentials_noncompliant")

    return flags


def cors_check(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    hostname = urlparse(url).hostname or url

    probes = []
    for origin in _probe_origins(hostname):
        headers = dict(SETTINGS.session_headers)
        headers["Origin"] = origin
        try:
            resp = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        except requests.RequestException as exc:
            probes.append({"origin_sent": origin, "error": _redact_sessions(str(exc))})
            continue
        probes.append(
            {
                "origin_sent": origin,
                "status": resp.status_code,
                "access_control_allow_origin": resp.headers.get("Access-Control-Allow-Origin"),
                "access_control_allow_credentials": resp.headers.get(
                    "Access-Control-Allow-Credentials"
                ),
            }
        )

    return {"url": url, "probes": probes, "flags": _classify(probes)}
