"""Passive/low-impact recon tools: DNS, HTTP headers, TLS cert info."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import requests

from d3m0n.config import SETTINGS


def dns_lookup(hostname: str) -> dict:
    """Resolve common record types for a hostname."""
    records: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS"):
        try:
            answers = dns.resolver.resolve(hostname, rtype, lifetime=5.0)
            records[rtype] = [str(r) for r in answers]
        except Exception as exc:  # noqa: BLE001 - surface any resolver failure
            records[rtype] = [f"<error: {exc.__class__.__name__}>"]
    return {"hostname": hostname, "records": records}


def http_probe(url: str) -> dict:
    """Fetch status, headers, and a page title for a URL, GET only.

    Low-impact recon only: a query string or fragment on `url` is refused
    rather than sent. Scope enforcement (safety.Scope.contains) only ever
    validates the hostname portion of a target, never the path/query, so
    without this check an in-scope-looking target could carry an arbitrary
    GET-based payload (reflected XSS/SSTI/open-redirect/IDOR-by-parameter-
    change) straight into a real request — with any configured
    D3M0N_SESSION_HEADERS (an authenticated session) attached automatically.
    That would make this tool a request-tampering primitive in substance,
    contradicting the project's "no tool here ever auto-exploits" invariant
    regardless of what prompts.py tells the model to do with it. This is
    the tool-level boundary that invariant actually depends on.

    If D3M0N_SESSION_HEADERS is configured (see config.py), those headers
    ride along automatically — the caller never supplies or sees them.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.query or parsed.fragment:
        return {
            "url": url,
            "error": "http_probe is recon-only and refuses any target with a query string "
            "or fragment -- it would otherwise be sent as a live request, authenticated "
            "session included if one is configured. Probe the bare host/path; use "
            "burp_scan or burp_traffic_review for anything that needs a specific parameter "
            "value, which only ever detect/report and never execute a payload themselves.",
        }
    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True, headers=SETTINGS.session_headers or None
        )
    except requests.RequestException as exc:
        return {"url": url, "error": str(exc)}
    title = None
    match = resp.text[:4000].lower().find("<title>")
    if match != -1:
        end = resp.text[:4000].lower().find("</title>", match)
        if end != -1:
            title = resp.text[match + 7 : end].strip()
    return {
        "url": url,
        "final_url": resp.url,
        "status": resp.status_code,
        "server": resp.headers.get("Server"),
        "headers": dict(resp.headers),
        "title": title,
    }


def tls_info(hostname: str, port: int = 443) -> dict:
    """Fetch the TLS certificate's subject/issuer/validity for hostname:port."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
    except Exception as exc:  # noqa: BLE001
        return {"hostname": hostname, "port": port, "error": str(exc)}

    not_after = cert.get("notAfter")
    expires_in_days = None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            expires_in_days = (expiry - datetime.now(timezone.utc)).days
        except ValueError:
            pass

    return {
        "hostname": hostname,
        "port": port,
        "subject": cert.get("subject"),
        "issuer": cert.get("issuer"),
        "not_after": not_after,
        "expires_in_days": expires_in_days,
        "subject_alt_names": cert.get("subjectAltName"),
    }
