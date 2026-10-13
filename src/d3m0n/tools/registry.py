"""Tool schemas handed to Claude, plus the dispatcher that runs them.

Every tool here is called through `run_tool()`, which enforces scope via
`safety.enforce_scope()` before dispatching — this is the single choke point
so no new tool can accidentally skip the authorization check.
"""

from __future__ import annotations

from typing import Any, Callable

from d3m0n.safety import Scope, enforce_scope
from d3m0n.tools.burp_scanner import burp_scan
from d3m0n.tools.burp_traffic import burp_traffic_review
from d3m0n.tools.fuzz import ffuf_scan
from d3m0n.tools.recon import dns_lookup, http_probe, tls_info
from d3m0n.tools.scan import nmap_scan
from d3m0n.tools.subdomain import subfinder_scan
from d3m0n.tools.vuln import nuclei_scan

# Anthropic tool-use schema. `target` must be present on every tool so the
# scope check below has something to validate against.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "dns_lookup",
        "description": "Resolve A/AAAA/MX/TXT/NS DNS records for a hostname.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Hostname to resolve"}},
            "required": ["target"],
        },
    },
    {
        "name": "http_probe",
        "description": "GET a URL and return status, headers, server banner, and page title.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "URL or hostname"}},
            "required": ["target"],
        },
    },
    {
        "name": "tls_info",
        "description": "Fetch TLS certificate subject/issuer/expiry for hostname:port.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Hostname"},
                "port": {"type": "integer", "description": "Port, default 443"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nmap_scan",
        "description": (
            "Run an nmap service/version-detection scan (-sV -Pn, no exploit scripts) "
            "against a target for a port range."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "ports": {"type": "string", "description": "Port range, e.g. '1-1024'"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "subfinder_scan",
        "description": "Enumerate subdomains of a root domain using subfinder (passive sources).",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Root domain, e.g. example.com"}
            },
            "required": ["target"],
        },
    },
    {
        "name": "nuclei_scan",
        "description": (
            "Run nuclei detection templates (known CVEs, exposed panels, misconfigurations) "
            "against a URL/host. Detection only — reports what matched, does not exploit."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL or hostname"},
                "severity": {
                    "type": "string",
                    "description": "Comma-separated severities, default 'medium,high,critical'",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "ffuf_scan",
        "description": "Discover hidden paths/files on a web target via wordlist-based fuzzing.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL or hostname"},
                "wordlist": {
                    "type": "string",
                    "description": "Optional path to a wordlist file on disk",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "burp_scan",
        "description": (
            "Launch a Burp Suite Scanner scan (Burp Suite PROFESSIONAL/ENTERPRISE only, via "
            "its REST API) against a URL/host and return the issues Burp's own engine finds. "
            "Detection only — never confirms exploitability or sends anything beyond what "
            "Burp's Scanner sends on its own. Returns a clear error if Burp's REST API isn't "
            "configured/reachable, or if you're on Community Edition (no Scanner there)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL or hostname"},
                "path": {"type": "string", "description": "Path to scan, default '/'"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "burp_traffic_review",
        "description": (
            "Review an exported Burp proxy-history XML file (Proxy > HTTP history > Save "
            "items, in any Burp edition including Community) for things worth a manual "
            "look: missing security headers, cookies without Secure/HttpOnly, reflected "
            "query params, verbose error pages. Flags leads, not confirmed vulnerabilities."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The primary hostname this export is about (checked against scope)",
                },
                "export_path": {
                    "type": "string",
                    "description": "Path to the Burp 'Save items' XML export file on disk",
                },
            },
            "required": ["target", "export_path"],
        },
    },
    {
        "name": "finish",
        "description": (
            "Call this when the objective is satisfied (or can't be progressed further) "
            "to end the run and write the findings report."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Summary of what was found"}
            },
            "required": ["summary"],
        },
    },
]

_DISPATCH: dict[str, Callable[..., dict]] = {
    "dns_lookup": lambda target, **_: dns_lookup(target),
    "http_probe": lambda target, **_: http_probe(target),
    "tls_info": lambda target, port=443, **_: tls_info(target, port),
    "nmap_scan": lambda target, ports="1-1024", **_: nmap_scan(target, ports),
    "subfinder_scan": lambda target, **_: subfinder_scan(target),
    "nuclei_scan": lambda target, severity="medium,high,critical", **_: nuclei_scan(target, severity),
    "ffuf_scan": lambda target, wordlist=None, **_: ffuf_scan(target, wordlist),
    "burp_scan": lambda target, path="/", **_: burp_scan(target, path),
    "burp_traffic_review": lambda target, export_path, scope, **_: burp_traffic_review(
        export_path, scope
    ),
}


def run_tool(name: str, tool_input: dict, scope: Scope) -> dict:
    """Dispatch a tool call by name, enforcing scope first.

    `finish` has no network target and is handled by the graph directly, so
    it's never passed here. `scope` is passed through to every dispatched
    tool (as a keyword, absorbed by `**_` on the ones that don't need it) —
    `burp_traffic_review` is the one tool that needs the full Scope object,
    since it independently re-checks every host embedded in its input file
    rather than just the single declared `target`.
    """
    if name not in _DISPATCH:
        return {"error": f"Unknown tool: {name!r}"}
    target = tool_input.get("target")
    if not target:
        return {"error": f"Tool {name!r} requires a 'target'"}
    enforce_scope(scope, target)  # raises OutOfScopeError on violation
    return _DISPATCH[name](scope=scope, **tool_input)
