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
from d3m0n.tools.cors_check import cors_check
from d3m0n.tools.crawler import crawl_site
from d3m0n.tools.fuzz import ffuf_scan
from d3m0n.tools.graphql import graphql_introspect
from d3m0n.tools.idor_check import idor_check
from d3m0n.tools.js_secrets import js_secrets_scan
from d3m0n.tools.recon import dns_lookup, http_probe, tls_info
from d3m0n.tools.scan import nmap_scan
from d3m0n.tools.subdomain import subfinder_scan
from d3m0n.tools.takeover_check import subdomain_takeover_check
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
            "Launch ONE Burp Suite Scanner task (Burp Suite PROFESSIONAL/ENTERPRISE only, via "
            "its REST API) covering a host and one or more paths on it, and return the issues "
            "Burp's own engine finds. Batch every path worth scanning on this host (e.g. ones "
            "ffuf_scan already discovered) into one call via `paths` rather than calling this "
            "once per path. Detection only — never confirms exploitability or sends anything "
            "beyond what Burp's Scanner sends on its own. Returns a clear error if Burp's REST "
            "API isn't configured/reachable, or if you're on Community Edition (no Scanner there)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL or hostname"},
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Paths to scan together in one task, default ['/']",
                },
                "scan_config_name": {
                    "type": "string",
                    "description": (
                        "Name of a Scanner configuration already saved in Burp's UI (e.g. one "
                        "that adds an authenticated session via a Session Handling Rule). "
                        "Optional — omit for an unauthenticated scan with Burp's defaults."
                    ),
                },
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
        "name": "idor_check",
        "description": (
            "Request one resource URL (one you already saw while browsing authenticated "
            "content — an order/profile/document/account reference) as three identities: "
            "your primary session, a second configured test account, and anonymous. Returns "
            "all three responses side by side (status, length, snippet, body-similarity "
            "score) so you can tell whether a DIFFERENT account sees the same data: broken "
            "access control / IDOR. Detection only — gathers the comparison, never declares "
            "a verdict itself. The URL's path/query must be identifier-shaped (letters, "
            "digits, / _ . - ~ : = & ? , only, checked after full percent-decoding); anything "
            "payload-shaped is refused. Set enumerate_range > 0 to also probe that many "
            "numeric ids either side of the one in the URL (e.g. /orders/4471 with "
            "enumerate_range=5 also tries 4466..4470 and 4472..4476) under the second "
            "account alone, always via GET regardless of `method` — the standard "
            "IDOR-by-enumeration technique. Capped at 10. `method` defaults to GET; HEAD "
            "and OPTIONS work the same way (also surfaces the response's Allow header when "
            "present). POST/PUT/PATCH/DELETE actually change data under whichever identity "
            "sends them, so they're refused with a clear error unless the operator has set "
            "D3M0N_ALLOW_MUTATING_IDOR_CHECKS=1 before this run — if you hit that refusal, "
            "tell the human rather than trying to work around it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The exact resource URL to compare across identities",
                },
                "enumerate_range": {
                    "type": "integer",
                    "description": (
                        "How many nearby numeric ids to probe either side, default 0 "
                        "(off), capped at 10"
                    ),
                },
                "method": {
                    "type": "string",
                    "description": (
                        "HTTP method: GET (default), HEAD, OPTIONS, POST, PUT, PATCH, "
                        "DELETE. The last four need D3M0N_ALLOW_MUTATING_IDOR_CHECKS=1 "
                        "set by the operator ahead of time, or this tool refuses."
                    ),
                },
                "body": {
                    "type": "string",
                    "description": (
                        "Request body for POST/PUT/PATCH/DELETE, e.g. a JSON string. "
                        "Capped at 20000 characters. Ignored for GET/HEAD/OPTIONS."
                    ),
                },
                "content_type": {
                    "type": "string",
                    "description": (
                        "Content-Type header to send with `body`, default 'application/json'"
                    ),
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "crawl_site",
        "description": (
            "Bounded, in-scope, GET-only crawl starting from one URL: follows links/forms/"
            "script sources found in each page's own HTML (never model-composed per link), "
            "staying strictly within scope. Never submits a form, only reports its action/"
            "method. Returns structured metadata only (url/status/length per page, discovered "
            "forms, discovered JS file URLs) — never raw page content. Use this to map real "
            "attack surface before pointing burp_scan/nuclei_scan/idor_check at it, instead of "
            "guessing at paths."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Starting URL or hostname"},
                "max_pages": {
                    "type": "integer",
                    "description": "Max pages to fetch, default 20, capped at 50",
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Max link-following depth, default 2, capped at 3",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "js_secrets_scan",
        "description": (
            "Fetch one JS (or any text) file and check it against a fixed set of secret/"
            "hidden-endpoint patterns (AWS/Google/Slack keys, JWTs, private key headers, "
            "generic api_key-shaped assignments, embedded /api//internal//admin/ paths). "
            "Each kept finding has a confidence (high/medium/low, downgraded when the "
            "matched value's entropy looks too low to be real random secret data), the "
            "entropy score itself (null where it isn't a meaningful signal, e.g. a private "
            "key header or a path), a position (character offset) and a context snippet "
            "(~50 chars either side, one line). Obvious placeholders/examples (keyword- or "
            "structure-matched, e.g. 'your-api-key', repeated characters, sequential runs) "
            "are excluded from `findings` but never silently dropped — see "
            "filtered_placeholder_count/examples. minified_heuristic describes the fetched "
            "body's own line/whitespace shape (informational, not a confidence input). A "
            "match is still a lead worth manual verification, not a confirmed exposure. "
            "Feed it script URLs crawl_site discovers."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL of the JS/text file to scan"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "graphql_introspect",
        "description": (
            "POST a standard, fixed introspection query to a GraphQL endpoint and report "
            "whether introspection is enabled and, if so, a summary of the schema (type "
            "names, query/mutation root type). A misconfigured-open introspection endpoint "
            "hands over the whole schema for free — a common, easy, real finding."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "GraphQL endpoint URL"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "cors_check",
        "description": (
            "Probe for CORS misconfiguration: sends a fixed small set of Origin header "
            "values (arbitrary unrelated origin, null, naive-prefix, naive-suffix) and "
            "reports how Access-Control-Allow-Origin/-Credentials respond. Flags include "
            "reflects_arbitrary_origin(_with_credentials), allows_null_origin, "
            "subdomain_prefix/suffix_pattern_weakness. Detection only."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "URL or hostname"}},
            "required": ["target"],
        },
    },
    {
        "name": "subdomain_takeover_check",
        "description": (
            "Check whether a subdomain's CNAME points at a known takeover-prone provider "
            "(GitHub Pages, S3, Heroku, Azure, Shopify, and others) and, if so, whether the "
            "response body matches that provider's 'unclaimed resource' fingerprint. A "
            "match is a real, often high-severity lead (dangling DNS); no match is "
            "inconclusive, not a clean bill of health, since fingerprints can drift."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Subdomain hostname to check"},
            },
            "required": ["target"],
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
    "burp_scan": lambda target, paths=None, scan_config_name=None, **_: burp_scan(
        target, paths, scan_config_name
    ),
    "idor_check": lambda target, enumerate_range=0, method="GET", body=None, content_type=None, **_: idor_check(
        target, enumerate_range, method, body, content_type
    ),
    "crawl_site": lambda target, scope, max_pages=20, max_depth=2, **_: crawl_site(
        target, scope, max_pages, max_depth
    ),
    "js_secrets_scan": lambda target, **_: js_secrets_scan(target),
    "graphql_introspect": lambda target, **_: graphql_introspect(target),
    "cors_check": lambda target, **_: cors_check(target),
    "subdomain_takeover_check": lambda target, **_: subdomain_takeover_check(target),
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
    # tool_input is model-controlled JSON, never validated against the
    # declared schema on this side. None of the schemas above list "scope"
    # as a property, but if a tool call's input happens to include that key
    # anyway, it would collide with the scope=scope keyword every dispatch
    # lambda receives below and raise TypeError at the call site itself —
    # before any individual tool runs, and uncaught by callers (graph.py's
    # _run_one only catches OutOfScopeError). Drop it so a stray key
    # degrades to "ignored" instead of "crashes the whole agent run".
    tool_input = {k: v for k, v in tool_input.items() if k != "scope"}
    target = tool_input.get("target")
    if not target:
        return {"error": f"Tool {name!r} requires a 'target'"}
    enforce_scope(scope, target)  # raises OutOfScopeError on violation
    return _DISPATCH[name](scope=scope, **tool_input)
