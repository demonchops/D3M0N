"""Tool schemas handed to Claude, plus the dispatcher that runs them.

Every tool here is called through `run_tool()`, which enforces scope via
`safety.enforce_scope()` before dispatching — this is the single choke point
so no new tool can accidentally skip the authorization check.
"""

from __future__ import annotations

from typing import Any, Callable

from d3m0n.safety import Scope, enforce_scope
from d3m0n.tools.recon import dns_lookup, http_probe, tls_info
from d3m0n.tools.scan import nmap_scan

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
}


def run_tool(name: str, tool_input: dict, scope: Scope) -> dict:
    """Dispatch a tool call by name, enforcing scope first.

    `finish` has no network target and is handled by the graph directly, so
    it's never passed here.
    """
    if name not in _DISPATCH:
        return {"error": f"Unknown tool: {name!r}"}
    target = tool_input.get("target")
    if not target:
        return {"error": f"Tool {name!r} requires a 'target'"}
    enforce_scope(scope, target)  # raises OutOfScopeError on violation
    return _DISPATCH[name](**tool_input)
