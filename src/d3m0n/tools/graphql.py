"""GraphQL introspection check — a fixed, hardcoded query, never model-supplied.

POSTs the standard __schema introspection query to a given endpoint and
reports whether introspection is enabled and a truncated summary of the
schema if so. A misconfigured-open introspection endpoint on a
production API is a common, easy, real finding — it hands over the
whole schema for free.

The query text itself never varies by caller input — only the target URL
does — so there's no injection surface here beyond "which endpoint to
ask," the same low-risk shape as nuclei_scan/ffuf_scan.
"""

from __future__ import annotations

import requests

from d3m0n.config import SETTINGS

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}
"""

_MAX_TYPES_LISTED = 40


def _redact_sessions(text: str) -> str:
    secret_values = [v for v in SETTINGS.session_headers.values() if v]
    for value in secret_values:
        text = text.replace(value, "***REDACTED-SESSION-HEADER***")
    return text


def graphql_introspect(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.post(
            url,
            json={"query": _INTROSPECTION_QUERY},
            timeout=10,
            headers=SETTINGS.session_headers or None,
        )
    except requests.RequestException as exc:
        return {"url": url, "error": _redact_sessions(str(exc))}

    if resp.status_code != 200:
        return {"url": url, "status": resp.status_code, "introspection_enabled": False}

    try:
        data = resp.json()
    except ValueError:
        return {"url": url, "status": resp.status_code, "introspection_enabled": False}

    schema = (data or {}).get("data", {}).get("__schema") if isinstance(data, dict) else None
    if not schema:
        return {"url": url, "status": resp.status_code, "introspection_enabled": False}

    types = schema.get("types") or []
    type_names = [t.get("name") for t in types if t.get("name") and not t["name"].startswith("__")]

    return {
        "url": url,
        "status": resp.status_code,
        "introspection_enabled": True,
        "query_type": (schema.get("queryType") or {}).get("name"),
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "type_count": len(type_names),
        "type_names": sorted(type_names)[:_MAX_TYPES_LISTED],
    }
