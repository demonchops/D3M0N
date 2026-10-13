"""Review of an exported Burp proxy-history — no live Burp or Pro needed.

Works with Burp Suite COMMUNITY Edition (which has no Scanner or REST
API): in Burp, go to Proxy > HTTP history, select the requests you want
reviewed, right-click > "Save items" > save as XML, and point this tool
at that file.

This never talks to the network — it only reads the file it's given, and
only reasons over traffic you already captured yourself. Every host
present in the export is checked against the confirmed scope before being
included; anything outside scope is counted and silently excluded from
the results, never reported on (you may well have other sites in your
proxy history that have nothing to do with this engagement).

What it flags is a lead for a manual look, not a confirmed vulnerability —
e.g. "this query parameter's value reappears verbatim in the response" is
worth checking by hand in Repeater (is it actually unescaped in an
HTML/JS/attribute context? does it execute?), not proof of XSS by itself.
"""

from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET

from d3m0n.safety import Scope

_SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
)

_ERROR_PATTERN = re.compile(
    r"(stack trace|traceback \(most recent|sql syntax|ORA-\d{5}|at System\.|"
    r"System\.Exception|django\.core|NullPointerException)",
    re.IGNORECASE,
)

# xml.etree.ElementTree (expat) isn't vulnerable to classic XXE (external
# entities can't pull in a file/URL) by default, but it IS vulnerable to a
# "billion laughs" entity-expansion DoS if the input defines nested
# entities. A genuine Burp "Save items" export never contains a DOCTYPE or
# ENTITY declaration, so refuse up front rather than let expat anywhere
# near one — a cheap guard, not a claim that defused XML parsing is
# generally solved by this one check.
_DANGEROUS_XML_MARKERS = (b"<!DOCTYPE", b"<!ENTITY")


def _b64_decode(elem) -> bytes:
    if elem is None or elem.text is None:
        return b""
    if elem.get("base64") == "true":
        try:
            return base64.b64decode(elem.text)
        except (ValueError, TypeError):
            return b""
    return elem.text.encode("utf-8", errors="replace")


def _flag_item(path: str, response: bytes) -> list[str]:
    flags: list[str] = []
    resp_text = response.decode("utf-8", errors="replace")
    header_block = resp_text.split("\r\n\r\n", 1)[0].lower()

    for header in _SECURITY_HEADERS:
        if header not in header_block:
            flags.append(f"missing {header} response header")

    cookie_lines = [line for line in header_block.splitlines() if line.startswith("set-cookie:")]
    for cookie_line in cookie_lines:
        if "secure" not in cookie_line or "httponly" not in cookie_line:
            flags.append("Set-Cookie missing Secure and/or HttpOnly")
            break

    # Rough reflected-input heuristic: a query param value reappearing
    # verbatim in the response body is *worth a manual look*, nothing more.
    query = path.split("?", 1)[1] if "?" in path else ""
    for pair in query.split("&"):
        if "=" not in pair:
            continue
        _, _, value = pair.partition("=")
        if len(value) >= 4 and value in resp_text:
            flags.append(f"query value {value!r} reflected verbatim in response body")
            break

    if _ERROR_PATTERN.search(resp_text):
        flags.append("response body looks like a verbose error/stack trace")

    return flags


def burp_traffic_review(export_path: str, scope: Scope, max_flagged: int = 50) -> dict:
    try:
        with open(export_path, "rb") as f:
            raw = f.read()
    except OSError as exc:
        return {"export_path": export_path, "error": f"Could not read {export_path!r}: {exc}"}

    if any(marker in raw for marker in _DANGEROUS_XML_MARKERS):
        return {
            "export_path": export_path,
            "error": "Refusing to parse: this file contains a DOCTYPE/ENTITY declaration, "
            "which a genuine Burp 'Save items' export never has. Guards against XML "
            "entity-expansion ('billion laughs') denial-of-service.",
        }

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        return {"export_path": export_path, "error": f"Could not parse {export_path!r}: {exc}"}

    total = 0
    out_of_scope = 0
    flagged = []

    for item in root.findall("item"):
        total += 1
        host_elem = item.find("host")
        host = (host_elem.text or "").strip() if host_elem is not None else ""
        if not host or not scope.contains(host):
            out_of_scope += 1
            continue

        method = (item.findtext("method") or "").strip()
        path = (item.findtext("path") or "").strip()
        response = _b64_decode(item.find("response"))

        flags = _flag_item(path, response)
        if flags:
            flagged.append({"host": host, "method": method, "path": path, "flags": flags})

    return {
        "export_path": export_path,
        "items_total": total,
        "items_out_of_scope": out_of_scope,
        "items_flagged": len(flagged),
        "flagged": flagged[:max_flagged],
        "truncated": len(flagged) > max_flagged,
    }
