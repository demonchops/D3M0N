"""Review of an exported Burp proxy-history — no live Burp or Pro needed.

Works with Burp Suite COMMUNITY Edition (which has no Scanner or REST
API): in Burp, go to Proxy > HTTP history, select the requests you want
reviewed, right-click > "Save items" > save as XML, and point this tool
at that file.

This never talks to the network — it only reads the file it's given, and
only reasons over traffic you already captured yourself. Every item's
real origin — its <host> label, its <url>'s hostname, and its own
request's Host: header, which can each be set independently in a
hand-edited or fabricated export — must agree before that host is
checked against the confirmed scope and the item included; anything
out of scope, or whose origin is ambiguous/inconsistent, is counted and
silently excluded from the results, never reported on (you may well have
other sites in your proxy history that have nothing to do with this
engagement).

What it flags is a lead for a manual look, not a confirmed vulnerability —
e.g. "this query parameter's value reappears verbatim in the response" is
worth checking by hand in Repeater (is it actually unescaped in an
HTML/JS/attribute context? does it execute?), not proof of XSS by itself.
"""

from __future__ import annotations

import base64
import codecs
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

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
#
# The check has to run on *decoded text*, not raw bytes: expat auto-detects
# UTF-16/UTF-32 (via BOM, or the no-BOM signatures below) and happily
# parses a DOCTYPE/ENTITY written in either, but a literal ASCII byte
# search (b"<!DOCTYPE" in raw) never matches them — every character is 2
# or 4 bytes with interleaved nulls — so the guard would silently never
# fire while expat still fully processes the declaration underneath.
_DANGEROUS_XML_MARKERS = ("<!DOCTYPE", "<!ENTITY")

_BOM_ENCODINGS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)

# No-BOM multi-byte signatures for the start of "<?xml" in UTF-16/UTF-32,
# per XML 1.0 Appendix F — expat auto-detects these too, BOM or not.
_NOBOM_ENCODINGS: tuple[tuple[bytes, str], ...] = (
    (b"\x00\x00\x00\x3c", "utf-32-be"),
    (b"\x3c\x00\x00\x00", "utf-32-le"),
    (b"\x00\x3c\x00\x3f", "utf-16-be"),
    (b"\x3c\x00\x3f\x00", "utf-16-le"),
)


def _sniff_text(raw: bytes) -> str:
    """Decode `raw` the same way expat would pick an encoding (BOM, or the
    no-BOM multi-byte signatures XML 1.0 Appendix F defines) for the
    DOCTYPE/ENTITY guard, so a byte-level substring check can't be dodged
    by an encoding expat still parses fine. Falls back to utf-8 (replacing
    bad bytes), which is also correct for the common ASCII-compatible case
    the original raw-bytes check already handled."""
    for bom, encoding in _BOM_ENCODINGS:
        if raw.startswith(bom):
            try:
                return raw[len(bom):].decode(encoding, errors="replace")
            except LookupError:
                break
    for sig, encoding in _NOBOM_ENCODINGS:
        if raw.startswith(sig):
            try:
                return raw.decode(encoding, errors="replace")
            except LookupError:
                break
    return raw.decode("utf-8", errors="replace")


_HOST_HEADER_RE = re.compile(rb"^host:[ \t]*(\S+)", re.IGNORECASE | re.MULTILINE)


def _host_header_hostname(request_bytes: bytes) -> str:
    """Pull the hostname out of a decoded request's Host: header (port, if
    any, stripped the same way urlparse strips it from a URL)."""
    match = _HOST_HEADER_RE.search(request_bytes)
    if not match:
        return ""
    raw_value = match.group(1).decode("ascii", errors="replace").strip()
    return urlparse(f"//{raw_value}").hostname or ""


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
    # Tolerate LF-only header/body separation, not just strict CRLF-CRLF:
    # a literal "\r\n\r\n" split silently finds no match on an LF-only
    # response, so header_block falls back to the ENTIRE response text
    # (headers *and* body). For the missing-header checks below, that's a
    # silent false negative whenever the body happens to mention a header
    # name that's genuinely missing (e.g. a debug/echo page reflecting
    # request headers back).
    header_block = re.split(r"\r?\n\r?\n", resp_text, maxsplit=1)[0].lower()

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

    if any(marker in _sniff_text(raw) for marker in _DANGEROUS_XML_MARKERS):
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
        declared_host = (host_elem.text or "").strip() if host_elem is not None else ""
        url_host = urlparse(item.findtext("url") or "").hostname or ""
        request_host = _host_header_hostname(_b64_decode(item.find("request")))

        # The <host> element is just a label; it is NOT cross-checked
        # against the item's own <url> or its request's Host: header by
        # the XML format itself. Require at least two of the three
        # sources to be present and for every present one to agree —
        # otherwise this item's real origin is ambiguous (or the label
        # was simply forged) and it must not be trusted under that name.
        # A genuine, unedited Burp "Save items" export always has all
        # three agree.
        present = [h for h in (declared_host, url_host, request_host) if h]
        if not declared_host or len(present) < 2 or len({h.lower() for h in present}) != 1:
            out_of_scope += 1
            continue
        host = declared_host
        if not scope.contains(host):
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
