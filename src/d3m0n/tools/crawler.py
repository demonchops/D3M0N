"""Bounded, in-scope, GET-only site crawler — discovers attack surface,
never submits forms, never returns raw page content.

Follows links/forms/script sources found in each fetched page's own HTML
(server-served, not model-composed) breadth-first, starting from one
model-given URL. Every discovered link is checked against scope before
being followed or reported — a link to an out-of-scope host is counted
and dropped, never fetched.

GET only; forms are reported (page, action, method) for further manual/
tool-based testing, never auto-submitted. Returns structured metadata
only (url/status/length/depth per page, discovered form and script
descriptors) — deliberately never raw body content, so this can't become
the kind of "fetch whatever, see the raw response" oracle an adversarial
review already found and closed in recon.py's http_probe. Bounded by
MAX_PAGES/MAX_DEPTH regardless of what's requested, and paced with a
small delay between requests, so this can't turn into a rapid-fire
scrape of a real target.
"""

from __future__ import annotations

import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from d3m0n.config import SETTINGS
from d3m0n.safety import Scope

MAX_PAGES = 50
MAX_DEPTH = 3
_CRAWL_DELAY_S = 0.3
_MAX_PARSE_CHARS = 2_000_000
_MAX_QUEUE = 500


class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag == "a" and attr_dict.get("href"):
            self.links.append(attr_dict["href"])
        elif tag == "form":
            self.forms.append(
                {
                    "action": attr_dict.get("action", ""),
                    "method": (attr_dict.get("method") or "GET").upper(),
                }
            )
        elif tag == "script" and attr_dict.get("src"):
            self.scripts.append(attr_dict["src"])


def _redact_sessions(text: str) -> str:
    secret_values = [v for v in SETTINGS.session_headers.values() if v]
    for value in secret_values:
        text = text.replace(value, "***REDACTED-SESSION-HEADER***")
    return text


def crawl_site(start_url: str, scope: Scope, max_pages: int = 20, max_depth: int = 2) -> dict:
    """BFS crawl within `scope`, starting from `start_url`. See module
    docstring for the safety properties — structured metadata only, GET
    only, forms reported never submitted, bounded and paced."""
    if not start_url.startswith(("http://", "https://")):
        start_url = "https://" + start_url

    max_pages = max(1, min(max_pages, MAX_PAGES))
    max_depth = max(0, min(max_depth, MAX_DEPTH))

    queue: list[tuple[str, int]] = [(start_url, 0)]
    queued = {start_url}
    visited: set[str] = set()
    pages = []
    forms_found = []
    scripts_found: set[str] = set()
    out_of_scope_skipped = 0

    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        if len(pages) > 0:
            time.sleep(_CRAWL_DELAY_S)

        try:
            resp = requests.get(
                url, timeout=10, allow_redirects=True, headers=SETTINGS.session_headers or None
            )
        except requests.RequestException as exc:
            pages.append({"url": url, "depth": depth, "error": _redact_sessions(str(exc))})
            continue

        content_type = resp.headers.get("Content-Type", "")
        body = resp.text
        pages.append({"url": url, "depth": depth, "status": resp.status_code, "length": len(body)})

        if depth >= max_depth or "html" not in content_type.lower():
            continue

        parser = _LinkExtractor()
        try:
            parser.feed(body[:_MAX_PARSE_CHARS])
        except Exception:  # noqa: BLE001 - a malformed page must never crash the crawl
            continue

        for href in parser.links:
            absolute = urljoin(url, href)
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https"):
                continue
            if not parsed.hostname or not scope.contains(parsed.hostname):
                out_of_scope_skipped += 1
                continue
            if absolute not in queued and len(queue) < _MAX_QUEUE:
                queued.add(absolute)
                queue.append((absolute, depth + 1))

        for form in parser.forms:
            action_url = urljoin(url, form["action"]) if form["action"] else url
            parsed = urlparse(action_url)
            if parsed.hostname and scope.contains(parsed.hostname):
                forms_found.append({"page": url, "action": action_url, "method": form["method"]})

        for src in parser.scripts:
            absolute = urljoin(url, src)
            parsed = urlparse(absolute)
            if parsed.hostname and scope.contains(parsed.hostname):
                scripts_found.add(absolute)

    return {
        "start_url": start_url,
        "pages_visited": len(pages),
        "pages": pages,
        "forms_found": forms_found,
        "scripts_found": sorted(scripts_found),
        "out_of_scope_links_skipped": out_of_scope_skipped,
        "truncated": len(queue) > 0,
    }
