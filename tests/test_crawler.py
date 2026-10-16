"""crawl_site: link/form/script extraction, scope filtering, bounds, and
that it never issues anything but a GET (forms are reported, never
submitted)."""

import requests

import d3m0n.tools.crawler as crawler_mod
from d3m0n.safety import parse_scope


class FakeResp:
    def __init__(self, text="", status=200, content_type="text/html"):
        self.text = text
        self.status_code = status
        self.headers = {"Content-Type": content_type}


def test_discovers_in_scope_links_and_skips_out_of_scope(monkeypatch):
    monkeypatch.setattr(crawler_mod.time, "sleep", lambda *_: None)
    scope = parse_scope("example.com")

    pages = {
        "https://example.com/": FakeResp(
            '<html><a href="/about">About</a>'
            '<a href="https://evil.com/x">Evil</a>'
            '<a href="https://sub.example.com/deep">Deep</a></html>'
        ),
        "https://example.com/about": FakeResp("<html>about page</html>"),
        "https://sub.example.com/deep": FakeResp("<html>deep page</html>"),
    }

    def fake_get(url, **kwargs):
        return pages.get(url, FakeResp(status=404))

    monkeypatch.setattr(requests, "get", fake_get)
    result = crawler_mod.crawl_site("https://example.com/", scope, max_pages=10, max_depth=2)

    visited_urls = {p["url"] for p in result["pages"]}
    assert "https://example.com/about" in visited_urls
    assert "https://sub.example.com/deep" in visited_urls
    assert all("evil.com" not in p["url"] for p in result["pages"])
    assert result["out_of_scope_links_skipped"] >= 1


def test_forms_reported_never_submitted(monkeypatch):
    monkeypatch.setattr(crawler_mod.time, "sleep", lambda *_: None)
    scope = parse_scope("example.com")

    def fake_get(url, **kwargs):
        if url == "https://example.com/":
            return FakeResp('<html><form action="/login" method="POST"></form></html>')
        return FakeResp("<html>login page</html>")

    def fail_post(*a, **k):
        raise AssertionError("crawl_site must never issue a POST")

    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(requests, "post", fail_post)

    result = crawler_mod.crawl_site("https://example.com/", scope, max_pages=5, max_depth=1)

    assert any(f["action"] == "https://example.com/login" for f in result["forms_found"])
    assert all(f["method"] == "POST" for f in result["forms_found"])


def test_scripts_discovered(monkeypatch):
    monkeypatch.setattr(crawler_mod.time, "sleep", lambda *_: None)
    scope = parse_scope("example.com")

    def fake_get(url, **kwargs):
        return FakeResp('<html><script src="/static/app.js"></script></html>')

    monkeypatch.setattr(requests, "get", fake_get)
    result = crawler_mod.crawl_site("https://example.com/", scope, max_pages=1, max_depth=1)

    assert "https://example.com/static/app.js" in result["scripts_found"]


def test_max_pages_and_depth_are_clamped(monkeypatch):
    monkeypatch.setattr(crawler_mod.time, "sleep", lambda *_: None)
    scope = parse_scope("example.com")
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp("<html></html>"))

    # Requesting absurd values must not be honored verbatim.
    result = crawler_mod.crawl_site(
        "https://example.com/", scope, max_pages=10_000, max_depth=10_000
    )
    assert result["pages_visited"] <= crawler_mod.MAX_PAGES


def test_malformed_href_does_not_crash_the_whole_crawl(monkeypatch):
    # urljoin()/urlparse() raise ValueError on a malformed bracketed host
    # (e.g. an unmatched "[") instead of just failing to parse one -- a
    # single bad link anywhere on any page visited must not crash the
    # whole crawl (and, upstream, the whole agent run) over it. Same
    # lesson an earlier adversarial review already taught safety.py's own
    # urlparse call, reapplied here after it resurfaced in a new tool.
    monkeypatch.setattr(crawler_mod.time, "sleep", lambda *_: None)
    scope = parse_scope("example.com")

    def fake_get(url, **kwargs):
        if url.endswith("/fine"):
            return FakeResp("<html>fine page</html>")
        return FakeResp('<html><a href="http://[notclosed/path">bad</a><a href="/fine">ok</a></html>')

    monkeypatch.setattr(requests, "get", fake_get)
    result = crawler_mod.crawl_site("https://example.com/", scope, max_pages=5, max_depth=2)

    assert result["malformed_links_skipped"] >= 1
    assert any(p["url"] == "https://example.com/fine" for p in result["pages"])


def test_malformed_form_action_and_script_src_do_not_crash(monkeypatch):
    monkeypatch.setattr(crawler_mod.time, "sleep", lambda *_: None)
    scope = parse_scope("example.com")

    def fake_get(url, **kwargs):
        return FakeResp(
            '<html><form action="http://[bad-form" method="POST"></form>'
            '<script src="http://[bad-script"></script></html>'
        )

    monkeypatch.setattr(requests, "get", fake_get)
    result = crawler_mod.crawl_site("https://example.com/", scope, max_pages=1, max_depth=1)

    assert result["pages_visited"] == 1
    assert result["forms_found"] == []
    assert result["scripts_found"] == []
    assert result["malformed_links_skipped"] == 2


def test_non_html_content_type_not_parsed_for_links(monkeypatch):
    monkeypatch.setattr(crawler_mod.time, "sleep", lambda *_: None)
    scope = parse_scope("example.com")

    def fake_get(url, **kwargs):
        return FakeResp('<a href="/should-not-be-followed">x</a>', content_type="application/pdf")

    monkeypatch.setattr(requests, "get", fake_get)
    result = crawler_mod.crawl_site("https://example.com/doc.pdf", scope, max_pages=5, max_depth=2)

    assert result["pages_visited"] == 1  # nothing queued from a non-HTML response


def test_malformed_html_does_not_crash(monkeypatch):
    monkeypatch.setattr(crawler_mod.time, "sleep", lambda *_: None)
    scope = parse_scope("example.com")
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp("<html><a href=unterminated")
    )

    result = crawler_mod.crawl_site("https://example.com/", scope, max_pages=3, max_depth=1)
    assert result["pages_visited"] == 1


def test_connection_failure_redacts_session_values(monkeypatch):
    from d3m0n.config import Settings

    monkeypatch.setattr(crawler_mod.time, "sleep", lambda *_: None)
    monkeypatch.setattr(
        crawler_mod, "SETTINGS", Settings(session_headers={"Cookie": "session=SECRET123"})
    )
    scope = parse_scope("example.com")

    def fake_get(*a, **k):
        raise requests.ConnectionError("failed near session=SECRET123")

    monkeypatch.setattr(requests, "get", fake_get)
    result = crawler_mod.crawl_site("https://example.com/", scope)

    assert "SECRET123" not in repr(result)
    assert "REDACTED" in result["pages"][0]["error"]
