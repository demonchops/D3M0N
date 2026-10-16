"""subdomain_takeover_check: CNAME matching, fingerprint confirmation,
graceful DNS/HTTP failure, CNAME-loop protection, and redaction."""

import requests

import d3m0n.tools.takeover_check as takeover_mod
from d3m0n.config import Settings


class FakeAnswer:
    def __init__(self, target):
        self.target = target + "."  # dnspython targets are dot-terminated


def test_matches_known_service_and_fingerprint(monkeypatch):
    monkeypatch.setattr(takeover_mod, "SETTINGS", Settings(session_headers={}))
    monkeypatch.setattr(
        takeover_mod.dns.resolver,
        "resolve",
        lambda *a, **k: [FakeAnswer("old-project.github.io")],
    )

    class FakeResp:
        status_code = 404
        text = "<html>There isn't a GitHub Pages site here.</html>"

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = takeover_mod.subdomain_takeover_check("blog.example.com")

    assert result["matches_known_service"] is True
    assert result["service"] == "GitHub Pages"
    assert result["fingerprint_check"] == "matched"


def test_matches_service_but_fingerprint_not_matched_is_inconclusive(monkeypatch):
    monkeypatch.setattr(takeover_mod, "SETTINGS", Settings(session_headers={}))
    monkeypatch.setattr(
        takeover_mod.dns.resolver, "resolve", lambda *a, **k: [FakeAnswer("myapp.herokuapp.com")]
    )

    class FakeResp:
        status_code = 200
        text = "<html>Welcome to my live app!</html>"

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = takeover_mod.subdomain_takeover_check("app.example.com")

    assert result["matches_known_service"] is True
    assert result["fingerprint_check"] == "not_matched"
    # Must not read as "safe" -- it's explicitly inconclusive.
    assert "inconclusive" in result["note"]


def test_no_cname_match_for_unrelated_service(monkeypatch):
    monkeypatch.setattr(takeover_mod, "SETTINGS", Settings(session_headers={}))
    monkeypatch.setattr(
        takeover_mod.dns.resolver, "resolve", lambda *a, **k: [FakeAnswer("internal-lb.example.com")]
    )

    result = takeover_mod.subdomain_takeover_check("app.example.com")

    assert result["matches_known_service"] is False
    assert result["cname_chain"] == ["internal-lb.example.com"]


def test_dns_resolution_failure_handled_gracefully(monkeypatch):
    def fake_resolve(*a, **k):
        raise Exception("NXDOMAIN")

    monkeypatch.setattr(takeover_mod.dns.resolver, "resolve", fake_resolve)
    result = takeover_mod.subdomain_takeover_check("nonexistent.example.com")

    assert result["matches_known_service"] is False
    assert result["cname_chain"] == []


def test_cname_loop_does_not_hang(monkeypatch):
    # a -> b -> a -> b ... must terminate, not loop forever or exceed max_hops.
    responses = {"a.example.com": "b.example.com", "b.example.com": "a.example.com"}

    def fake_resolve(name, *a, **k):
        return [FakeAnswer(responses.get(name.rstrip("."), name))]

    monkeypatch.setattr(takeover_mod.dns.resolver, "resolve", fake_resolve)
    chain = takeover_mod._resolve_cname_chain("a.example.com")

    assert len(chain) <= takeover_mod._MAX_CNAME_HOPS
    # The loop-guard must actually have kicked in (not just the hop cap).
    assert len(chain) <= 2


def test_https_fails_falls_back_to_http(monkeypatch):
    monkeypatch.setattr(takeover_mod, "SETTINGS", Settings(session_headers={}))

    class FakeHttpResp:
        status_code = 404
        text = "NoSuchBucket"

    def fake_get(url, **kwargs):
        if url.startswith("https://"):
            raise requests.exceptions.SSLError("no valid cert")
        return FakeHttpResp()

    monkeypatch.setattr(requests, "get", fake_get)
    service = {"service": "AWS S3", "cname_contains": "s3.amazonaws.com", "body_fingerprint": "NoSuchBucket"}
    result = takeover_mod._check_fingerprint("bucket.example.com", service)

    assert result["fingerprint_check"] == "matched"


def test_both_schemes_fail_returns_error_not_exception(monkeypatch):
    monkeypatch.setattr(takeover_mod, "SETTINGS", Settings(session_headers={"Cookie": "s=SECRETZZZ"}))

    def fake_get(*a, **k):
        raise requests.ConnectionError("failed near s=SECRETZZZ")

    monkeypatch.setattr(requests, "get", fake_get)
    service = {"service": "Heroku", "cname_contains": "herokuapp.com", "body_fingerprint": "No such app"}
    result = takeover_mod._check_fingerprint("app.example.com", service)

    assert result["fingerprint_check"] == "error"
    assert "SECRETZZZ" not in result["error"]
    assert "REDACTED" in result["error"]
