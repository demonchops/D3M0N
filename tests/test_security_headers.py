"""security_headers_check: header/cookie findings, the clickjacking
verdict, and credential redaction -- fully mocked, no live target needed."""

import requests

import d3m0n.tools.security_headers as sh_mod
from d3m0n.config import Settings


class FakeRawHeaders:
    def __init__(self, set_cookie_list):
        self._set_cookie_list = set_cookie_list

    def getlist(self, key):
        return self._set_cookie_list if key == "Set-Cookie" else []


class FakeRaw:
    def __init__(self, set_cookie_list):
        self.headers = FakeRawHeaders(set_cookie_list)


class FakeResp:
    def __init__(self, headers=None, status_code=200, set_cookies=None):
        self.headers = headers or {}
        self.status_code = status_code
        self.raw = FakeRaw(set_cookies or [])


def _finding_types(result):
    return {(f["header"], f["finding"]) for f in result["findings"] if "header" in f}


# --- scheme ---


def test_plain_http_flagged(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = sh_mod.security_headers_check("http://example.com")
    assert ("(scheme)", "plaintext_http") in _finding_types(result)
    assert result["is_https"] is False


def test_https_no_scheme_finding(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(
            headers={"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'"}
        ),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert ("(scheme)", "plaintext_http") not in _finding_types(result)


# --- HSTS ---


def test_hsts_missing_over_https(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = sh_mod.security_headers_check("https://example.com")
    assert ("Strict-Transport-Security", "missing") in _finding_types(result)


def test_hsts_not_evaluated_over_http(monkeypatch):
    # Missing HSTS over plain HTTP would be redundant with the scheme
    # finding -- HSTS itself isn't meaningful to assess there.
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = sh_mod.security_headers_check("http://example.com")
    assert ("Strict-Transport-Security", "missing") not in _finding_types(result)


def test_hsts_short_max_age_flagged_weak(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(headers={"Strict-Transport-Security": "max-age=60"}),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert ("Strict-Transport-Security", "weak") in _finding_types(result)


def test_hsts_malformed_no_max_age(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(headers={"Strict-Transport-Security": "includeSubDomains"}),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert ("Strict-Transport-Security", "malformed") in _finding_types(result)


def test_hsts_long_max_age_no_finding(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(headers={"Strict-Transport-Security": "max-age=31536000"}),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert all(f.get("header") != "Strict-Transport-Security" for f in result["findings"])


# --- CSP ---


def test_csp_missing(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = sh_mod.security_headers_check("https://example.com")
    assert ("Content-Security-Policy", "missing") in _finding_types(result)


def test_csp_unsafe_inline_flagged(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(
            headers={"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"}
        ),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert ("Content-Security-Policy", "weak_directive") in _finding_types(result)


def test_csp_wildcard_script_src_flagged(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(headers={"Content-Security-Policy": "script-src *"}),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert ("Content-Security-Policy", "wildcard_script_source") in _finding_types(result)


def test_csp_wildcard_on_img_src_not_flagged(monkeypatch):
    # A wildcard on img-src is routine and not the risky case this checks for.
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(
            headers={"Content-Security-Policy": "default-src 'self'; img-src *"}
        ),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert ("Content-Security-Policy", "wildcard_script_source") not in _finding_types(result)


def test_csp_strict_policy_no_findings(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(headers={"Content-Security-Policy": "default-src 'self'"}),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert all(f.get("header") != "Content-Security-Policy" for f in result["findings"])


# --- X-Content-Type-Options ---


def test_nosniff_missing(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = sh_mod.security_headers_check("https://example.com")
    assert ("X-Content-Type-Options", "missing") in _finding_types(result)


def test_nosniff_present_no_finding(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(headers={"X-Content-Type-Options": "nosniff"}),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert all(f.get("header") != "X-Content-Type-Options" for f in result["findings"])


def test_nosniff_invalid_value(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(headers={"X-Content-Type-Options": "sniff-away"}),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert ("X-Content-Type-Options", "invalid_value") in _finding_types(result)


# --- clickjacking ---


def test_clickjacking_no_protection(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = sh_mod.security_headers_check("https://example.com")
    assert result["clickjacking"] == {"likely_frameable": True, "protected_by": None}
    assert ("X-Frame-Options", "missing") in _finding_types(result)


def test_clickjacking_protected_by_xfo_deny(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp(headers={"X-Frame-Options": "DENY"})
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert result["clickjacking"] == {"likely_frameable": False, "protected_by": "x-frame-options"}
    assert ("X-Frame-Options", "missing") not in _finding_types(result)


def test_clickjacking_protected_by_csp_frame_ancestors_even_without_xfo(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(
            headers={"Content-Security-Policy": "frame-ancestors 'self'"}
        ),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert result["clickjacking"] == {
        "likely_frameable": False,
        "protected_by": "csp-frame-ancestors",
    }


def test_clickjacking_allow_from_flagged_unsupported(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(
            headers={"X-Frame-Options": "ALLOW-FROM https://partner.example"}
        ),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert result["clickjacking"]["likely_frameable"] is True
    assert ("X-Frame-Options", "unsupported_value") in _finding_types(result)


def test_clickjacking_invalid_xfo_value(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp(headers={"X-Frame-Options": "banana"})
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert ("X-Frame-Options", "invalid_value") in _finding_types(result)


# --- Referrer-Policy / Permissions-Policy ---


def test_referrer_policy_missing_is_info(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = sh_mod.security_headers_check("https://example.com")
    finding = next(f for f in result["findings"] if f.get("header") == "Referrer-Policy")
    assert finding["severity"] == "info"


def test_referrer_policy_unsafe_url_flagged_weak(monkeypatch):
    monkeypatch.setattr(
        requests, "get", lambda *a, **k: FakeResp(headers={"Referrer-Policy": "unsafe-url"})
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert ("Referrer-Policy", "weak") in _finding_types(result)


def test_referrer_policy_good_value_no_finding(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(headers={"Referrer-Policy": "strict-origin-when-cross-origin"}),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert all(f.get("header") != "Referrer-Policy" for f in result["findings"])


def test_permissions_policy_missing_is_info(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = sh_mod.security_headers_check("https://example.com")
    finding = next(f for f in result["findings"] if f.get("header") == "Permissions-Policy")
    assert finding["severity"] == "info"


# --- cookies ---


def test_cookie_missing_all_attributes(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(set_cookies=["sessionid=abc123; Path=/"]),
    )
    result = sh_mod.security_headers_check("https://example.com")
    cookie_findings = [f for f in result["findings"] if "cookie_name" in f]
    assert len(cookie_findings) == 1
    assert cookie_findings[0]["cookie_name"] == "sessionid"
    assert set(cookie_findings[0]["missing_attributes"]) == {"Secure", "HttpOnly", "SameSite"}
    assert cookie_findings[0]["severity"] == "medium"


def test_cookie_name_containing_flag_word_not_false_negative(monkeypatch):
    # "secure_session" as a COOKIE NAME must not make the check think the
    # Secure ATTRIBUTE is present -- that's exactly the substring-match
    # trap this parsing avoids.
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(set_cookies=["secure_session=abc123; Path=/"]),
    )
    result = sh_mod.security_headers_check("https://example.com")
    cookie_findings = [f for f in result["findings"] if "cookie_name" in f]
    assert cookie_findings[0]["cookie_name"] == "secure_session"
    assert "Secure" in cookie_findings[0]["missing_attributes"]


def test_cookie_with_all_attributes_no_finding(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(
            set_cookies=["sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"]
        ),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert [f for f in result["findings"] if "cookie_name" in f] == []


def test_multiple_set_cookie_headers_each_checked(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(
            set_cookies=[
                "a=1; Secure; HttpOnly; SameSite=Strict",
                "b=2; Path=/",
            ]
        ),
    )
    result = sh_mod.security_headers_check("https://example.com")
    cookie_findings = [f for f in result["findings"] if "cookie_name" in f]
    assert len(cookie_findings) == 1
    assert cookie_findings[0]["cookie_name"] == "b"


def test_set_cookie_fallback_when_raw_headers_unavailable(monkeypatch):
    class NoRawResp:
        headers = {"Set-Cookie": "sessionid=abc123; Path=/"}
        status_code = 200

    monkeypatch.setattr(requests, "get", lambda *a, **k: NoRawResp())
    result = sh_mod.security_headers_check("https://example.com")
    cookie_findings = [f for f in result["findings"] if "cookie_name" in f]
    assert len(cookie_findings) == 1
    assert cookie_findings[0]["cookie_name"] == "sessionid"


def test_no_cookies_no_cookie_findings(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResp())
    result = sh_mod.security_headers_check("https://example.com")
    assert [f for f in result["findings"] if "cookie_name" in f] == []


# --- fully-hardened site: no findings at all ---


def test_fully_hardened_site_has_no_findings(monkeypatch):
    monkeypatch.setattr(
        requests,
        "get",
        lambda *a, **k: FakeResp(
            headers={
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            },
            set_cookies=["sessionid=abc; Secure; HttpOnly; SameSite=Strict"],
        ),
    )
    result = sh_mod.security_headers_check("https://example.com")
    assert result["finding_count"] == 0
    assert result["clickjacking"] == {
        "likely_frameable": False,
        "protected_by": "csp-frame-ancestors",
    }


# --- errors / redaction ---


def test_connection_failure_returns_clear_error(monkeypatch):
    def fake_get(*a, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "get", fake_get)
    result = sh_mod.security_headers_check("https://example.com")
    assert "error" in result


def test_connection_failure_redacts_session_values(monkeypatch):
    monkeypatch.setattr(sh_mod, "SETTINGS", Settings(session_headers={"Cookie": "s=SECRET999"}))

    def fake_get(*a, **k):
        raise requests.ConnectionError("failed near s=SECRET999")

    monkeypatch.setattr(requests, "get", fake_get)
    result = sh_mod.security_headers_check("https://example.com")
    assert "SECRET999" not in result["error"]
    assert "REDACTED" in result["error"]


def test_url_without_scheme_defaults_to_https(monkeypatch):
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        return FakeResp()

    monkeypatch.setattr(requests, "get", fake_get)
    sh_mod.security_headers_check("example.com")
    assert captured["url"] == "https://example.com"
