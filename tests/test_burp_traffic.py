"""burp_traffic_review() against synthetic Burp 'Save items' XML exports —
no live Burp needed, and no network access either."""

import base64

from d3m0n.safety import parse_scope
from d3m0n.tools.burp_traffic import burp_traffic_review


def _item(host, path, response_bytes, method="GET"):
    req_b64 = base64.b64encode(f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()).decode()
    resp_b64 = base64.b64encode(response_bytes).decode()
    return f"""
    <item>
      <url>https://{host}{path}</url>
      <host ip="1.2.3.4">{host}</host>
      <port>443</port>
      <method>{method}</method>
      <path>{path}</path>
      <request base64="true">{req_b64}</request>
      <status>200</status>
      <response base64="true">{resp_b64}</response>
    </item>
    """


def _write_export(tmp_path, items_xml):
    path = tmp_path / "export.xml"
    path.write_text(f'<?xml version="1.0"?>\n<items burpVersion="test">{"".join(items_xml)}</items>')
    return str(path)


def test_flags_missing_headers_and_reflected_param(tmp_path):
    scope = parse_scope("example.com")
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>You searched for hello</html>"
    )
    export = _write_export(
        tmp_path, [_item("good.example.com", "/search?q=hello", response)]
    )

    result = burp_traffic_review(export, scope)

    assert result["items_total"] == 1
    assert result["items_out_of_scope"] == 0
    assert result["items_flagged"] == 1
    flags = result["flagged"][0]["flags"]
    assert any("content-security-policy" in f for f in flags)
    assert any("reflected verbatim" in f for f in flags)


def test_clean_response_not_flagged(tmp_path):
    scope = parse_scope("example.com")
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Security-Policy: default-src 'self'\r\n"
        b"X-Frame-Options: DENY\r\n"
        b"Strict-Transport-Security: max-age=31536000\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"\r\n<html>nothing interesting here</html>"
    )
    export = _write_export(tmp_path, [_item("clean.example.com", "/", response)])

    result = burp_traffic_review(export, scope)

    assert result["items_total"] == 1
    assert result["items_flagged"] == 0
    assert result["flagged"] == []


def test_out_of_scope_host_excluded(tmp_path):
    scope = parse_scope("example.com")
    # This response would absolutely be flagged if it were in scope — the
    # point is that it must never show up because the host isn't in scope.
    response = b"HTTP/1.1 200 OK\r\n\r\n<html>you searched for hello</html>"
    export = _write_export(
        tmp_path,
        [
            _item("good.example.com", "/search?q=hello", response),
            _item("notinscope.com", "/search?q=hello", response),
        ],
    )

    result = burp_traffic_review(export, scope)

    assert result["items_total"] == 2
    assert result["items_out_of_scope"] == 1
    assert all(f["host"] != "notinscope.com" for f in result["flagged"])


def test_cookie_missing_secure_httponly_flagged(tmp_path):
    scope = parse_scope("example.com")
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Security-Policy: default-src 'self'\r\n"
        b"X-Frame-Options: DENY\r\n"
        b"Strict-Transport-Security: max-age=31536000\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"Set-Cookie: session=abc123; Path=/\r\n"
        b"\r\n<html>ok</html>"
    )
    export = _write_export(tmp_path, [_item("good.example.com", "/login", response)])

    result = burp_traffic_review(export, scope)

    assert result["items_flagged"] == 1
    assert any("Secure" in f for f in result["flagged"][0]["flags"])


def test_malformed_file_returns_error_not_exception(tmp_path):
    scope = parse_scope("example.com")
    path = tmp_path / "bad.xml"
    path.write_text("not even xml {{{")

    result = burp_traffic_review(str(path), scope)
    assert "error" in result


def test_missing_file_returns_error_not_exception(tmp_path):
    scope = parse_scope("example.com")
    result = burp_traffic_review(str(tmp_path / "nope.xml"), scope)
    assert "error" in result
