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


def test_cookie_name_containing_flag_word_still_flagged(tmp_path):
    # A cookie literally NAMED "securetoken", with HttpOnly genuinely set
    # but Secure genuinely NOT set, isolates the bug: a raw substring
    # search finds "secure" in the NAME and wrongly concludes the Secure
    # ATTRIBUTE is present, and since HttpOnly really is there too, the
    # old `or`-based check had nothing left to catch it on.
    scope = parse_scope("example.com")
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Security-Policy: default-src 'self'\r\n"
        b"X-Frame-Options: DENY\r\n"
        b"Strict-Transport-Security: max-age=31536000\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"Set-Cookie: securetoken=abc123; Path=/; HttpOnly\r\n"
        b"\r\n<html>ok</html>"
    )
    export = _write_export(tmp_path, [_item("good.example.com", "/login", response)])

    result = burp_traffic_review(export, scope)

    assert result["items_flagged"] == 1
    assert any("Secure" in f for f in result["flagged"][0]["flags"])


def test_cookie_with_real_secure_httponly_attributes_not_flagged(tmp_path):
    scope = parse_scope("example.com")
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Security-Policy: default-src 'self'\r\n"
        b"X-Frame-Options: DENY\r\n"
        b"Strict-Transport-Security: max-age=31536000\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"Set-Cookie: session=abc123; Path=/; Secure; HttpOnly\r\n"
        b"\r\n<html>ok</html>"
    )
    export = _write_export(tmp_path, [_item("good.example.com", "/login", response)])

    result = burp_traffic_review(export, scope)
    assert result["items_flagged"] == 0


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


def test_doctype_rejected_before_parsing(tmp_path):
    # A genuine Burp export never has a DOCTYPE/ENTITY — guards against
    # XML entity-expansion ("billion laughs") DoS.
    scope = parse_scope("example.com")
    path = tmp_path / "evil.xml"
    path.write_text(
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE items [<!ENTITY lol \"lol\">]>\n"
        "<items><item><host>good.example.com</host></item></items>"
    )

    result = burp_traffic_review(str(path), scope)
    assert "error" in result
    assert "DOCTYPE" in result["error"]


def test_doctype_rejected_even_when_utf16_encoded(tmp_path):
    # A raw ASCII-literal byte search (b"<!DOCTYPE" in raw) never matches
    # UTF-16-encoded text -- every character becomes 2 bytes with
    # interleaved nulls -- even though expat auto-detects the BOM and
    # parses the DOCTYPE/ENTITY declaration underneath just fine. The
    # guard has to decode first.
    scope = parse_scope("example.com")
    path = tmp_path / "evil16.xml"
    xml_text = (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE items [<!ENTITY lol \"lol\">]>\n"
        "<items><item><host>good.example.com</host></item></items>"
    )
    path.write_bytes(xml_text.encode("utf-16"))  # adds a BOM

    result = burp_traffic_review(str(path), scope)
    assert "error" in result
    assert "DOCTYPE" in result["error"]


def test_doctype_rejected_even_when_utf16_le_no_bom(tmp_path):
    # Same bypass, but via the no-BOM UTF-16LE signature (XML 1.0
    # Appendix F) that expat also auto-detects.
    scope = parse_scope("example.com")
    path = tmp_path / "evil16le.xml"
    xml_text = (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        "<!DOCTYPE items [<!ENTITY lol \"lol\">]>\n"
        "<items><item><host>good.example.com</host></item></items>"
    )
    path.write_bytes(xml_text.encode("utf-16-le"))  # no BOM

    result = burp_traffic_review(str(path), scope)
    assert "error" in result
    assert "DOCTYPE" in result["error"]


def test_mismatched_host_label_excluded(tmp_path):
    # <host> claims an in-scope name, but the item's own <url> and the
    # embedded request's Host: header both say something else entirely.
    # The label alone must never be trusted as the item's real origin.
    scope = parse_scope("example.com")
    response = b"HTTP/1.1 200 OK\r\n\r\n<html>you searched for hello</html>"
    req_b64 = base64.b64encode(b"GET /search?q=hello HTTP/1.1\r\nHost: evil.net\r\n\r\n").decode()
    resp_b64 = base64.b64encode(response).decode()
    item_xml = f"""
    <item>
      <url>https://evil.net/search?q=hello</url>
      <host ip="1.2.3.4">good.example.com</host>
      <port>443</port>
      <method>GET</method>
      <path>/search?q=hello</path>
      <request base64="true">{req_b64}</request>
      <status>200</status>
      <response base64="true">{resp_b64}</response>
    </item>
    """
    export = _write_export(tmp_path, [item_xml])

    result = burp_traffic_review(export, scope)

    assert result["items_total"] == 1
    assert result["items_out_of_scope"] == 1
    assert result["items_flagged"] == 0
    assert all(f["host"] != "good.example.com" for f in result["flagged"])


def test_flags_missing_headers_with_lf_only_line_endings(tmp_path):
    # The header/body split used to assume strict "\r\n\r\n" separation.
    # On an LF-only response, that split silently finds no match, so
    # header_block falls back to the ENTIRE response text (headers *and*
    # body) -- a false negative whenever the body happens to mention a
    # header name that is genuinely missing, e.g. a debug/echo page that
    # reflects request headers back.
    scope = parse_scope("example.com")
    response = (
        b"HTTP/1.1 200 OK\n"
        b"Content-Type: text/html\n"
        b"\n"
        b"<html>You searched for hello. Echoing headers: X-Frame-Options</html>"
    )
    export = _write_export(tmp_path, [_item("good.example.com", "/search?q=hello", response)])

    result = burp_traffic_review(export, scope)

    assert result["items_total"] == 1
    assert result["items_flagged"] == 1
    flags = result["flagged"][0]["flags"]
    assert any("x-frame-options" in f for f in flags)
    assert any("reflected verbatim" in f for f in flags)
