"""run_tool() dispatch: scope enforcement happens before dispatch, and a
stray key in model-supplied tool_input must never crash the dispatch call
itself."""

import pytest

import d3m0n.tools.registry as registry_mod
from d3m0n.safety import OutOfScopeError, parse_scope
from d3m0n.tools.registry import run_tool


def test_missing_target_returns_error():
    scope = parse_scope("example.com")
    result = run_tool("dns_lookup", {}, scope)
    assert "error" in result


def test_out_of_scope_raises():
    scope = parse_scope("example.com")
    with pytest.raises(OutOfScopeError):
        run_tool("dns_lookup", {"target": "evil.com"}, scope)


def test_stray_scope_key_in_tool_input_does_not_crash_dispatch(monkeypatch):
    # tool_input is model-controlled JSON, never validated against the
    # declared schema on this side. None of the schemas list "scope" as a
    # property, but a literal "scope" key in tool_input used to collide
    # with the scope=scope keyword every dispatch lambda receives, raising
    # TypeError at the call site itself -- before dns_lookup ever ran, and
    # uncaught all the way out of the agent run.
    monkeypatch.setattr(
        registry_mod, "dns_lookup", lambda target: {"hostname": target, "records": {}}
    )
    scope = parse_scope("example.com")
    result = run_tool("dns_lookup", {"target": "example.com", "scope": "x"}, scope)
    assert result == {"hostname": "example.com", "records": {}}


def test_idor_check_dispatch_forwards_method_body_content_type(monkeypatch):
    captured = {}

    def fake_idor_check(target, enumerate_range, method, body, content_type):
        captured.update(
            target=target,
            enumerate_range=enumerate_range,
            method=method,
            body=body,
            content_type=content_type,
        )
        return {"ok": True}

    monkeypatch.setattr(registry_mod, "idor_check", fake_idor_check)
    scope = parse_scope("example.com")
    result = run_tool(
        "idor_check",
        {
            "target": "https://example.com/api/orders/1",
            "method": "PATCH",
            "body": '{"status": "shipped"}',
            "content_type": "application/json",
        },
        scope,
    )

    assert result == {"ok": True}
    assert captured == {
        "target": "https://example.com/api/orders/1",
        "enumerate_range": 0,
        "method": "PATCH",
        "body": '{"status": "shipped"}',
        "content_type": "application/json",
    }
