"""policy.py: PolicyEngine's tool-whitelist/scope gating, and the
consolidated secret-redaction pass over the agent's own summary text."""

import pytest

from d3m0n.config import Settings
from d3m0n.policy import PolicyEngine, redact_known_secrets
from d3m0n.safety import OutOfScopeError, parse_scope


def _engine(allowed_tools=None):
    scope = parse_scope("example.com")
    return PolicyEngine(scope, known_tools=frozenset({"dns_lookup", "http_probe"}), allowed_tools=allowed_tools)


# --- tool_allowed ---


def test_known_tool_allowed_by_default():
    assert _engine().tool_allowed("dns_lookup") is True


def test_unknown_tool_not_allowed():
    assert _engine().tool_allowed("shell_exec") is False


def test_further_restriction_excludes_known_but_unlisted_tool():
    engine = _engine(allowed_tools=frozenset({"dns_lookup"}))
    assert engine.tool_allowed("dns_lookup") is True
    assert engine.tool_allowed("http_probe") is False


def test_empty_allowed_tools_means_nothing_is_allowed():
    # None means "no further restriction"; an empty set is a real,
    # different thing -- nothing passes, not "no restriction".
    engine = _engine(allowed_tools=frozenset())
    assert engine.tool_allowed("dns_lookup") is False


# --- check_scope ---


def test_check_scope_passes_for_in_scope_target():
    _engine().check_scope("sub.example.com")  # must not raise


def test_check_scope_raises_for_out_of_scope_target():
    with pytest.raises(OutOfScopeError):
        _engine().check_scope("evil.com")


# --- redact_known_secrets ---


def test_redacts_session_headers_both_accounts(monkeypatch):
    monkeypatch.setattr(
        "d3m0n.policy.SETTINGS",
        Settings(
            session_headers={"Cookie": "sid=ALICE-SECRET"},
            session_headers_b={"Cookie": "sid=BOB-SECRET"},
        ),
    )
    text = redact_known_secrets("saw sid=ALICE-SECRET and sid=BOB-SECRET in the response")
    assert "ALICE-SECRET" not in text
    assert "BOB-SECRET" not in text
    assert "REDACTED" in text


def test_redacts_burp_credentials(monkeypatch):
    monkeypatch.setattr(
        "d3m0n.policy.SETTINGS",
        Settings(
            burp_api_key="BURP-KEY-999",
            burp_login_username="alice@example.com",
            burp_login_password="Tr0ub4dor&3",
        ),
    )
    text = redact_known_secrets(
        "used key BURP-KEY-999 to log in as alice@example.com with Tr0ub4dor&3"
    )
    assert "BURP-KEY-999" not in text
    assert "alice@example.com" not in text
    assert "Tr0ub4dor&3" not in text


def test_redacts_model_api_keys(monkeypatch):
    monkeypatch.setattr(
        "d3m0n.policy.SETTINGS",
        Settings(anthropic_api_key="sk-ant-REALSECRET", local_model_api_key="local-REALSECRET"),
    )
    text = redact_known_secrets("sk-ant-REALSECRET and local-REALSECRET appeared")
    assert "REALSECRET" not in text


def test_clean_text_unchanged_when_nothing_configured(monkeypatch):
    monkeypatch.setattr("d3m0n.policy.SETTINGS", Settings())
    text = redact_known_secrets("nothing sensitive here")
    assert text == "nothing sensitive here"


def test_none_and_empty_text_do_not_raise():
    assert redact_known_secrets(None) == ""
    assert redact_known_secrets("") == ""
