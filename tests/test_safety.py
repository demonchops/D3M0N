import pytest

from d3m0n.safety import confirm_authorization, parse_scope


def test_assume_yes_confirms_without_prompt(capsys):
    scope = parse_scope("example.com")
    confirm_authorization(scope, assume_yes=True)  # should not raise
    out = capsys.readouterr().out
    assert "Authorization confirmed" in out


def test_declining_authorization_exits(monkeypatch):
    scope = parse_scope("example.com")
    monkeypatch.setattr("builtins.input", lambda _: "nope")
    with pytest.raises(SystemExit):
        confirm_authorization(scope)
