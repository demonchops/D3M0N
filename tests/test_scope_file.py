import json

import pytest

from d3m0n.safety import ScopeFileError, load_scope_file


def _write(tmp_path, data):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(data))
    return str(path)


def test_valid_scope_file_loads(tmp_path):
    path = _write(
        tmp_path,
        {
            "program": "Test Program",
            "scope": "example.com",
            "authorized": True,
            "confirmed_by": "tester",
            "confirmed_at": "2026-01-01",
        },
    )
    scope, meta = load_scope_file(path)
    assert scope.contains("api.example.com")
    assert meta["confirmed_by"] == "tester"
    assert meta["program"] == "Test Program"


def test_not_authorized_true_rejected(tmp_path):
    path = _write(
        tmp_path, {"scope": "example.com", "authorized": False, "confirmed_by": "tester"}
    )
    with pytest.raises(ScopeFileError, match="authorized"):
        load_scope_file(path)


def test_authorized_string_not_accepted(tmp_path):
    # "authorized": "true" (a string, not a bool) must not sneak past the check.
    path = _write(
        tmp_path, {"scope": "example.com", "authorized": "true", "confirmed_by": "tester"}
    )
    with pytest.raises(ScopeFileError, match="authorized"):
        load_scope_file(path)


def test_missing_confirmed_by_rejected(tmp_path):
    path = _write(tmp_path, {"scope": "example.com", "authorized": True})
    with pytest.raises(ScopeFileError, match="confirmed_by"):
        load_scope_file(path)


def test_missing_scope_rejected(tmp_path):
    path = _write(tmp_path, {"authorized": True, "confirmed_by": "tester"})
    with pytest.raises(ScopeFileError, match="scope"):
        load_scope_file(path)


def test_missing_file_rejected(tmp_path):
    with pytest.raises(ScopeFileError, match="not found"):
        load_scope_file(str(tmp_path / "nope.json"))


def test_invalid_json_rejected(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text("{not valid json")
    with pytest.raises(ScopeFileError, match="not valid JSON"):
        load_scope_file(str(path))


def test_example_file_is_not_authorized():
    # The committed template must fail safe if someone runs it unedited.
    with pytest.raises(ScopeFileError, match="authorized"):
        load_scope_file("scope.example.json")
