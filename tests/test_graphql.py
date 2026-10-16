"""graphql_introspect: enabled/disabled detection, bad responses, redaction."""

import requests

import d3m0n.tools.graphql as gql_mod
from d3m0n.config import Settings


class FakeResp:
    def __init__(self, json_data=None, status=200):
        self._json_data = json_data
        self.status_code = status

    def json(self):
        if self._json_data is None:
            raise ValueError("no body")
        return self._json_data


def test_introspection_enabled_parses_schema(monkeypatch):
    schema = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {"name": "User", "kind": "OBJECT", "fields": []},
                    {"name": "__Type", "kind": "OBJECT", "fields": []},
                    {"name": "Order", "kind": "OBJECT", "fields": []},
                ],
            }
        }
    }
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResp(json_data=schema))

    result = gql_mod.graphql_introspect("https://example.com/graphql")

    assert result["introspection_enabled"] is True
    assert result["query_type"] == "Query"
    assert result["mutation_type"] == "Mutation"
    # __Type (dunder-prefixed, a meta-type) must be excluded from the count.
    assert result["type_count"] == 2
    assert "User" in result["type_names"]
    assert "__Type" not in result["type_names"]


def test_introspection_disabled_no_schema_key(monkeypatch):
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: FakeResp(json_data={"errors": [{"message": "no"}]})
    )
    result = gql_mod.graphql_introspect("https://example.com/graphql")
    assert result["introspection_enabled"] is False


def test_non_200_status(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResp(status=404))
    result = gql_mod.graphql_introspect("https://example.com/graphql")
    assert result["introspection_enabled"] is False
    assert result["status"] == 404


def test_non_json_body(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResp(json_data=None))
    result = gql_mod.graphql_introspect("https://example.com/graphql")
    assert result["introspection_enabled"] is False


def test_connection_failure_redacts_session_values(monkeypatch):
    monkeypatch.setattr(gql_mod, "SETTINGS", Settings(session_headers={"Cookie": "s=SECRETXYZ"}))

    def fake_post(*a, **k):
        raise requests.ConnectionError("failed near s=SECRETXYZ")

    monkeypatch.setattr(requests, "post", fake_post)
    result = gql_mod.graphql_introspect("https://example.com/graphql")

    assert "SECRETXYZ" not in result["error"]
    assert "REDACTED" in result["error"]
