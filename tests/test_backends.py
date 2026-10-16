"""agent/backends.py: the Anthropic<->OpenAI translation layer, and
OpenAICompatibleClient's full round trip, fully mocked (no real server
needed)."""

import json

import pytest
import requests

import d3m0n.agent.backends as backends_mod
from d3m0n.agent.backends import (
    Block,
    OpenAICompatibleClient,
    _from_openai_response,
    _to_openai_messages,
    _to_openai_system,
    _to_openai_tools,
)


def test_block_attribute_access_and_model_dump():
    b = Block(type="tool_use", id="x1", name="dns_lookup", input={"target": "example.com"})
    assert b.type == "tool_use"
    assert b.name == "dns_lookup"
    assert b.input == {"target": "example.com"}
    assert b.model_dump() == {
        "type": "tool_use",
        "id": "x1",
        "name": "dns_lookup",
        "input": {"target": "example.com"},
    }


def test_to_openai_system_string_passthrough():
    assert _to_openai_system("plain system prompt") == "plain system prompt"


def test_to_openai_system_extracts_anthropic_blocks():
    blocks = [{"type": "text", "text": "hello", "cache_control": {"type": "ephemeral"}}]
    assert _to_openai_system(blocks) == "hello"


def test_to_openai_tools_strips_cache_control():
    anthropic_tools = [
        {
            "name": "dns_lookup",
            "description": "Resolve records",
            "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}},
            "cache_control": {"type": "ephemeral"},
        }
    ]
    result = _to_openai_tools(anthropic_tools)
    assert result == [
        {
            "type": "function",
            "function": {
                "name": "dns_lookup",
                "description": "Resolve records",
                "parameters": {"type": "object", "properties": {"target": {"type": "string"}}},
            },
        }
    ]


def test_to_openai_messages_string_content_passthrough():
    messages = [{"role": "user", "content": "Objective: test"}]
    assert _to_openai_messages(messages) == [{"role": "user", "content": "Objective: test"}]


def test_to_openai_messages_assistant_with_tool_calls():
    messages = [
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Let me check."},
                {"type": "tool_use", "id": "call_1", "name": "dns_lookup", "input": {"target": "x.com"}},
            ],
        }
    ]
    result = _to_openai_messages(messages)
    assert len(result) == 1
    assert result[0]["role"] == "assistant"
    assert result[0]["content"] == "Let me check."
    assert result[0]["tool_calls"] == [
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "dns_lookup", "arguments": json.dumps({"target": "x.com"})},
        }
    ]


def test_to_openai_messages_multiple_tool_results_become_separate_messages():
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "call_1", "content": "result 1"},
                {"type": "tool_result", "tool_use_id": "call_2", "content": "result 2"},
            ],
        }
    ]
    result = _to_openai_messages(messages)
    assert result == [
        {"role": "tool", "tool_call_id": "call_1", "content": "result 1"},
        {"role": "tool", "tool_call_id": "call_2", "content": "result 2"},
    ]


def test_to_openai_messages_user_text_block():
    messages = [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
    assert _to_openai_messages(messages) == [{"role": "user", "content": "hello"}]


def test_from_openai_response_text_only():
    data = {"choices": [{"message": {"content": "just thinking out loud", "tool_calls": None}}]}
    blocks = _from_openai_response(data)
    assert len(blocks) == 1
    assert blocks[0].type == "text"
    assert blocks[0].text == "just thinking out loud"


def test_from_openai_response_with_tool_calls():
    data = {
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_abc",
                            "function": {"name": "dns_lookup", "arguments": '{"target": "x.com"}'},
                        }
                    ],
                }
            }
        ]
    }
    blocks = _from_openai_response(data)
    assert len(blocks) == 1
    assert blocks[0].type == "tool_use"
    assert blocks[0].id == "call_abc"
    assert blocks[0].name == "dns_lookup"
    assert blocks[0].input == {"target": "x.com"}


def test_from_openai_response_malformed_tool_arguments_does_not_crash():
    data = {
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [{"id": "c1", "function": {"name": "dns_lookup", "arguments": "{not json"}}],
                }
            }
        ]
    }
    blocks = _from_openai_response(data)
    assert blocks[0].input == {}


def test_from_openai_response_missing_choices_raises_clear_error():
    with pytest.raises(RuntimeError, match="unexpected response shape"):
        _from_openai_response({"error": "something went wrong"})


def test_openai_compatible_client_full_round_trip(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "function": {"name": "dns_lookup", "arguments": '{"target": "x.com"}'},
                                }
                            ],
                        }
                    }
                ]
            }

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["payload"] = json
        captured["headers"] = headers
        return FakeResp()

    monkeypatch.setattr(requests, "post", fake_post)

    client = OpenAICompatibleClient("http://localhost:11434/v1", api_key="sk-local")
    response = client.messages.create(
        model="llama3.1:70b",
        max_tokens=1024,
        system=[{"type": "text", "text": "You are D3M0N."}],
        tools=[{"name": "dns_lookup", "description": "x", "input_schema": {"type": "object"}}],
        messages=[{"role": "user", "content": "go"}],
    )

    assert captured["url"] == "http://localhost:11434/v1/chat/completions"
    assert captured["payload"]["model"] == "llama3.1:70b"
    assert captured["payload"]["messages"][0] == {"role": "system", "content": "You are D3M0N."}
    assert captured["payload"]["tools"][0]["function"]["name"] == "dns_lookup"
    assert captured["headers"]["Authorization"] == "Bearer sk-local"
    assert response.content[0].type == "tool_use"
    assert response.content[0].name == "dns_lookup"


def test_openai_compatible_client_connection_failure_raises_clear_runtimeerror(monkeypatch):
    def fake_post(*a, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "post", fake_post)
    client = OpenAICompatibleClient("http://localhost:11434/v1")

    with pytest.raises(RuntimeError, match="Could not reach the local model"):
        client.messages.create(model="x", max_tokens=1, system="sys", tools=[], messages=[])


def test_openai_compatible_client_non_json_response_raises_clear_error(monkeypatch):
    class FakeResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResp())
    client = OpenAICompatibleClient("http://localhost:11434/v1")

    with pytest.raises(RuntimeError, match="non-JSON response"):
        client.messages.create(model="x", max_tokens=1, system="sys", tools=[], messages=[])


def test_openai_compatible_client_no_tools_omits_tool_fields(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": "no tools here", "tool_calls": None}}]}

    def fake_post(url, json=None, **kwargs):
        captured["payload"] = json
        return FakeResp()

    monkeypatch.setattr(requests, "post", fake_post)
    client = OpenAICompatibleClient("http://localhost:11434/v1")
    client.messages.create(model="x", max_tokens=1, system="sys", tools=[], messages=[])

    assert "tools" not in captured["payload"]
    assert "tool_choice" not in captured["payload"]
