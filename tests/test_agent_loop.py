"""Integration-level characterization of the plan -> act -> observe loop
itself (run_agent end to end, with a scripted fake client standing in for
Claude and real tool dispatch through the real registry/PolicyEngine —
only the individual tool functions are mocked). These exist to lock down
the loop's actual behavior (multi-step looping, concurrent batched tool
calls, mid-loop scope blocking, step-budget cutoff, live event logging)
BEFORE any internal refactor of graph.py's plan_and_act, so a refactor
has something real to be checked against rather than just "the tests
that already happened to pass"."""

import json

import d3m0n.agent.graph as graph_mod
import d3m0n.tools.registry as registry_mod
from d3m0n.agent.backends import Block
from d3m0n.config import Settings


class _ScriptedResponse:
    def __init__(self, blocks):
        self.content = blocks


class _ScriptedMessages:
    def __init__(self, responses):
        self._responses = list(responses)

    def create(self, **kwargs):
        return self._responses.pop(0)


class _ScriptedClient:
    def __init__(self, responses):
        self.messages = _ScriptedMessages(responses)


def _tool_use(call_id, name, **input_kwargs):
    return Block(type="tool_use", id=call_id, name=name, input=input_kwargs)


def _text(text):
    return Block(type="text", text=text)


def test_multi_step_loop_with_real_tool_dispatch(monkeypatch):
    monkeypatch.setattr(
        graph_mod,
        "_client",
        lambda: _ScriptedClient(
            [
                _ScriptedResponse([_tool_use("c1", "dns_lookup", target="example.com")]),
                _ScriptedResponse([_tool_use("c2", "finish", summary="done")]),
            ]
        ),
    )
    monkeypatch.setattr(
        registry_mod, "dns_lookup", lambda target: {"hostname": target, "records": {"A": ["1.2.3.4"]}}
    )

    final_state = graph_mod.run_agent("objective", "example.com", max_steps=5, live_events=False)

    assert final_state["step"] == 2
    assert final_state["done"] is True
    assert final_state["summary"] == "done"
    assert len(final_state["findings"]) == 1
    assert final_state["findings"][0]["tool"] == "dns_lookup"
    assert final_state["findings"][0]["result"]["hostname"] == "example.com"


def test_batched_tool_calls_in_one_turn_count_as_one_step(monkeypatch):
    monkeypatch.setattr(
        graph_mod,
        "_client",
        lambda: _ScriptedClient(
            [
                _ScriptedResponse(
                    [
                        _tool_use("c1", "dns_lookup", target="example.com"),
                        _tool_use("c2", "tls_info", target="example.com"),
                    ]
                ),
                _ScriptedResponse([_tool_use("c3", "finish", summary="done")]),
            ]
        ),
    )
    monkeypatch.setattr(registry_mod, "dns_lookup", lambda target: {"hostname": target})
    monkeypatch.setattr(registry_mod, "tls_info", lambda target, port=443: {"subject": f"CN={target}"})

    final_state = graph_mod.run_agent("objective", "example.com", max_steps=5, live_events=False)

    assert final_state["step"] == 2  # one step for both batched calls, not two
    assert {f["tool"] for f in final_state["findings"]} == {"dns_lookup", "tls_info"}


def test_out_of_scope_tool_call_blocked_not_crash_and_not_a_finding(monkeypatch):
    monkeypatch.setattr(
        graph_mod,
        "_client",
        lambda: _ScriptedClient(
            [
                _ScriptedResponse([_tool_use("c1", "dns_lookup", target="totally-not-example.com")]),
                _ScriptedResponse([_tool_use("c2", "finish", summary="done")]),
            ]
        ),
    )

    final_state = graph_mod.run_agent("objective", "example.com", max_steps=5, live_events=False)

    assert final_state["findings"] == []  # a blocked call must never become a finding
    tool_result_texts = [
        block["content"]
        for msg in final_state["messages"]
        if msg["role"] == "user" and isinstance(msg["content"], list)
        for block in msg["content"]
        if isinstance(block, dict) and block.get("type") == "tool_result"
    ]
    assert any("BLOCKED" in text for text in tool_result_texts)


def test_plain_text_responses_loop_until_step_budget_exhausted(monkeypatch):
    # A response with no tool_use at all must not hang the loop --
    # should_continue still ends the run once max_steps is reached.
    monkeypatch.setattr(
        graph_mod,
        "_client",
        lambda: _ScriptedClient([_ScriptedResponse([_text("thinking...")]) for _ in range(3)]),
    )

    final_state = graph_mod.run_agent("objective", "example.com", max_steps=3, live_events=False)

    assert final_state["step"] == 3
    assert final_state["done"] is False
    assert final_state["summary"] == "Stopped: step budget exhausted."


def test_live_event_log_records_step_and_tool_done_events(monkeypatch, tmp_path):
    monkeypatch.setattr(graph_mod, "SETTINGS", Settings(output_dir=str(tmp_path)))
    monkeypatch.setattr(
        graph_mod,
        "_client",
        lambda: _ScriptedClient(
            [
                _ScriptedResponse([_tool_use("c1", "dns_lookup", target="example.com")]),
                _ScriptedResponse([_tool_use("c2", "finish", summary="done")]),
            ]
        ),
    )
    monkeypatch.setattr(registry_mod, "dns_lookup", lambda target: {"hostname": target, "records": {}})

    final_state = graph_mod.run_agent("objective", "example.com", max_steps=5, live_events=True)

    events_path = final_state["events_path"]
    assert events_path and tmp_path.as_posix() in events_path.replace("\\", "/")
    events = [json.loads(line) for line in open(events_path)]
    event_types = [e["type"] for e in events]
    assert event_types[0] == "run_start"
    assert "step" in event_types
    assert "tool_done" in event_types
    assert event_types[-1] == "run_done"
    tool_done = next(e for e in events if e["type"] == "tool_done")
    assert tool_done["tool"] == "dns_lookup"
    assert tool_done["ok"] is True
