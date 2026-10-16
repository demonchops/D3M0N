"""Pure-function tests for graph.py helpers — no ANTHROPIC_API_KEY or network
needed, since these don't touch the client."""

import json

import pytest

import d3m0n.agent.graph as graph_mod
import d3m0n.policy as policy_mod
from d3m0n.agent.backends import Block, OpenAICompatibleClient
from d3m0n.config import Settings


def test_client_anthropic_backend_requires_key(monkeypatch):
    monkeypatch.setattr(graph_mod, "SETTINGS", Settings(backend="anthropic", anthropic_api_key=None))
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        graph_mod._client()


def test_client_anthropic_backend_succeeds_with_key(monkeypatch):
    monkeypatch.setattr(
        graph_mod, "SETTINGS", Settings(backend="anthropic", anthropic_api_key="sk-ant-fake")
    )
    client = graph_mod._client()
    assert isinstance(client, graph_mod.anthropic.Anthropic)


def test_client_local_backend_requires_url(monkeypatch):
    monkeypatch.setattr(graph_mod, "SETTINGS", Settings(backend="local", local_model_url=None))
    with pytest.raises(RuntimeError, match="D3M0N_LOCAL_MODEL_URL"):
        graph_mod._client()


def test_client_local_backend_succeeds_with_url(monkeypatch):
    monkeypatch.setattr(
        graph_mod, "SETTINGS", Settings(backend="local", local_model_url="http://localhost:11434/v1")
    )
    client = graph_mod._client()
    assert isinstance(client, OpenAICompatibleClient)
    assert client.base_url == "http://localhost:11434/v1"


def test_client_unknown_backend_raises_clear_error(monkeypatch):
    monkeypatch.setattr(graph_mod, "SETTINGS", Settings(backend="carrier-pigeon"))
    with pytest.raises(RuntimeError, match="Unknown D3M0N_BACKEND"):
        graph_mod._client()


def test_short_result_not_truncated():
    result = {"a": 1}
    assert graph_mod._summarize_result(result) == str(result)


def test_long_result_truncated(monkeypatch):
    monkeypatch.setattr(graph_mod, "SETTINGS", Settings(max_result_chars=50))
    result = {"data": "x" * 500}
    text = graph_mod._summarize_result(result)
    assert len(text) < 500
    assert "truncated" in text


def test_short_note_known_tools():
    assert "3" in graph_mod._short_note("subfinder_scan", {"count": 3})
    assert "ok" == graph_mod._short_note("dns_lookup", {})


def test_event_log_writes_jsonl(tmp_path):
    from d3m0n.agent.events import EventLog

    path = str(tmp_path / "events.jsonl")
    log = EventLog(path)
    log.emit("run_start", objective="test", scope="example.com", max_steps=5)
    log.emit("tool_done", step=1, tool="dns_lookup", target="example.com", ok=True, note="ok")

    lines = open(path).read().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["type"] == "run_start"
    assert first["objective"] == "test"
    assert "ts" in first


def test_event_log_never_raises_on_bad_path():
    from d3m0n.agent.events import EventLog

    # A path under a directory that can't be created should be swallowed,
    # not raised — logging must never break a run.
    log = EventLog("/proc/1/this-cannot-be-written/events.jsonl")
    log.emit("run_start", objective="x", scope="y", max_steps=1)  # must not raise


class _FakeTextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _FakeResponse:
    def __init__(self, text):
        self.content = [_FakeTextBlock(text)]


class _FakeMessages:
    def __init__(self, text):
        self._text = text

    def create(self, **kwargs):
        return _FakeResponse(self._text)


class _FakeClient:
    def __init__(self, text):
        self.messages = _FakeMessages(text)


def test_critic_pass_returns_revised_summary(monkeypatch):
    monkeypatch.setattr(graph_mod, "_client", lambda: _FakeClient("Revised: toned down claim X."))
    revised = graph_mod.run_critic_pass(
        "obj", "example.com", "Draft: X is definitely vulnerable.", []
    )
    assert revised == "Revised: toned down claim X."


def test_critic_pass_falls_back_to_draft_on_error(monkeypatch):
    def boom():
        raise RuntimeError("ANTHROPIC_API_KEY is not set.")

    monkeypatch.setattr(graph_mod, "_client", boom)
    revised = graph_mod.run_critic_pass("obj", "example.com", "Draft summary unchanged.", [])
    assert revised == "Draft summary unchanged."


def test_critic_pass_falls_back_on_empty_response(monkeypatch):
    monkeypatch.setattr(graph_mod, "_client", lambda: _FakeClient(""))
    revised = graph_mod.run_critic_pass("obj", "example.com", "Draft summary unchanged.", [])
    assert revised == "Draft summary unchanged."


def test_findings_for_critic_truncates_when_huge():
    big_findings = [{"tool": "nuclei_scan", "result": {"data": "x" * 1000}} for _ in range(200)]
    text = graph_mod._findings_for_critic(big_findings)
    assert len(text) <= graph_mod._CRITIC_FINDINGS_CHAR_LIMIT + 100
    assert "truncated" in text


def test_findings_for_critic_passthrough_when_small():
    findings = [{"tool": "dns_lookup", "result": {"a": 1}}]
    text = graph_mod._findings_for_critic(findings)
    assert "dns_lookup" in text
    assert "truncated" not in text


class _FinishResponse:
    def __init__(self, summary_text: str):
        self.content = [Block(type="tool_use", id="call_1", name="finish", input={"summary": summary_text})]


class _FinishMessages:
    def __init__(self, summary_text: str):
        self._summary = summary_text

    def create(self, **kwargs):
        return _FinishResponse(self._summary)


class _FinishClient:
    def __init__(self, summary_text: str):
        self.messages = _FinishMessages(summary_text)


def test_run_agent_redacts_secret_from_final_summary(monkeypatch):
    # policy.redact_known_secrets reads policy.py's own module-level
    # SETTINGS at call time, so patching it there is what matters here --
    # not graph_mod.SETTINGS, which this test never exercises since the
    # fake client bypasses _client()'s backend selection entirely.
    monkeypatch.setattr(
        policy_mod, "SETTINGS", Settings(session_headers={"Cookie": "sid=SUPER-SECRET-TOKEN"})
    )
    monkeypatch.setattr(
        graph_mod,
        "_client",
        lambda: _FinishClient("Found an issue near sid=SUPER-SECRET-TOKEN in the logs."),
    )

    final_state = graph_mod.run_agent("objective", "example.com", max_steps=1, live_events=False)

    assert "SUPER-SECRET-TOKEN" not in final_state["summary"]
    assert "REDACTED" in final_state["summary"]


def test_run_agent_summary_without_secrets_unaffected(monkeypatch):
    monkeypatch.setattr(policy_mod, "SETTINGS", Settings())
    monkeypatch.setattr(graph_mod, "_client", lambda: _FinishClient("Nothing sensitive here."))

    final_state = graph_mod.run_agent("objective", "example.com", max_steps=1, live_events=False)

    assert final_state["summary"] == "Nothing sensitive here."


# --- the three named per-turn functions, tested in isolation ---


class _BlockResponse:
    def __init__(self, blocks):
        self.content = blocks


class _BlockMessages:
    def __init__(self, blocks):
        self._blocks = blocks

    def create(self, **kwargs):
        return _BlockResponse(self._blocks)


class _BlockClient:
    def __init__(self, blocks):
        self.messages = _BlockMessages(blocks)


def test_planner_step_appends_assistant_message_and_increments_step():
    state = {"messages": [{"role": "user", "content": "go"}], "step": 0, "cache_breakpoint": None}
    client = _BlockClient([Block(type="text", text="thinking out loud")])

    response = graph_mod._planner_step(client, state)

    assert response.content[0].text == "thinking out loud"
    assert state["step"] == 1
    assert state["messages"][-1]["role"] == "assistant"
    assert state["messages"][-1]["content"] == [{"type": "text", "text": "thinking out loud"}]


def test_tool_router_empty_calls_returns_empty_without_threadpool(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not touch the thread pool for zero calls")

    monkeypatch.setattr(graph_mod.concurrent.futures, "ThreadPoolExecutor", boom)
    assert graph_mod._tool_router([], scope=None) == []


def test_tool_router_dispatches_each_call_and_preserves_order(monkeypatch):
    calls = [Block(type="tool_use", id=f"c{i}", name="dns_lookup", input={"target": f"h{i}.com"}) for i in range(4)]

    def fake_run_one(call, scope):
        return ({"hostname": call.input["target"]}, None)

    monkeypatch.setattr(graph_mod, "_run_one", fake_run_one)
    outcomes = graph_mod._tool_router(calls, scope="fake-scope")

    assert [o[0]["hostname"] for o in outcomes] == ["h0.com", "h1.com", "h2.com", "h3.com"]


class _RecordingEventLog:
    def __init__(self):
        self.events = []

    def emit(self, event_type, **fields):
        self.events.append({"type": event_type, **fields})


def test_result_interpreter_records_finding_and_summarized_content():
    call = Block(type="tool_use", id="c1", name="dns_lookup", input={"target": "example.com"})
    state = {"findings": [], "step": 1}
    event_log = _RecordingEventLog()

    tool_results = graph_mod._result_interpreter(
        [call], [({"hostname": "example.com"}, None)], None, state, event_log
    )

    assert len(state["findings"]) == 1
    assert state["findings"][0]["tool"] == "dns_lookup"
    assert tool_results == [
        {"type": "tool_result", "tool_use_id": "c1", "content": "{'hostname': 'example.com'}"}
    ]
    tool_done = next(e for e in event_log.events if e["type"] == "tool_done")
    assert tool_done["ok"] is True


def test_result_interpreter_blocked_call_not_a_finding():
    from d3m0n.safety import OutOfScopeError

    call = Block(type="tool_use", id="c1", name="dns_lookup", input={"target": "evil.com"})
    state = {"findings": [], "step": 1}
    event_log = _RecordingEventLog()

    tool_results = graph_mod._result_interpreter(
        [call], [(None, OutOfScopeError("nope"))], None, state, event_log
    )

    assert state["findings"] == []
    assert "BLOCKED by scope enforcement" in tool_results[0]["content"]
    tool_done = next(e for e in event_log.events if e["type"] == "tool_done")
    assert tool_done["ok"] is False


def test_result_interpreter_finish_call_sets_done_and_summary():
    finish_call = Block(type="tool_use", id="c2", name="finish", input={"summary": "all done"})
    state = {"findings": [], "step": 1, "done": False, "summary": None}

    tool_results = graph_mod._result_interpreter([], [], finish_call, state, None)

    assert state["done"] is True
    assert state["summary"] == "all done"
    assert {"type": "tool_result", "tool_use_id": "c2", "content": "Run finished."} in tool_results


def test_result_interpreter_works_with_no_event_log():
    call = Block(type="tool_use", id="c1", name="dns_lookup", input={"target": "example.com"})
    state = {"findings": [], "step": 1}
    # Must not raise with event_log=None (the live_events=False case).
    graph_mod._result_interpreter([call], [({"hostname": "example.com"}, None)], None, state, None)
