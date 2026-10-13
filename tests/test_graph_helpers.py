"""Pure-function tests for graph.py helpers — no ANTHROPIC_API_KEY or network
needed, since these don't touch the client."""

import json

import d3m0n.agent.graph as graph_mod
from d3m0n.config import Settings


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
