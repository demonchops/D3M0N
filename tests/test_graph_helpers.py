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
