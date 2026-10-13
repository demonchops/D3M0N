"""The plan -> act -> observe -> decide loop, built on LangGraph.

Claude does the planning (via tool use); `tools.registry.run_tool` does the
acting, with scope enforcement as the hard boundary around what Claude's
plan is actually allowed to touch.

Two efficiency features live here, on top of a plain linear loop:

1. Independent tool calls the model batches into one response are executed
   concurrently (they're all I/O-bound: sockets/subprocesses), so a turn
   with several checks takes roughly as long as the slowest one, not the
   sum of all of them.
2. A rolling prompt-cache breakpoint is kept on the message history, on top
   of static breakpoints on the system prompt and tool schemas, so a long
   run pays full price for new content each turn instead of re-pricing the
   whole growing conversation every single step.
"""

from __future__ import annotations

import concurrent.futures
import os
from datetime import datetime, timezone

import anthropic
from langgraph.graph import END, StateGraph

from d3m0n.agent.events import EventLog
from d3m0n.agent.prompts import SYSTEM_PROMPT, objective_prompt
from d3m0n.agent.state import AgentState
from d3m0n.config import SETTINGS
from d3m0n.safety import OutOfScopeError, Scope, parse_scope
from d3m0n.tools.registry import TOOL_SCHEMAS, run_tool

_SYSTEM_BLOCKS = [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}]

# Cache the tool schema array too — it's static for the whole run, and seven
# tool definitions add up to a few hundred tokens resent every turn otherwise.
_TOOLS_WITH_CACHE: list[dict] = [dict(t) for t in TOOL_SCHEMAS]
if _TOOLS_WITH_CACHE:
    _TOOLS_WITH_CACHE[-1] = {**_TOOLS_WITH_CACHE[-1], "cache_control": {"type": "ephemeral"}}


def _client() -> anthropic.Anthropic:
    if not SETTINGS.anthropic_api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set.")
    return anthropic.Anthropic(api_key=SETTINGS.anthropic_api_key)


def _set_cache_breakpoint(state: AgentState) -> None:
    """Move the single rolling cache breakpoint to the end of the message
    history as it stands right now (everything settled before this turn's
    new content). Anthropic matches the longest previously-cached prefix, so
    moving one breakpoint forward each turn is enough to get incremental
    caching across the whole loop — there's no need to keep re-marking every
    earlier point.
    """
    prev = state.get("cache_breakpoint")
    if prev is not None:
        msg_idx, block_idx = prev
        try:
            state["messages"][msg_idx]["content"][block_idx].pop("cache_control", None)
        except (IndexError, KeyError, TypeError):
            pass

    if not state["messages"]:
        return
    last_msg = state["messages"][-1]
    content = last_msg["content"]
    if isinstance(content, str):
        content = [{"type": "text", "text": content}]
        last_msg["content"] = content
    if not content:
        return
    content[-1]["cache_control"] = {"type": "ephemeral"}
    state["cache_breakpoint"] = (len(state["messages"]) - 1, len(content) - 1)


def _summarize_result(result: dict) -> str:
    """Cap how many characters of a tool result go back into the LLM's
    context. The full, untruncated result still lands in `findings` (and
    therefore in the final JSON report) — this only controls what gets
    re-sent, and re-priced, on every subsequent turn."""
    text = str(result)
    limit = SETTINGS.max_result_chars
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return f"{text[:limit]}\n...[truncated {omitted} chars; full result is in the run's findings report]"


def _run_one(call, scope: Scope) -> tuple[dict | None, OutOfScopeError | None]:
    try:
        return run_tool(call.name, call.input, scope), None
    except OutOfScopeError as exc:
        return None, exc


def _short_note(tool_name: str, result: dict) -> str:
    """One-line human summary of a successful tool result, for the live TUI."""
    if tool_name == "subfinder_scan":
        return f"{result.get('count', 0)} subdomains"
    if tool_name == "nuclei_scan":
        return f"{result.get('count', 0)} template matches"
    if tool_name == "ffuf_scan":
        return f"{result.get('count', 0)} paths found"
    if tool_name == "http_probe":
        return f"HTTP {result.get('status')} — {result.get('server') or 'no server header'}"
    if tool_name == "tls_info":
        return f"expires in {result.get('expires_in_days')}d"
    if tool_name == "burp_scan":
        return f"{result.get('issue_count', 0)} Burp issues ({result.get('status')})"
    if tool_name == "burp_traffic_review":
        return f"{result.get('items_flagged', 0)} flagged of {result.get('items_total', 0)}"
    if tool_name == "idor_check":
        sim = result.get("a_vs_b_body_similarity")
        return f"A/B similarity {sim}" if sim is not None else "compared"
    return "ok"


def build_graph(scope: Scope, event_log: EventLog | None = None):
    client = _client()

    def plan_and_act(state: AgentState) -> AgentState:
        if state["step"] == 0:
            state["messages"].append(
                {"role": "user", "content": objective_prompt(state["objective"], state["scope_raw"])}
            )

        _set_cache_breakpoint(state)

        response = client.messages.create(
            model=SETTINGS.model,
            max_tokens=3072,
            system=_SYSTEM_BLOCKS,
            tools=_TOOLS_WITH_CACHE,
            messages=state["messages"],
        )

        assistant_content = [block.model_dump() for block in response.content]
        state["messages"].append({"role": "assistant", "content": assistant_content})
        state["step"] += 1

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            # Plain-text response with no tool call; loop back around rather
            # than hang — should_continue still ends the run once the step
            # budget runs out if the model keeps doing this.
            return state

        finish_call = next((c for c in tool_uses if c.name == "finish"), None)
        exec_calls = [c for c in tool_uses if c.name != "finish"]

        if event_log is not None and exec_calls:
            event_log.emit(
                "step",
                step=state["step"],
                tools=[{"name": c.name, "target": c.input.get("target", "")} for c in exec_calls],
            )

        # Independent calls the model batched into this one turn run
        # concurrently — they're all I/O-bound (sockets/subprocesses), so
        # this is a real wall-clock win, not just bookkeeping.
        exec_outcomes: list[tuple[dict | None, OutOfScopeError | None]] = []
        if exec_calls:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(exec_calls))) as pool:
                exec_outcomes = list(pool.map(lambda c: _run_one(c, scope), exec_calls))

        tool_results = []
        for call, (result, exc) in zip(exec_calls, exec_outcomes):
            target = call.input.get("target", "")
            if exc is not None:
                content = f"BLOCKED by scope enforcement: {exc}"
                if event_log is not None:
                    event_log.emit(
                        "tool_done", step=state["step"], tool=call.name, target=target,
                        ok=False, note="blocked by scope enforcement",
                    )
            else:
                state["findings"].append({"tool": call.name, "input": call.input, "result": result})
                content = _summarize_result(result)
                if event_log is not None:
                    ok = "error" not in result
                    note = str(result.get("error", "")) if not ok else _short_note(call.name, result)
                    event_log.emit(
                        "tool_done", step=state["step"], tool=call.name, target=target,
                        ok=ok, note=note[:120],
                    )
            tool_results.append({"type": "tool_result", "tool_use_id": call.id, "content": content})

        if finish_call is not None:
            state["done"] = True
            state["summary"] = finish_call.input.get("summary", "")
            tool_results.append(
                {"type": "tool_result", "tool_use_id": finish_call.id, "content": "Run finished."}
            )

        state["messages"].append({"role": "user", "content": tool_results})
        return state

    def should_continue(state: AgentState) -> str:
        if state["done"]:
            return "end"
        if state["step"] >= state["max_steps"]:
            state["summary"] = state.get("summary") or "Stopped: step budget exhausted."
            return "end"
        return "continue"

    graph = StateGraph(AgentState)
    graph.add_node("plan_and_act", plan_and_act)
    graph.set_entry_point("plan_and_act")
    graph.add_conditional_edges(
        "plan_and_act", should_continue, {"continue": "plan_and_act", "end": END}
    )
    return graph.compile()


def run_agent(
    objective: str, scope_raw: str, max_steps: int | None = None, *, live_events: bool = True
) -> AgentState:
    scope = parse_scope(scope_raw)
    resolved_max_steps = max_steps or SETTINGS.max_steps

    event_log = None
    events_path = None
    if live_events:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        events_path = os.path.join(SETTINGS.output_dir, f"events_{stamp}.jsonl")
        event_log = EventLog(events_path)
        event_log.emit(
            "run_start", objective=objective, scope=scope_raw, max_steps=resolved_max_steps
        )

    compiled = build_graph(scope, event_log)
    initial: AgentState = {
        "objective": objective,
        "scope_raw": scope_raw,
        "messages": [],
        "findings": [],
        "step": 0,
        "max_steps": resolved_max_steps,
        "done": False,
        "summary": None,
        "cache_breakpoint": None,
        "events_path": events_path,
    }
    final_state = compiled.invoke(initial)

    if event_log is not None:
        event_log.emit(
            "run_done",
            summary=final_state.get("summary") or "",
            findings_count=len(final_state.get("findings", [])),
            steps_used=final_state.get("step", 0),
        )

    return final_state
