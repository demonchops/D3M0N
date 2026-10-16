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
import json
import os
from datetime import datetime, timezone

import anthropic
from langgraph.graph import END, StateGraph

from d3m0n.agent.backends import OpenAICompatibleClient
from d3m0n.agent.events import EventLog
from d3m0n.agent.prompts import CRITIC_SYSTEM_PROMPT, SYSTEM_PROMPT, objective_prompt
from d3m0n.agent.state import AgentState
from d3m0n.config import SETTINGS
from d3m0n.policy import redact_known_secrets
from d3m0n.safety import OutOfScopeError, Scope, parse_scope
from d3m0n.tools.registry import TOOL_SCHEMAS, run_tool

_SYSTEM_BLOCKS = [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}]

# Cache the tool schema array too — it's static for the whole run, and seven
# tool definitions add up to a few hundred tokens resent every turn otherwise.
_TOOLS_WITH_CACHE: list[dict] = [dict(t) for t in TOOL_SCHEMAS]
if _TOOLS_WITH_CACHE:
    _TOOLS_WITH_CACHE[-1] = {**_TOOLS_WITH_CACHE[-1], "cache_control": {"type": "ephemeral"}}


def _client():
    """Returns whichever backend is configured. Both duck-type
    anthropic.Anthropic()'s surface (.messages.create(...) -> something
    with a .content list of blocks), so nothing below this function
    needs to know or care which one it got — including run_critic_pass,
    which calls this too.
    """
    if SETTINGS.backend == "local":
        if not SETTINGS.local_model_url:
            raise RuntimeError(
                "D3M0N_BACKEND=local requires D3M0N_LOCAL_MODEL_URL to be set (e.g. "
                "http://localhost:11434/v1 for Ollama) — see the README's "
                "'Running without an API key' section."
            )
        return OpenAICompatibleClient(
            SETTINGS.local_model_url, SETTINGS.local_model_api_key or "not-needed"
        )
    if SETTINGS.backend != "anthropic":
        raise RuntimeError(f"Unknown D3M0N_BACKEND {SETTINGS.backend!r}; use 'anthropic' or 'local'.")
    if not SETTINGS.anthropic_api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Set D3M0N_BACKEND=local (with D3M0N_LOCAL_MODEL_URL) "
            "to run against a self-hosted model instead — see the README's "
            "'Running without an API key' section."
        )
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
        note = f"{result.get('issue_count', 0)} Burp issues ({result.get('status')})"
        high_or_above = sum(
            1 for i in result.get("issues", []) if (i.get("severity_score") or 0) >= 3
        )
        if high_or_above:
            note += f", {high_or_above} high/critical"
        return note
    if tool_name == "burp_traffic_review":
        return f"{result.get('items_flagged', 0)} flagged of {result.get('items_total', 0)}"
    if tool_name == "idor_check":
        sim = result.get("a_vs_b_body_similarity")
        note = f"A/B similarity {sim}" if sim is not None else "compared"
        enum = result.get("enumeration", {})
        if "probes" in enum:
            note += f", {len(enum['probes'])} ids enumerated"
        return note
    if tool_name == "crawl_site":
        return f"{result.get('pages_visited', 0)} pages, {len(result.get('forms_found', []))} forms"
    if tool_name == "js_secrets_scan":
        high = sum(1 for f in result.get("findings", []) if f.get("confidence") == "high")
        note = f"{result.get('finding_count', 0)} pattern matches"
        if high:
            note += f" ({high} high-confidence)"
        filtered = result.get("filtered_placeholder_count", 0)
        if filtered:
            note += f", {filtered} placeholders filtered"
        return note
    if tool_name == "graphql_introspect":
        return "introspection ENABLED" if result.get("introspection_enabled") else "introspection off"
    if tool_name == "cors_check":
        flags = result.get("flags", [])
        return f"{len(flags)} CORS flags: {', '.join(flags)}" if flags else "no CORS flags"
    if tool_name == "security_headers_check":
        note = f"{result.get('finding_count', 0)} header findings"
        if result.get("clickjacking", {}).get("likely_frameable"):
            note += ", likely frameable"
        return note
    if tool_name == "subdomain_takeover_check":
        if not result.get("matches_known_service"):
            return "no known-provider CNAME"
        return f"{result.get('service')}: {result.get('fingerprint_check')}"
    return "ok"


_CRITIC_FINDINGS_CHAR_LIMIT = 60_000


def _findings_for_critic(findings: list[dict]) -> str:
    """Serialize findings for the one-shot critic call — a much larger
    budget than _summarize_result's per-step cap, since this runs once
    at the end over everything, not once per turn over the growing
    conversation."""
    text = json.dumps(findings, default=str)
    if len(text) <= _CRITIC_FINDINGS_CHAR_LIMIT:
        return text
    omitted = len(text) - _CRITIC_FINDINGS_CHAR_LIMIT
    return f"{text[:_CRITIC_FINDINGS_CHAR_LIMIT]}\n...[truncated {omitted} chars]"


def run_critic_pass(objective: str, scope_raw: str, draft_summary: str, findings: list[dict]) -> str:
    """One extra, non-tool-use Claude call that skeptically reviews the
    draft summary against the actual findings before the report is
    written. Returns the (possibly revised) summary. Never raises —
    falls back to the draft summary unchanged on any failure, since a
    broken self-review must never break a run that otherwise succeeded."""
    try:
        client = _client()
        response = client.messages.create(
            model=SETTINGS.model,
            max_tokens=2048,
            system=CRITIC_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Objective: {objective}\nScope: {scope_raw}\n\n"
                        f"Draft summary:\n{draft_summary}\n\n"
                        f"Actual tool findings:\n{_findings_for_critic(findings)}"
                    ),
                }
            ],
        )
        revised = "\n".join(b.text for b in response.content if b.type == "text").strip()
        return revised or draft_summary
    except Exception:  # noqa: BLE001 - a broken critic pass must never break the run
        return draft_summary


def build_graph(scope: Scope, event_log: EventLog | None = None, methodology_directive: str | None = None):
    client = _client()

    def plan_and_act(state: AgentState) -> AgentState:
        if state["step"] == 0:
            state["messages"].append(
                {
                    "role": "user",
                    "content": objective_prompt(
                        state["objective"], state["scope_raw"], methodology_directive
                    ),
                }
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
    objective: str,
    scope_raw: str,
    max_steps: int | None = None,
    *,
    live_events: bool = True,
    methodology_directive: str | None = None,
    use_critic_pass: bool = False,
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

    compiled = build_graph(scope, event_log, methodology_directive)
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
        "summary_before_critic": None,
    }
    final_state = compiled.invoke(initial)

    if use_critic_pass and final_state.get("summary"):
        original_summary = final_state["summary"]
        revised = run_critic_pass(
            objective, scope_raw, original_summary, final_state.get("findings", [])
        )
        if revised != original_summary:
            final_state["summary_before_critic"] = original_summary
            final_state["summary"] = revised

    # Last-resort redaction pass (policy.redact_known_secrets) over the
    # agent's own free-text summary before anyone reads it (the event
    # log, the printed console output, the saved report). Every
    # individual tool already redacts its own result text, but none of
    # that covers the model's own prose — this is the one place that
    # does, covering every secret-bearing setting this project knows
    # about, not just whichever one a particular tool happened to use.
    if final_state.get("summary"):
        final_state["summary"] = redact_known_secrets(final_state["summary"])
    if final_state.get("summary_before_critic"):
        final_state["summary_before_critic"] = redact_known_secrets(
            final_state["summary_before_critic"]
        )

    if event_log is not None:
        event_log.emit(
            "run_done",
            summary=final_state.get("summary") or "",
            findings_count=len(final_state.get("findings", [])),
            steps_used=final_state.get("step", 0),
        )

    return final_state
