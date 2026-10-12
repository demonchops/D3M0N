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

import anthropic
from langgraph.graph import END, StateGraph

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


def build_graph(scope: Scope):
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

        # Independent calls the model batched into this one turn run
        # concurrently — they're all I/O-bound (sockets/subprocesses), so
        # this is a real wall-clock win, not just bookkeeping.
        exec_outcomes: list[tuple[dict | None, OutOfScopeError | None]] = []
        if exec_calls:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(exec_calls))) as pool:
                exec_outcomes = list(pool.map(lambda c: _run_one(c, scope), exec_calls))

        tool_results = []
        for call, (result, exc) in zip(exec_calls, exec_outcomes):
            if exc is not None:
                content = f"BLOCKED by scope enforcement: {exc}"
            else:
                state["findings"].append({"tool": call.name, "input": call.input, "result": result})
                content = _summarize_result(result)
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


def run_agent(objective: str, scope_raw: str, max_steps: int | None = None) -> AgentState:
    scope = parse_scope(scope_raw)
    compiled = build_graph(scope)
    initial: AgentState = {
        "objective": objective,
        "scope_raw": scope_raw,
        "messages": [],
        "findings": [],
        "step": 0,
        "max_steps": max_steps or SETTINGS.max_steps,
        "done": False,
        "summary": None,
        "cache_breakpoint": None,
    }
    return compiled.invoke(initial)
