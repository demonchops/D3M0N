"""The plan -> act -> observe -> decide loop, built on LangGraph.

Claude does the planning (via tool use); `tools.registry.run_tool` does the
acting, with scope enforcement as the hard boundary around what Claude's
plan is actually allowed to touch.
"""

from __future__ import annotations

import anthropic
from langgraph.graph import END, StateGraph

from d3m0n.agent.prompts import SYSTEM_PROMPT, objective_prompt
from d3m0n.agent.state import AgentState
from d3m0n.config import SETTINGS
from d3m0n.safety import OutOfScopeError, Scope, parse_scope
from d3m0n.tools.registry import TOOL_SCHEMAS, run_tool


def _client() -> anthropic.Anthropic:
    if not SETTINGS.anthropic_api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set.")
    return anthropic.Anthropic(api_key=SETTINGS.anthropic_api_key)


def build_graph(scope: Scope):
    client = _client()

    def plan_and_act(state: AgentState) -> AgentState:
        if state["step"] == 0:
            state["messages"].append(
                {"role": "user", "content": objective_prompt(state["objective"], state["scope_raw"])}
            )

        response = client.messages.create(
            model=SETTINGS.model,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=state["messages"],
        )

        assistant_content = [block.model_dump() for block in response.content]
        state["messages"].append({"role": "assistant", "content": assistant_content})
        state["step"] += 1

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            # Model responded with plain text and no tool call; nudge once
            # more via the loop rather than hanging.
            return state

        tool_results = []
        for call in tool_uses:
            if call.name == "finish":
                state["done"] = True
                state["summary"] = call.input.get("summary", "")
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": call.id,
                        "content": "Run finished.",
                    }
                )
                continue
            try:
                result = run_tool(call.name, call.input, scope)
                state["findings"].append({"tool": call.name, "input": call.input, "result": result})
                content = str(result)
            except OutOfScopeError as exc:
                content = f"BLOCKED by scope enforcement: {exc}"
            tool_results.append(
                {"type": "tool_result", "tool_use_id": call.id, "content": content}
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
    }
    return compiled.invoke(initial)
