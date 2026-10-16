"""Shared state threaded through the LangGraph loop."""

from __future__ import annotations

from typing import Any, TypedDict


class AgentState(TypedDict):
    objective: str
    scope_raw: str
    messages: list[dict[str, Any]]  # Anthropic-format message history
    findings: list[dict[str, Any]]  # structured tool results, for the final report
    step: int
    max_steps: int
    done: bool
    summary: str | None
    cache_breakpoint: tuple[int, int] | None  # internal: rolling prompt-cache marker
    events_path: str | None  # internal: where live-TUI events are being written, if at all
    summary_before_critic: str | None  # set only if --mode pentest's critic pass revised the summary
    defense_recommendations: dict | None  # set only in --mode pentest -- see agent/defense_mapper.py
