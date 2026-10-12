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
