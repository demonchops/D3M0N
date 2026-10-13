"""Runtime settings for the agent."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    model: str = os.environ.get("D3M0N_MODEL", "claude-sonnet-5")
    max_steps: int = int(os.environ.get("D3M0N_MAX_STEPS", "25"))
    tool_timeout_s: int = int(os.environ.get("D3M0N_TOOL_TIMEOUT", "30"))
    output_dir: str = os.environ.get("D3M0N_OUTPUT_DIR", "./d3m0n_runs")
    max_result_chars: int = int(os.environ.get("D3M0N_MAX_RESULT_CHARS", "4000"))
    anthropic_api_key: str | None = os.environ.get("ANTHROPIC_API_KEY")
    # Burp Suite Professional/Enterprise's REST API (Settings > Suite > REST
    # API in Burp). Community Edition has no Scanner/REST API — see
    # tools/burp_traffic.py for a Community-compatible alternative.
    burp_api_url: str | None = os.environ.get("D3M0N_BURP_API_URL")
    burp_api_key: str | None = os.environ.get("D3M0N_BURP_API_KEY")


SETTINGS = Settings()
