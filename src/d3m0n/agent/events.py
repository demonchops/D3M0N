"""Best-effort JSONL event log for the optional live TUI companion (tui/).

This is a pure side-channel: a run works identically with or without it being
read by anything. One JSON object per line, newline-delimited, append-only,
flushed after every write so an external `tail -f`-style reader (the Go TUI)
sees events as they happen. A write failure here must never break the run —
worst case, nobody gets a live view this time.

Event shapes (the Go TUI's fixed contract — keep in sync with tui/'s
README section if either side changes):
    {"type": "run_start", "ts": float, "objective": str, "scope": str, "max_steps": int}
    {"type": "step", "ts": float, "step": int, "tools": [{"name": str, "target": str}, ...]}
    {"type": "tool_done", "ts": float, "step": int, "tool": str, "target": str,
     "ok": bool, "note": str}
    {"type": "run_done", "ts": float, "summary": str, "findings_count": int, "steps_used": int}
"""

from __future__ import annotations

import json
import os
import time


class EventLog:
    def __init__(self, path: str):
        self.path = path
        try:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
        except OSError:
            pass

    def emit(self, event_type: str, **fields) -> None:
        record = {"type": event_type, "ts": time.time(), **fields}
        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(record) + "\n")
                f.flush()
        except OSError:
            pass  # best-effort; a logging failure must never break the run
