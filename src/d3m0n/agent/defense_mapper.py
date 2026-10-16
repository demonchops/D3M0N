"""DefenseMapper: turns a run's raw findings into remediation + detection-
rule suggestions. Same pattern as graph.py's run_critic_pass — one extra,
non-tool-use Claude call that runs once at the end of a run (--mode
pentest only; see graph.py's run_agent), never raises, and degrades
gracefully on any failure rather than breaking a run that otherwise
succeeded.

Takes `client` as a parameter rather than constructing one itself (unlike
run_critic_pass, which calls graph._client() internally) specifically to
avoid this module depending on graph.py while graph.py depends on this
one — dependency injection here, not a missing feature.

The model is asked for a strict JSON array (see prompts.py's
DEFENSE_MAPPER_SYSTEM_PROMPT) since this is a one-shot text completion,
not a tool call — there's no schema enforcement to lean on, so the
response is parsed defensively: markdown code fences are stripped if the
model adds them anyway, a non-JSON or non-array response falls back to
an empty list WITH `generation_error` set (never silently implying there
was nothing to flag), and any single entry that isn't itself an object
is skipped rather than failing the whole batch.
"""

from __future__ import annotations

import json
import re

from d3m0n.agent.prompts import DEFENSE_MAPPER_SYSTEM_PROMPT
from d3m0n.config import SETTINGS

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)
_FINDINGS_CHAR_LIMIT = 60_000
_FIELD_CHAR_LIMIT = 1000


def _strip_fences(text: str) -> str:
    return _FENCE_RE.sub("", text).strip()


def _findings_for_prompt(findings: list[dict]) -> str:
    text = json.dumps(findings, default=str)
    if len(text) <= _FINDINGS_CHAR_LIMIT:
        return text
    omitted = len(text) - _FINDINGS_CHAR_LIMIT
    return f"{text[:_FINDINGS_CHAR_LIMIT]}\n...[truncated {omitted} chars]"


def run_defense_mapper(client, objective: str, scope_raw: str, findings: list[dict]) -> dict:
    """Returns {"entries": [...], "generation_error": str | None}.
    `entries` is always a list (possibly empty); `generation_error` is
    only set when generation/parsing failed, so an empty list from a
    genuinely clean run and an empty list from a broken call are never
    indistinguishable in the saved report."""
    try:
        response = client.messages.create(
            model=SETTINGS.model,
            max_tokens=4096,
            system=DEFENSE_MAPPER_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Objective: {objective}\nScope: {scope_raw}\n\n"
                        f"Raw tool findings:\n{_findings_for_prompt(findings)}"
                    ),
                }
            ],
        )
        text = _strip_fences(
            "\n".join(b.text for b in response.content if b.type == "text").strip()
        )
        raw_entries = json.loads(text) if text else []
        if not isinstance(raw_entries, list):
            raise ValueError(f"expected a JSON array, got {type(raw_entries).__name__}")

        entries = []
        for entry in raw_entries:
            if not isinstance(entry, dict):
                continue
            entries.append(
                {
                    "finding_summary": str(entry.get("finding_summary", ""))[:_FIELD_CHAR_LIMIT],
                    "remediation": str(entry.get("remediation", ""))[:_FIELD_CHAR_LIMIT],
                    "detection_ideas": str(entry.get("detection_ideas", ""))[:_FIELD_CHAR_LIMIT],
                }
            )
        return {"entries": entries, "generation_error": None}
    except Exception as exc:  # noqa: BLE001 - a broken defense mapper must never break the run
        return {"entries": [], "generation_error": str(exc)}
