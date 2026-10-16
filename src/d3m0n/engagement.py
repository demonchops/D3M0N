"""A structured engagement config: scope + an ordered list of objectives
in one file, loadable from JSON or YAML, read before the agent does
anything else.

This is a superset of the plain scope file (scope.example.json) — same
authorization fields (program/scope/authorized/confirmed_by/confirmed_at/
notes), same authorization RULE, enforced through safety.py's
`validate_authorization_dict` rather than a second, divergently-
maintained copy of it. The only thing this adds is `objectives`: a
written-down, ordered list of what to work on (and in what phase), so a
multi-step engagement doesn't need to be re-typed as a single
`--objective` string every run.

This does NOT add a new way to get authorized to test something. It's
still exactly the same rule as a plain scope file — `"authorized": true`
plus `"confirmed_by"` — on the exact same Scope/parse_scope machinery
every other tool call in this project is already checked against.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from d3m0n.safety import Scope, ScopeFileError, validate_authorization_dict

# Mirrors the phases pentest mode already walks through (see
# agent/prompts.py's PENTEST_MODE_DIRECTIVE) — kept as one fixed list so
# an objective's `phase` is always one of a known, ordered set, not
# arbitrary free text.
VALID_PHASES = ("recon", "map", "detect", "access_control", "defend", "verify")


class Objective(BaseModel):
    phase: str
    description: str
    done: bool = False

    model_config = {"extra": "forbid"}

    def model_post_init(self, __context) -> None:
        if self.phase not in VALID_PHASES:
            raise ValueError(f"phase must be one of {VALID_PHASES}, got {self.phase!r}")


class EngagementConfig(BaseModel):
    program: str = "<unnamed program>"
    scope: str
    authorized: bool = False
    confirmed_by: str | None = None
    confirmed_at: str | None = None
    notes: str = ""
    objectives: list[Objective] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


def _read_structured_file(path: str) -> dict:
    suffix = Path(path).suffix.lower()
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        raise ScopeFileError(f"Engagement file not found: {path!r}")
    except IsADirectoryError:
        raise ScopeFileError(f"Engagement file {path!r} is a directory, not a file.")

    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise ScopeFileError(
                f"Engagement file {path!r} has a .yaml/.yml extension but PyYAML "
                "isn't installed — `pip install pyyaml` (it's in requirements.txt)."
            )
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ScopeFileError(f"Engagement file {path!r} is not valid YAML: {exc}")
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ScopeFileError(f"Engagement file {path!r} is not valid JSON: {exc}")

    if not isinstance(data, dict):
        raise ScopeFileError(
            f"Engagement file {path!r} must contain an object/mapping at the top "
            f"level, not a {type(data).__name__}."
        )
    return data


def load_engagement_config(path: str) -> EngagementConfig:
    """Parse + validate an engagement file (JSON, or YAML if the path ends
    in .yaml/.yml). Pydantic validation errors (an unknown field, a bad
    phase name, a missing required field) are wrapped in ScopeFileError
    so callers only need to catch one error type, same as load_scope_file.
    """
    data = _read_structured_file(path)
    try:
        return EngagementConfig.model_validate(data)
    except ValidationError as exc:
        raise ScopeFileError(f"Engagement file {path!r} is invalid: {exc}")


def engagement_scope(config: EngagementConfig) -> tuple[Scope, dict]:
    """The exact same authorization rule as a plain scope file — see
    safety.py's validate_authorization_dict — regardless of how many
    objectives are attached."""
    return validate_authorization_dict(
        config.model_dump(exclude={"objectives"}), f"engagement file (program: {config.program!r})"
    )


def objectives_summary(config: EngagementConfig) -> str:
    """Render the not-yet-done objectives as the objective text the
    agent is actually given — ordered, one per line, phase-labeled.
    Empty string if there are none (e.g. a config written for its scope
    alone, with the real objective still supplied via --objective)."""
    pending = [o for o in config.objectives if not o.done]
    if not pending:
        return ""
    lines = [f"- [{o.phase}] {o.description}" for o in pending]
    return "Planned objectives, in order:\n" + "\n".join(lines)
