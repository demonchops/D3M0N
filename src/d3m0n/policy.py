"""Policy Engine: the one place scope and tool-whitelist checks are
asked, so "did this action pass policy" has a single, inspectable
answer instead of being implicit across a handful of call sites.

This mostly WRAPS mechanisms that already exist and are already
mandatory — safety.py's enforce_scope, and the tool registry's own fixed
dispatch table — rather than inventing new ones. `registry.run_tool()`
constructs a PolicyEngine and asks it before dispatching, so this is the
actual gate the real dispatch path goes through, not a parallel object
nothing calls.

Two things here are genuinely new, not just a wrapper:

1. `allowed_tools` — an optional further restriction below the global
   tool whitelist. Nothing currently populates this (no engagement-
   config field feeds it yet); it's a ready extension point for when
   one does, not a gap being quietly papered over.
2. `redact_known_secrets()` — one consolidated redaction pass over
   every secret-bearing setting this project knows about (both session-
   header accounts, the Burp REST API key, the Burp login username/
   password, the local-model and Anthropic API keys). It exists because
   the per-tool redaction helpers (idor_check._redact_sessions,
   burp_scanner._redact_all, js_secrets._redact_sessions, ...) each only
   cover that one tool's own result text — none of them reach the
   agent's own free-text summary, which is exactly where a secret that
   slipped past a tool's own redaction would end up. graph.py's
   run_agent() runs every returned summary through this before anyone
   sees it. It does NOT replace the per-tool helpers; it covers the one
   place they don't reach.

What this deliberately does NOT do: scan the model's own prose for
"unsafe suggestions" by keyword or pattern. This whole project's system
prompt instructs the model to write manual verification recipes that
can legitimately read like "try X as the parameter value" — a filter
broad enough to catch something resembling an exploit would just as
reliably mangle that correct, intended output, and one narrow enough not
to would catch nothing real either. Passive-only stays what it already
was: an architectural fact (no tool in the registry can exploit or
tamper with a target), checked here by `tool_allowed`'s whitelist, not a
runtime text heuristic layered on top of it.
"""

from __future__ import annotations

from d3m0n.config import SETTINGS
from d3m0n.safety import Scope, enforce_scope


class PolicyEngine:
    def __init__(
        self,
        scope: Scope,
        known_tools: frozenset[str],
        allowed_tools: frozenset[str] | None = None,
    ) -> None:
        self.scope = scope
        self.known_tools = known_tools
        # None means "no further restriction beyond the global whitelist"
        # — not "nothing is allowed". An empty frozenset, if ever passed,
        # correctly means exactly that: nothing.
        self.allowed_tools = allowed_tools

    def tool_allowed(self, name: str) -> bool:
        if name not in self.known_tools:
            return False
        if self.allowed_tools is not None and name not in self.allowed_tools:
            return False
        return True

    def check_scope(self, target: str) -> None:
        """Raises safety.OutOfScopeError on violation — unchanged from
        calling enforce_scope() directly, which is all this does."""
        enforce_scope(self.scope, target)


def _known_secret_values() -> list[str]:
    values: list[str] = []
    values.extend(v for v in SETTINGS.session_headers.values() if v)
    values.extend(v for v in SETTINGS.session_headers_b.values() if v)
    for value in (
        SETTINGS.burp_api_key,
        SETTINGS.burp_login_username,
        SETTINGS.burp_login_password,
        SETTINGS.local_model_api_key,
        SETTINGS.anthropic_api_key,
    ):
        if value:
            values.append(value)
    return values


def redact_known_secrets(text: str | None) -> str:
    """Replace every currently-configured secret value (see module
    docstring) wherever it appears in `text`. Safe to call on anything,
    including None/empty — returns "" rather than raising."""
    if not text:
        return text or ""
    for value in _known_secret_values():
        text = text.replace(value, "***REDACTED***")
    return text
