"""Authorization gate and scope fencing.

Two independent protections live here, and both must pass before any tool
touches the network:

1. `confirm_authorization()` — an interactive, explicit, per-run confirmation
   that the operator is authorized to test the declared scope. This is asked
   once, up front, and is not something the LLM can answer on your behalf.

2. `enforce_scope()` — a hard check, run again before *every* tool call,
   that the tool's target actually falls inside the confirmed scope. The
   planner (the LLM) proposes targets; this function is the only thing that
   decides whether a proposal is allowed to execute. A prompt-injected or
   hallucinated out-of-scope target is rejected here regardless of what the
   model "decided".
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from urllib.parse import urlparse


class OutOfScopeError(Exception):
    """Raised when a tool call would touch something outside the confirmed scope."""


@dataclass(frozen=True)
class Scope:
    """A parsed, confirmed authorization scope."""

    raw: str
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    hostnames: tuple[str, ...]

    def contains(self, target: str) -> bool:
        target = target.strip()
        # A full URL (scheme://host/path...) — several tool schemas accept
        # "URL or hostname", so reduce to just the hostname before matching.
        # Without this, a full URL would fail both checks below and get
        # rejected as out-of-scope even when its host genuinely is in
        # scope — fails closed (never wrongly *allows* anything) but was
        # wrong in the safe direction, which is still worth fixing.
        if "://" in target:
            try:
                parsed_host = urlparse(target).hostname
            except ValueError:
                # A malformed bracketed host (e.g. an unmatched "[") makes
                # urlparse raise instead of just failing to find a host.
                # contains() is the project's one hardened chokepoint and
                # must never raise on a bad target, only reject it — leave
                # `target` as the original string so it still fails closed
                # via the exact/subdomain-suffix checks below.
                parsed_host = None
            if parsed_host:
                target = parsed_host
        target = target.rstrip(".")
        # IP or CIDR target: must fall inside one of the authorized networks.
        try:
            ip = ipaddress.ip_address(target)
            return any(ip in net for net in self.networks)
        except ValueError:
            pass
        # Hostname target: must exactly match, or be a subdomain of, an
        # authorized hostname.
        target_l = target.lower()
        for host in self.hostnames:
            if target_l == host or target_l.endswith("." + host):
                return True
        return False


def parse_scope(scope_str: str) -> Scope:
    """Parse a comma-separated scope string of IPs/CIDRs/hostnames."""
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    hostnames: list[str] = []
    for item in (s.strip() for s in scope_str.split(",")):
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
            continue
        except ValueError:
            pass
        if re.fullmatch(r"[A-Za-z0-9*._-]+", item):
            hostnames.append(item.lower().lstrip("*.").rstrip("."))
        else:
            raise ValueError(f"Could not parse scope entry: {item!r}")
    if not networks and not hostnames:
        raise ValueError("Scope is empty — refusing to run with no defined boundary.")
    return Scope(raw=scope_str, networks=tuple(networks), hostnames=tuple(hostnames))


def confirm_authorization(scope: Scope, *, assume_yes: bool = False) -> None:
    """Interactively require the operator to confirm authorization.

    Raises SystemExit if the operator declines. `assume_yes` exists only for
    non-interactive test runs — it is never set by a CLI flag that a normal
    invocation would stumble into.
    """
    print("=" * 70)
    print("D3M0N — Autonomous Red-Team Agent")
    print("=" * 70)
    print(f"Declared scope: {scope.raw}")
    print(
        "\nBy proceeding you confirm that YOU hold explicit, current "
        "authorization to run security testing against everything in the "
        "scope above (e.g. you own it, have a signed engagement/rules of "
        "engagement, or it's a lab/CTF environment built for this).\n"
    )
    if assume_yes:
        print("[assume_yes] Authorization confirmed non-interactively.")
        return
    answer = input("Type 'I am authorized' to continue: ").strip()
    if answer != "I am authorized":
        raise SystemExit("Authorization not confirmed. Exiting.")


def enforce_scope(scope: Scope, target: str) -> None:
    """Raise OutOfScopeError if `target` is not inside `scope`."""
    if not scope.contains(target):
        raise OutOfScopeError(
            f"Refusing to run against {target!r}: outside confirmed scope "
            f"({scope.raw!r}). This is enforced independently of the "
            f"agent's plan."
        )


class ScopeFileError(Exception):
    """Raised when a scope file is missing, malformed, or not marked authorized."""


def validate_authorization_dict(data: dict, source: str) -> tuple[Scope, dict]:
    """The authorization rule itself, factored out of load_scope_file so
    engagement.py's richer config (scope + an ordered objectives list,
    loadable from JSON or YAML) enforces the exact same rule through this
    one function rather than a second, divergently-maintained copy of it.
    `source` is just a label for the error message (a file path, or a
    description of where the dict came from)."""
    if data.get("authorized") is not True:
        raise ScopeFileError(
            f'{source!r} does not have "authorized": true. Refusing to run. Edit '
            f"the file yourself to confirm you hold current authorization for "
            f"this exact scope before flipping that to true."
        )
    confirmed_by = data.get("confirmed_by")
    if not confirmed_by:
        raise ScopeFileError(f'{source!r} is missing "confirmed_by" (who is vouching for this).')
    scope_str = data.get("scope")
    if not scope_str:
        raise ScopeFileError(f'{source!r} is missing "scope".')

    scope = parse_scope(scope_str)
    meta = {
        # `or` rather than dict.get(key, default): a source whose schema
        # always materializes every field (e.g. a Pydantic model's
        # .model_dump(), as engagement.py passes in) sets these to None
        # rather than omitting them, which would make the dict.get(...,
        # default) form never fall through to its default at all.
        "program": data.get("program") or "<unnamed program>",
        "confirmed_by": confirmed_by,
        "confirmed_at": data.get("confirmed_at") or "<unspecified>",
        "notes": data.get("notes") or "",
    }
    return scope, meta


def load_scope_file(path: str) -> tuple[Scope, dict]:
    """Load a committed scope file instead of prompting every run.

    This trades the interactive per-run prompt for a one-time, auditable,
    user-authored file. It is NOT a bypass of the authorization check — the
    file itself has to contain an explicit `"authorized": true` plus who
    confirmed it, or this refuses to run. You still have to go write that
    down yourself; nothing here sets it for you.

    Expected JSON shape:
        {
          "program": "Acme Corp Bug Bounty (HackerOne)",
          "scope": "*.acme.com, 10.20.0.0/24",
          "authorized": true,
          "confirmed_by": "your-handle",
          "confirmed_at": "2026-10-12",
          "notes": "optional free text, e.g. a link to the program page"
        }
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        raise ScopeFileError(f"Scope file not found: {path!r}")
    except json.JSONDecodeError as exc:
        raise ScopeFileError(f"Scope file {path!r} is not valid JSON: {exc}")

    return validate_authorization_dict(data, path)


def print_scope_file_banner(scope: Scope, meta: dict, *, source_label: str = "scope file") -> None:
    """Print what was loaded from a scope/engagement file (no input()
    prompt — the file itself is the auditable confirmation). engagement.py
    passes source_label="engagement file" so the banner names what was
    actually loaded rather than always claiming "scope file"."""
    print("=" * 70)
    print("D3M0N — Autonomous Red-Team Agent")
    print("=" * 70)
    print(f"Program: {meta['program']}")
    print(f"Scope: {scope.raw}")
    print(f"Authorization confirmed by: {meta['confirmed_by']} on {meta['confirmed_at']}")
    if meta.get("notes"):
        print(f"Notes: {meta['notes']}")
    print(f"(loaded from {source_label} — no per-run prompt)")
    print("=" * 70)
