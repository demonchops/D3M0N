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
import re
from dataclasses import dataclass


class OutOfScopeError(Exception):
    """Raised when a tool call would touch something outside the confirmed scope."""


@dataclass(frozen=True)
class Scope:
    """A parsed, confirmed authorization scope."""

    raw: str
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    hostnames: tuple[str, ...]

    def contains(self, target: str) -> bool:
        target = target.strip().rstrip(".")
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
