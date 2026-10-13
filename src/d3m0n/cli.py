from __future__ import annotations

import argparse
import sys

from d3m0n.agent.graph import run_agent
from d3m0n.config import SETTINGS
from d3m0n.safety import (
    ScopeFileError,
    confirm_authorization,
    load_scope_file,
    parse_scope,
    print_scope_file_banner,
)
from d3m0n.tools.report import write_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="d3m0n",
        description="Autonomous recon agent for authorized security testing / bug bounty scope.",
    )
    scope_group = parser.add_mutually_exclusive_group(required=True)
    scope_group.add_argument(
        "--scope",
        help="Comma-separated IPs/CIDRs/hostnames you are authorized to test, "
        "e.g. 'example.com,10.0.0.0/24'. Prompts for an interactive authorization "
        "confirmation every run.",
    )
    scope_group.add_argument(
        "--scope-file",
        help="Path to a committed scope file (see scope.example.json) instead of "
        "--scope. No interactive prompt — the file itself is the auditable "
        'authorization record, and it has to say "authorized": true.',
    )
    parser.add_argument(
        "--objective",
        required=True,
        help="What you want the agent to work on, e.g. 'Enumerate subdomains and "
        "flag anything exposing an admin panel'",
    )
    parser.add_argument("--max-steps", type=int, default=SETTINGS.max_steps)
    args = parser.parse_args(argv)

    if args.scope_file:
        try:
            scope, meta = load_scope_file(args.scope_file)
        except ScopeFileError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print_scope_file_banner(scope, meta)
    else:
        try:
            scope = parse_scope(args.scope)
        except ValueError as exc:
            print(f"Invalid scope: {exc}", file=sys.stderr)
            return 2
        confirm_authorization(scope)

    try:
        final_state = run_agent(args.objective, scope.raw, max_steps=args.max_steps)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    report_path = write_report(
        SETTINGS.output_dir,
        args.objective,
        scope.raw,
        final_state["findings"],
    )

    print("\n" + "=" * 70)
    print("Run complete.")
    print(f"Summary: {final_state.get('summary')}")
    print(f"Findings written to: {report_path}")
    events_path = final_state.get("events_path")
    if events_path:
        print(f"Live event log: {events_path}")
        print(f"  (watch it in the Go TUI: d3m0n-tui {events_path})")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
