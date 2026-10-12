from __future__ import annotations

import argparse
import sys

from d3m0n.agent.graph import run_agent
from d3m0n.config import SETTINGS
from d3m0n.safety import confirm_authorization, parse_scope
from d3m0n.tools.report import write_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="d3m0n",
        description="Autonomous recon agent for authorized security testing / bug bounty scope.",
    )
    parser.add_argument(
        "--scope",
        required=True,
        help="Comma-separated IPs/CIDRs/hostnames you are authorized to test, "
        "e.g. 'example.com,10.0.0.0/24'",
    )
    parser.add_argument(
        "--objective",
        required=True,
        help="What you want the agent to work on, e.g. 'Enumerate subdomains and "
        "flag anything exposing an admin panel'",
    )
    parser.add_argument("--max-steps", type=int, default=SETTINGS.max_steps)
    args = parser.parse_args(argv)

    try:
        scope = parse_scope(args.scope)
    except ValueError as exc:
        print(f"Invalid scope: {exc}", file=sys.stderr)
        return 2

    confirm_authorization(scope)

    try:
        final_state = run_agent(args.objective, args.scope, max_steps=args.max_steps)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    report_path = write_report(
        SETTINGS.output_dir,
        args.objective,
        args.scope,
        final_state["findings"],
    )

    print("\n" + "=" * 70)
    print("Run complete.")
    print(f"Summary: {final_state.get('summary')}")
    print(f"Findings written to: {report_path}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
