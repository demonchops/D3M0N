from __future__ import annotations

import argparse
import sys

from d3m0n.agent.graph import run_agent
from d3m0n.agent.prompts import PENTEST_MODE_DIRECTIVE, PENTEST_MODE_MIN_STEPS
from d3m0n.config import SETTINGS
from d3m0n.engagement import engagement_scope, load_engagement_config, objectives_summary
from d3m0n.safety import (
    ScopeFileError,
    confirm_authorization,
    load_scope_file,
    parse_scope,
    print_scope_file_banner,
)
from d3m0n.tools.report import write_report


def _resolve_mode(mode: str, max_steps: int, default_max_steps: int) -> tuple[str | None, int, bool]:
    """Pure function, easy to unit-test without touching argparse/the
    agent loop. Returns (methodology_directive_or_None, resolved_max_steps,
    use_critic_pass).

    An explicit --max-steps (anything other than the untouched default) is
    always respected as-is, in either direction — pentest mode only raises
    the floor when the operator didn't set one, it never second-guesses an
    explicit choice.
    """
    if mode != "pentest":
        return None, max_steps, False
    resolved_steps = max_steps
    if max_steps == default_max_steps:
        resolved_steps = max(max_steps, PENTEST_MODE_MIN_STEPS)
    return PENTEST_MODE_DIRECTIVE, resolved_steps, True


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
    scope_group.add_argument(
        "--engagement-file",
        help="Path to a structured engagement config (JSON or YAML — see "
        "engagement.example.json/.yaml) combining scope with an ordered list of "
        "objectives, instead of --scope-file. Same authorization rule as "
        '--scope-file ("authorized": true, "confirmed_by" required); supplies '
        "--objective automatically from its objectives list.",
    )
    parser.add_argument(
        "--objective",
        help="What you want the agent to work on, e.g. 'Enumerate subdomains and "
        "flag anything exposing an admin panel'. Required unless --engagement-file "
        "supplies objectives of its own — if both are given, this is appended as "
        "an extra instruction alongside the file's objectives.",
    )
    parser.add_argument("--max-steps", type=int, default=SETTINGS.max_steps)
    parser.add_argument(
        "--mode",
        choices=["default", "pentest"],
        default="default",
        help="'pentest' works the full methodology systematically across the whole scope "
        "(enumerate -> map -> detect -> access-control, breadth-first) instead of just "
        "the specific objective text, raises the step budget if you haven't set one "
        "explicitly, and adds a skeptical self-review pass before the final report.",
    )
    args = parser.parse_args(argv)

    if args.engagement_file:
        try:
            config = load_engagement_config(args.engagement_file)
            scope, meta = engagement_scope(config)
        except ScopeFileError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print_scope_file_banner(scope, meta, source_label="engagement file")
        objective_text = objectives_summary(config)
        if args.objective:
            objective_text = (
                f"{objective_text}\n\nAdditional instruction: {args.objective}"
                if objective_text
                else args.objective
            )
        if not objective_text:
            print(
                f"{args.engagement_file!r} has no pending objectives and no --objective "
                "was given — nothing to work on.",
                file=sys.stderr,
            )
            return 2
    elif args.scope_file:
        try:
            scope, meta = load_scope_file(args.scope_file)
        except ScopeFileError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print_scope_file_banner(scope, meta)
        if not args.objective:
            print("--objective is required when using --scope-file.", file=sys.stderr)
            return 2
        objective_text = args.objective
    else:
        try:
            scope = parse_scope(args.scope)
        except ValueError as exc:
            print(f"Invalid scope: {exc}", file=sys.stderr)
            return 2
        confirm_authorization(scope)
        if not args.objective:
            print("--objective is required when using --scope.", file=sys.stderr)
            return 2
        objective_text = args.objective

    if SETTINGS.backend == "local":
        print(f"[backend] local model at {SETTINGS.local_model_url!r} ({SETTINGS.model})")
    else:
        print(f"[backend] Claude via the Anthropic API ({SETTINGS.model})")

    methodology_directive, resolved_max_steps, use_critic_pass = _resolve_mode(
        args.mode, args.max_steps, SETTINGS.max_steps
    )
    if args.mode == "pentest":
        print(
            f"[pentest mode] step budget {resolved_max_steps}, full methodology, "
            "skeptical self-review pass before the final report."
        )

    try:
        final_state = run_agent(
            objective_text,
            scope.raw,
            max_steps=resolved_max_steps,
            methodology_directive=methodology_directive,
            use_critic_pass=use_critic_pass,
        )
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    report_path = write_report(
        SETTINGS.output_dir,
        objective_text,
        scope.raw,
        final_state["findings"],
        summary=final_state.get("summary"),
        summary_before_critic=final_state.get("summary_before_critic"),
        defense_recommendations=final_state.get("defense_recommendations"),
    )

    print("\n" + "=" * 70)
    print("Run complete.")
    if final_state.get("summary_before_critic"):
        print("Summary (after self-review pass; see report for the pre-review draft too):")
    else:
        print("Summary:")
    print(final_state.get("summary"))
    defense = final_state.get("defense_recommendations")
    if defense and defense.get("entries"):
        print(f"Defense recommendations: {len(defense['entries'])} (see report for remediation/detection detail)")
    elif defense and defense.get("generation_error"):
        print(f"Defense recommendations: generation failed ({defense['generation_error']})")
    print(f"Findings written to: {report_path}")
    events_path = final_state.get("events_path")
    if events_path:
        print(f"Live event log: {events_path}")
        print(f"  (watch it in the Go TUI: d3m0n-tui {events_path})")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
