"""Write a findings report to disk at the end of a run."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone


def write_report(
    output_dir: str,
    objective: str,
    scope_raw: str,
    findings: list[dict],
    summary: str | None = None,
    summary_before_critic: str | None = None,
    defense_recommendations: dict | None = None,
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(output_dir, f"d3m0n_report_{stamp}.json")
    record = {
        "objective": objective,
        "scope": scope_raw,
        "generated_at": stamp,
        "summary": summary,
        "findings": findings,
    }
    if summary_before_critic:
        record["summary_before_critic_self_review"] = summary_before_critic
    if defense_recommendations:
        record["defense_recommendations"] = defense_recommendations
    with open(path, "w") as f:
        json.dump(record, f, indent=2, default=str)
    return path
