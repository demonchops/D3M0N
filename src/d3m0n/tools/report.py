"""Write a findings report to disk at the end of a run."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone


def write_report(output_dir: str, objective: str, scope_raw: str, findings: list[dict]) -> str:
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(output_dir, f"d3m0n_report_{stamp}.json")
    with open(path, "w") as f:
        json.dump(
            {
                "objective": objective,
                "scope": scope_raw,
                "generated_at": stamp,
                "findings": findings,
            },
            f,
            indent=2,
            default=str,
        )
    return path
