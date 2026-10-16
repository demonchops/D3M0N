"""Known-vulnerability / misconfiguration template scanning via nuclei.

Nuclei runs community-maintained detection templates (CVEs, exposed panels,
misconfig checks, etc). It's detection-only — it reports what matched, it
doesn't weaponize anything.
"""

from __future__ import annotations

import json
import shutil
import subprocess

from d3m0n.config import SETTINGS


def _redacted_command(cmd: list[str]) -> str:
    """Join `cmd` for display, replacing any configured session-header
    VALUE wherever it appears. The real `cmd` still gets the real value —
    this only controls what a result dict (and therefore the LLM
    conversation and the saved JSON report) ever sees."""
    secret_values = [v for v in SETTINGS.session_headers.values() if v]
    parts = []
    for part in cmd:
        if any(v in part for v in secret_values):
            parts.append("***REDACTED-SESSION-HEADER***")
        else:
            parts.append(part)
    return " ".join(parts)


def nuclei_scan(target: str, severity: str = "medium,high,critical", timeout_s: int = 180) -> dict:
    """Run nuclei's templates against `target`, filtered to `severity`.

    Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    (then run `nuclei -update-templates` once). If D3M0N_SESSION_HEADERS is
    configured, those headers ride along on every request automatically.
    """
    binary = shutil.which("nuclei")
    if binary is None:
        return {
            "target": target,
            "error": "nuclei is not installed; skipping. Install: "
            "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest "
            "(then run `nuclei -update-templates` once)",
        }

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    cmd = [binary, "-u", target, "-severity", severity, "-silent", "-jsonline"]
    for name, value in SETTINGS.session_headers.items():
        cmd += ["-H", f"{name}: {value}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
    except subprocess.TimeoutExpired:
        return {"target": target, "error": f"nuclei timed out after {timeout_s}s"}

    matches = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info", {})
        matches.append(
            {
                "template": item.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched_at": item.get("matched-at"),
            }
        )

    return {
        "target": target,
        "command": _redacted_command(cmd),
        "returncode": proc.returncode,
        "matches": matches,
        "count": len(matches),
    }
