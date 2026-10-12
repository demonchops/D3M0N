"""Known-vulnerability / misconfiguration template scanning via nuclei.

Nuclei runs community-maintained detection templates (CVEs, exposed panels,
misconfig checks, etc). It's detection-only — it reports what matched, it
doesn't weaponize anything.
"""

from __future__ import annotations

import json
import shutil
import subprocess


def nuclei_scan(target: str, severity: str = "medium,high,critical", timeout_s: int = 180) -> dict:
    """Run nuclei's templates against `target`, filtered to `severity`.

    Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    (then run `nuclei -update-templates` once).
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
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "matches": matches,
        "count": len(matches),
    }
