"""Subdomain enumeration via subfinder (skips cleanly if not installed)."""

from __future__ import annotations

import json
import shutil
import subprocess


def subfinder_scan(target: str, timeout_s: int = 60) -> dict:
    """Enumerate subdomains of `target` using subfinder's passive sources.

    Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    """
    binary = shutil.which("subfinder")
    if binary is None:
        return {
            "target": target,
            "error": "subfinder is not installed; skipping. Install: "
            "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        }

    cmd = [binary, "-d", target, "-silent", "-json"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
    except subprocess.TimeoutExpired:
        return {"target": target, "error": f"subfinder timed out after {timeout_s}s"}

    subdomains = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            subdomains.append(json.loads(line).get("host", line))
        except json.JSONDecodeError:
            subdomains.append(line)

    return {
        "target": target,
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "subdomains": subdomains,
        "count": len(subdomains),
        "stderr": (proc.stderr or "")[:2000],
    }
