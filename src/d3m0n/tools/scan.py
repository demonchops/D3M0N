"""nmap wrapper. Skips cleanly if nmap isn't installed."""

from __future__ import annotations

import shutil
import subprocess


def nmap_scan(target: str, ports: str = "1-1024", timeout_s: int = 60) -> dict:
    """Run a version-detection scan against `target` for `ports`.

    Uses -sV (service/version detection) and -Pn (skip host-discovery ping,
    since many authorized targets block ICMP) but no exploit or brute-force
    scripts — this stays squarely in "recon" territory.
    """
    binary = shutil.which("nmap")
    if binary is None:
        return {"target": target, "error": "nmap is not installed on this host; skipping."}

    cmd = [binary, "-sV", "-Pn", "-p", ports, target]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False
        )
    except subprocess.TimeoutExpired:
        return {"target": target, "error": f"nmap timed out after {timeout_s}s"}

    return {
        "target": target,
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
