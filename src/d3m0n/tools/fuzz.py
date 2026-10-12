"""Content/directory discovery via ffuf.

This is "what pages exist" discovery over GET requests against a wordlist —
not a login-brute-forcer. Don't point it at an auth endpoint with a
credential wordlist; that's a different (and deliberately not included)
class of tool.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

_DEFAULT_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

# Used only if nothing above exists on disk, so the tool still does
# *something* useful without extra setup.
_FALLBACK_WORDS = [
    "admin", "login", "api", "backup", "config", "dashboard", "debug",
    "docs", "health", "internal", "metrics", "status", "test", "tmp",
    "upload", "uploads", ".env", ".git/config", "robots.txt", "sitemap.xml",
    "swagger.json", "swagger-ui", "graphql", "actuator", "wp-admin",
]


def _resolve_wordlist(wordlist: str | None) -> str:
    if wordlist and os.path.isfile(wordlist):
        return wordlist
    for candidate in _DEFAULT_WORDLIST_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    fd, path = tempfile.mkstemp(suffix="_d3m0n_wordlist.txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(_FALLBACK_WORDS))
    return path


def ffuf_scan(target: str, wordlist: str | None = None, timeout_s: int = 120) -> dict:
    """Fuzz paths on `target` using ffuf (falls back to a tiny built-in wordlist).

    Install: go install github.com/ffuf/ffuf/v2@latest
    """
    binary = shutil.which("ffuf")
    if binary is None:
        return {
            "target": target,
            "error": "ffuf is not installed; skipping. Install: "
            "go install github.com/ffuf/ffuf/v2@latest",
        }

    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    url = target.rstrip("/") + "/FUZZ"
    wl = _resolve_wordlist(wordlist)

    cmd = [
        binary, "-u", url, "-w", wl, "-of", "json", "-o", "-", "-s",
        "-mc", "200,204,301,302,307,401,403",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
    except subprocess.TimeoutExpired:
        return {"target": target, "error": f"ffuf timed out after {timeout_s}s"}

    hits = []
    try:
        data = json.loads(proc.stdout) if proc.stdout.strip() else {}
        for r in data.get("results", []):
            hits.append({"url": r.get("url"), "status": r.get("status"), "length": r.get("length")})
    except json.JSONDecodeError:
        pass

    return {
        "target": target,
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "hits": hits,
        "count": len(hits),
    }
