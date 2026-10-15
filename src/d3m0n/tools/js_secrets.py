"""Regex-based secrets/hidden-endpoint scan over a JS (or any text) file.

Fetches one URL and checks its body against a fixed, hardcoded set of
secret/endpoint patterns (AWS/Google/Slack keys, JWTs, private key
headers, generic api_key-shaped assignments, embedded API paths) — these
are the TARGET's potential secrets, exposed in their own public-ish JS,
not anything of the operator's. A match is a lead worth manual
verification (it could be a placeholder/example/test value), not a
confirmed exposure.

The pattern set is fixed and never varies by caller input — only the
target URL does — so there's no way for a model-chosen URL to turn this
into a "show me whatever's in the response" oracle the way an
unrestricted raw-content-return tool would be (see recon.py's http_probe
docstring for that class of issue): none of these patterns match
arbitrary injected content, only specific real-secret shapes. Reuses the
configured session headers automatically, same as the other recon tools.

Each kept finding is a structured object, not a bare string:
  type       which pattern matched
  match      the matched text (truncated), same as before
  confidence "high"/"medium"/"low" — a fixed per-pattern baseline (AWS/
             Google/Slack keys and a private-key header are distinctive,
             low-false-positive formats -> high; a JWT is distinctive but
             often intentionally client-visible, not inherently secret ->
             medium; the generic api_key-shaped assignment is a loose,
             keyword-triggered format prone to false positives -> medium;
             an embedded /api//admin/ path is recon info, not a secret by
             itself -> low), downgraded one tier when entropy says the
             value looks less random than a real secret should.
  entropy    Shannon entropy in bits/char of the actual secret value
             (not the surrounding "key: " text) for the patterns where
             that's a meaningful signal (AWS/Google/Slack/JWT/generic);
             None for private_key_header (fixed marker text, not random
             data) and embedded_api_path (a path, not random data).
  position   character offset of the match in the fetched body, so a
             human with the file open can jump straight to it.
  context    ~50 chars either side of the match, whitespace-collapsed to
             one line and session-redacted — this is a character window,
             not a line, specifically because minified JS often IS one
             enormous line, where "the surrounding line" would mean
             nothing.

Placeholder filtering: a value that's an obvious example/dummy (matches
a placeholder-style keyword, is one character repeated, or is a near-
sequential run like "123456789...") is kept OUT of `findings` but never
silently thrown away — it's counted in `filtered_placeholder_count` and
a capped sample lands in `filtered_placeholder_examples`, so the exclusion
itself stays auditable instead of just disappearing.

`minified_heuristic` reports on the fetched body itself (not per-match):
average/max line length and whitespace ratio, with a boolean verdict.
This is informational, not a confidence input — a real secret sitting in
a minified bundle is exactly as real as one in readable source. It
exists so a human reading `context` snippets understands why they look
the way they do, and it's also the reason `context` is always a
character window rather than "print the enclosing line".
"""

from __future__ import annotations

import math
import re
from collections import Counter

import requests

from d3m0n.config import SETTINGS

_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "private_key_header": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "generic_api_key_assignment": re.compile(
        r"""(?i)(api[_-]?key|secret|token|auth)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,64})[\"']"""
    ),
    "embedded_api_path": re.compile(
        r"""(?:\"|')(/(?:api|internal|admin)/[A-Za-z0-9_/\-]{2,80})(?:\"|')"""
    ),
}

# Baseline confidence per pattern, before any entropy-based downgrade.
_BASE_CONFIDENCE: dict[str, str] = {
    "aws_access_key_id": "high",
    "google_api_key": "high",
    "slack_token": "high",
    "jwt": "medium",
    "private_key_header": "high",
    "generic_api_key_assignment": "medium",
    "embedded_api_path": "low",
}
_CONFIDENCE_DOWNGRADE = {"high": "medium", "medium": "low", "low": "low"}

# Patterns whose matched value is supposed to be high-entropy random data,
# so entropy/placeholder heuristics are meaningful for them. A private key
# HEADER is fixed marker text (not the key itself) and an embedded path is
# human-chosen routing text, not random data -- scoring either would be
# noise, not signal, so both are deliberately left out of this set.
_SCORED_PATTERNS = {
    "aws_access_key_id",
    "google_api_key",
    "slack_token",
    "jwt",
    "generic_api_key_assignment",
}
_LOW_ENTROPY_THRESHOLD = 3.0

_PLACEHOLDER_KEYWORDS = (
    "placeholder",
    # AWS's own docs use AKIAIOSFODNN7EXAMPLE as THE canonical example
    # access key -- copy-pasted into example configs constantly, so
    # "example"/"sample" are worth the (here, negligible: ~7-char word in
    # a 16-64 char alnum/hyphen/underscore string) false-positive risk as
    # bare keywords, not just "-key"-suffixed below.
    "example",
    "sample",
    "changeme",
    "change-me",
    "change_me",
    "your-api-key",
    "your_api_key",
    "yourapikey",
    "your-key",
    "your_key",
    "yourkey",
    "insert-key",
    "insert_key",
    "insertkey",
    "replace-me",
    "replace_me",
    "replaceme",
    "not-a-real-key",
    "not_a_real_key",
    "notarealkey",
    "fake-key",
    "fake_key",
    "fakekey",
    "dummy-key",
    "dummy_key",
    "dummykey",
    "test-key",
    "test_key",
    "testkey",
    "example-key",
    "example_key",
    "examplekey",
    "sample-key",
    "sample_key",
    "samplekey",
    "xxxxxxxx",
    "00000000",
)

_MAX_MATCHES_PER_PATTERN = 15
_MAX_BODY_CHARS = 3_000_000
_CONTEXT_CHARS = 50
_MAX_FILTERED_EXAMPLES = 10


def _redact_sessions(text: str) -> str:
    secret_values = [v for v in SETTINGS.session_headers.values() if v]
    for value in secret_values:
        text = text.replace(value, "***REDACTED-SESSION-HEADER***")
    return text


def _shannon_entropy(value: str) -> float:
    """Bits of entropy per character. 0.0 for an empty/single-char-type
    string; higher means "looks more like random data", which is what a
    real generated secret (vs. a word, or a placeholder) should look
    like."""
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return round(-sum((n / length) * math.log2(n / length) for n in counts.values()), 3)


def _is_sequential_run(value: str) -> bool:
    """True if most consecutive characters step by exactly +-1 (e.g.
    "123456789012345" or "abcdefghijklmnop") -- the standard shape of a
    hand-typed placeholder, not a generated secret. A fractional
    threshold (not "every single pair") tolerates the one wraparound
    break a digit run like "...8901..." has."""
    if len(value) < 8:
        return False
    pairs = list(zip(value, value[1:]))
    matching = sum(1 for a, b in pairs if abs(ord(b) - ord(a)) == 1)
    return matching / len(pairs) >= 0.8


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(keyword in lowered for keyword in _PLACEHOLDER_KEYWORDS):
        return True
    if len(lowered) >= 8 and len(set(lowered)) <= 2:
        return True  # e.g. "AAAAAAAAAAAAAAAA" / "00000000000000000000"
    if _is_sequential_run(lowered):
        return True
    return False


def _secret_value_for_scoring(kind: str, match: re.Match) -> str:
    """The actual secret-shaped substring to run entropy/placeholder
    checks against -- for generic_api_key_assignment that's the captured
    VALUE (group 2), not the "api_key: " text next to it; for everything
    else in _SCORED_PATTERNS the whole match already IS the secret."""
    if kind == "generic_api_key_assignment":
        return match.group(2)
    return match.group(0)


def _confidence_for(kind: str, entropy: float | None) -> str:
    base = _BASE_CONFIDENCE[kind]
    if entropy is not None and entropy < _LOW_ENTROPY_THRESHOLD:
        return _CONFIDENCE_DOWNGRADE[base]
    return base


def _context_snippet(body: str, start: int, end: int) -> str:
    left = max(0, start - _CONTEXT_CHARS)
    right = min(len(body), end + _CONTEXT_CHARS)
    snippet = re.sub(r"\s+", " ", body[left:right]).strip()
    return _redact_sessions(snippet)


def _minified_heuristic(body: str) -> dict:
    """Informational only -- see module docstring for why this doesn't
    feed into confidence scoring."""
    lines = [line for line in body.split("\n") if line]
    if not lines:
        return {
            "is_likely_minified": False,
            "line_count": 0,
            "avg_line_length": 0.0,
            "max_line_length": 0,
            "whitespace_ratio": 0.0,
        }
    lengths = [len(line) for line in lines]
    max_len = max(lengths)
    avg_len = sum(lengths) / len(lengths)
    whitespace_ratio = round(sum(1 for c in body if c.isspace()) / len(body), 4)
    is_likely_minified = (max_len > 1000 and whitespace_ratio < 0.10) or (
        len(lines) <= 3 and len(body) > 2000
    )
    return {
        "is_likely_minified": is_likely_minified,
        "line_count": len(lines),
        "avg_line_length": round(avg_len, 1),
        "max_line_length": max_len,
        "whitespace_ratio": whitespace_ratio,
    }


def js_secrets_scan(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(
            url, timeout=10, allow_redirects=True, headers=SETTINGS.session_headers or None
        )
    except requests.RequestException as exc:
        return {"url": url, "error": _redact_sessions(str(exc))}

    body = resp.text[:_MAX_BODY_CHARS]
    findings = []
    filtered_count = 0
    filtered_examples = []

    for kind, pattern in _PATTERNS.items():
        seen_values: set[str] = set()
        for match in pattern.finditer(body):
            raw_value = match.group(0)
            if raw_value in seen_values:
                continue
            seen_values.add(raw_value)

            if kind in _SCORED_PATTERNS and _looks_like_placeholder(
                _secret_value_for_scoring(kind, match)
            ):
                filtered_count += 1
                if len(filtered_examples) < _MAX_FILTERED_EXAMPLES:
                    filtered_examples.append(
                        {"type": kind, "match": _redact_sessions(raw_value[:80])}
                    )
            else:
                entropy = (
                    _shannon_entropy(_secret_value_for_scoring(kind, match))
                    if kind in _SCORED_PATTERNS
                    else None
                )
                findings.append(
                    {
                        "type": kind,
                        "match": _redact_sessions(raw_value[:200]),
                        "confidence": _confidence_for(kind, entropy),
                        "entropy": entropy,
                        "position": match.start(),
                        "context": _context_snippet(body, match.start(), match.end()),
                    }
                )

            if len(seen_values) >= _MAX_MATCHES_PER_PATTERN:
                break

    return {
        "url": url,
        "status": resp.status_code,
        "length": len(resp.text),
        "finding_count": len(findings),
        "findings": findings,
        "filtered_placeholder_count": filtered_count,
        "filtered_placeholder_examples": filtered_examples,
        "minified_heuristic": _minified_heuristic(body),
    }
