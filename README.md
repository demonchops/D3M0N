# D3M0N

An autonomous AI red-team agent, inspired by [BitterSecurity/Decepticon](https://github.com/BitterSecurity/Decepticon).

D3M0N uses an LLM (Claude, via the Anthropic API) as a planner/executor loop
(built on LangGraph) that can run reconnaissance and scanning tools against a
target, reason about the results, and decide what to do next. It's meant for
**authorized** penetration testing, CTFs, and security research — i.e. you
either own the target, have a signed engagement letter, or are on a
competition/lab network explicitly built for this.

## ⚠️ Authorization gate

D3M0N refuses to run against a target until you explicitly confirm you're
authorized to test it. This isn't a formality you can silently click through —
see `src/d3m0n/safety.py`. There's no bypass flag. If you need one for a
legitimate reason (e.g. CI against your own lab), edit the code yourself and
own that decision.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...

python -m d3m0n.cli --target 10.0.0.5 --scope "10.0.0.0/24" \
    --objective "Enumerate open services and identify likely vulnerable software versions"
```

You'll be asked once per run to confirm authorization before anything touches
the network.

## Architecture

```
src/d3m0n/
  cli.py          entrypoint, argument parsing, authorization prompt
  safety.py        the authorization gate + scope-fencing logic
  config.py        settings (model name, timeouts, output dir)
  agent/
    graph.py        LangGraph state machine: plan -> act -> observe -> decide
    prompts.py      system prompt + per-node prompt templates
    state.py        shared agent state (objective, scope, history, findings)
  tools/
    registry.py     tool schema registry handed to the LLM
    recon.py        passive/active recon: DNS, HTTP headers, TLS cert info
    scan.py         nmap wrapper (only runs if nmap is installed)
    report.py       writes a findings report to disk
tests/
  test_safety.py
  test_scope.py
```

### How it loops

1. **Plan** — the LLM is given the objective, the scope, and a summary of
   findings so far, and picks the next tool call (or decides it's done).
2. **Act** — the chosen tool runs, but only if its target is inside the
   confirmed scope (`safety.py` enforces this independently of what the LLM
   decides — the model proposing an out-of-scope target doesn't mean it runs).
3. **Observe** — the tool's output is summarized and appended to the shared
   state.
4. **Decide** — loop back to Plan, or stop once the objective is met or a
   step/time budget is exhausted.

### Tools included

- `dns_lookup` — resolve A/AAAA/MX/TXT records
- `http_probe` — fetch headers, status, server banner, title
- `tls_info` — certificate subject/issuer/expiry
- `nmap_scan` — wraps the local `nmap` binary if present (skipped otherwise)

These are deliberately read-only/low-impact. Nothing here throws exploits,
brute-forces credentials, or performs any destructive action — if you extend
it with more aggressive tooling, keep it scoped to things you're authorized
to run and respect the engagement's rules of engagement.

## Extending it

Add a new tool by writing a function in `tools/`, registering its schema in
`tools/registry.py`, and it becomes available to the planner automatically.
Everything funnels through `safety.enforce_scope()` first.
