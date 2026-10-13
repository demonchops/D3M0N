# D3M0N

An autonomous AI recon/detection agent for **authorized** bug bounty hunting and
penetration testing, inspired by [BitterSecurity/Decepticon](https://github.com/BitterSecurity/Decepticon).

D3M0N uses Claude (via the Anthropic API) as a planner/executor loop (built on
LangGraph) that runs recon and detection tools against a target, reasons about
the results, and decides what to check next — enumerate subdomains, probe
hosts, match known-vulnerability templates, discover hidden content — until
it's covered what you asked for. A separate Go program gives you a live
terminal dashboard of a run in progress.

**Honest framing:** this automates the recon phase bounty hunters already
automate with roughly these same tools (subfinder/nuclei/nmap/ffuf) — it's a
faster, better-narrated version of "run the usual recon chain and read the
output," not a vulnerability-discovery engine for logic bugs. It won't find
IDOR, broken auth, or business-logic flaws — those need manual testing against
an authenticated session. It earns its keep on large/under-explored attack
surface and as a first pass before you go manual on anything it surfaces.

## ⚠️ Scope is the boundary, not a formality

Bug bounty programs are contractually scope-limited — testing outside a
program's defined scope can get you banned from the platform and, in some
cases, turns "bug bounty" into unauthorized access under the CFAA or your
country's equivalent. That's on you personally, not a theoretical risk. So
D3M0N enforces scope two ways, and there's no flag that turns either off:

1. You confirm authorization once per run (or once via a committed scope
   file — see below) before anything touches the network.
2. Every tool call is checked against that scope independently of whatever
   the model decided (`safety.enforce_scope()`), so a hallucinated or
   prompt-injected out-of-scope target just fails instead of running.

Within that boundary, the goal is to find as much as it genuinely can.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...

python -m d3m0n.cli --scope "*.example.com" \
    --objective "Enumerate subdomains, probe anything live, and flag anything \
interesting for a bug bounty report"
```

You'll be asked once per run to confirm authorization before anything touches
the network, unless you use `--scope-file` (below).

### Low-friction repeated runs: scope files

Typing a confirmation sentence every run gets old fast if you're working one
program over several sessions. Copy `scope.example.json` to `scope.json`
(already gitignored — don't commit a program's real scope), fill in the real
scope and who's confirming it, flip `"authorized"` to `true`, and run with
`--scope-file` instead of `--scope`:

```bash
cp scope.example.json scope.json   # then edit it
python -m d3m0n.cli --scope-file scope.json --objective "..."
```

No interactive prompt — the file itself, with `"authorized": true` and a
`confirmed_by`, is the auditable record. `load_scope_file()` refuses to run
if either is missing, so copying the example file unedited fails safe (it
ships with `"authorized": false`).

## Live TUI

`tui/` is a small, separate Go module — a read-only terminal dashboard that
live-tails a run's JSONL event log (`src/d3m0n/agent/events.py`) and renders
objective/scope, step progress, in-flight tool calls, a scrolling log of
completed calls, a findings counter, and elapsed time.

It's a pure viewer, verified both by code inspection and by tracing a full
run under `strace`: it only ever reads the one file path you give it, polling
by byte offset every ~300ms — no network access, no subprocess execution, no
OS-specific file-watcher dependency. That matters here specifically because
D3M0N's one hard invariant is that scope enforcement can't be bypassed; a
"viewer" with its own ability to make network/tool calls would undermine
that, so it has none.

Build it:

```bash
cd tui
go build -o d3m0n-tui .
```

Run it against a run's event file — it's fine to start this before the run
begins, or point it at a file that's still being appended to:

```bash
./tui/d3m0n-tui path/to/events.jsonl
```

The CLI prints the events path for the current run when it finishes (and
it's also predictable mid-run: `{output_dir}/events_<UTC timestamp>.jsonl`).
Press `q`, `esc`, or `Ctrl-C` to quit. Once a `run_done` event arrives, the
dashboard shows `RUN COMPLETE` with the final summary and stops polling.

## Pentest mode

```bash
python -m d3m0n.cli --scope "*.example.com" \
    --objective "Find anything interesting" --mode pentest
```

The default mode just works your `--objective` text with whatever tools
Claude decides to use. `--mode pentest` instead works a fixed methodology
systematically across the **whole** scope, breadth-first, rather than
stopping at the first interesting thing it notices:

1. **Enumerate** every scope domain (`subfinder_scan`) and every host that
   comes back live (`dns_lookup`/`http_probe`/`tls_info`) before going deep
   on any single one.
2. **Map** each live host with `crawl_site` and `ffuf_scan` to find real
   paths/forms/JS files instead of guessing.
3. **Detect**: `nuclei_scan` and `burp_scan` (batching every discovered path
   into one call) on every live host; `js_secrets_scan` every discovered JS
   file; `graphql_introspect` anything that looks like GraphQL.
4. **Access control**: `idor_check` (with `enumerate_range` set on numeric
   ids) on every resource-shaped URL found while browsing authenticated
   content.
5. Only then does it call `finish`.

It also raises the step budget (to 60, unless you've explicitly set
`--max-steps` yourself — an explicit value is always respected, never
second-guessed) and adds a **skeptical self-review pass**: one extra,
separate Claude call that reads the draft summary against the actual raw
tool findings and revises anything that reads more confident than the
evidence supports before the report is written. If it revises anything,
both versions are saved (`summary` and `summary_before_critic_self_review`
in the JSON report) so you can see what got toned down and why.

**Calibrating expectations:** this runs the real methodology more
exhaustively and more systematically than hand-crafting an objective
each time — it's genuinely the most thorough this toolkit gets. It is
still everything described below, run more completely: real detection
tools finding real patterns, not a different, smarter engine underneath.
It won't find a novel logic bug no tool here has a pattern for, and it
still only ever reports leads with a verification recipe, never a
guarantee.

## Burp Suite integration

Two tools, because which one applies depends on your Burp edition — and in
both cases, **the agent explains a finding and tells you how to verify/PoC
it yourself; it never does that step for you.** There's no Repeater/Intruder-
style request-tampering tool in this registry at all, by design, so that's a
tooling boundary on top of the prompt instruction, not just a prompt instruction.

- **`burp_scan`** — Burp Suite **Professional/Enterprise only**. Drives
  Burp's own Scanner (passive + active detection) against an in-scope
  target via Burp's REST API and reports back whatever issues Burp's engine
  finds. Enable it in Burp (`Settings > Suite > REST API`), then:
  ```bash
  export D3M0N_BURP_API_URL=http://127.0.0.1:1337
  export D3M0N_BURP_API_KEY=...   # only if you set one in Burp
  ```
  Community Edition has no Scanner and no REST API — `burp_scan` returns a
  clear error telling you that if it's not configured/reachable, same as
  nmap/subfinder/etc. do when their binary is missing.

- **`burp_traffic_review`** — works with **Community Edition too**. In
  Burp: `Proxy > HTTP history`, select requests, right-click → `Save items`
  → XML. Point the agent at that file and it reviews the captured traffic
  for things worth a manual look (missing security headers, cookies
  without `Secure`/`HttpOnly`, a query parameter reflected verbatim in the
  response, verbose error pages) — leads, not confirmed vulnerabilities.
  Every host in the file is checked against scope independently; anything
  outside scope is counted and dropped before the agent ever sees it, so
  unrelated sites in your proxy history never leak into a report.

For every finding either tool surfaces, the system prompt requires three
things in the write-up: what the vulnerability class is and why it matters,
why *this* instance looks like it (the actual evidence, not inflated
confidence), and a concrete step-by-step manual verification recipe — e.g.
"open this request in Repeater, change parameter X to Y, resend, check for
Z in the response." You run that step; the agent only ever writes it down.

### Authenticated scanning

Unauthenticated-only scanning caps you to the attack surface everyone else
has already hit. To test as a logged-in (test!) account instead:

```bash
export D3M0N_SESSION_HEADERS="Cookie: sessionid=abc123"
# multiple headers: one "Name: value" per line
```

`http_probe`, `nuclei_scan`, and `ffuf_scan` include these headers on every
request automatically. **This is never an LLM tool parameter** — the model
never sees or sets the credential, and it's redacted out of anything a tool
returns (so it can't end up in the conversation sent to Claude's API or in
the saved JSON report). Treat it like an API key: don't commit it, and
check what's in a report/transcript before sharing one if this was set
while generating it.

For `burp_scan` specifically, authenticated scanning works through Burp's
own mechanisms: set `D3M0N_BURP_LOGIN_USERNAME`/`D3M0N_BURP_LOGIN_PASSWORD`
for Burp's auto-login during the scan, or set up a Session Handling Rule
in Burp's UI (`Project options > Sessions`), save it as a named Scanner
configuration, and pass that name via the `scan_config_name` tool
parameter — the name is just a label, not a secret, so it's fine for the
model to reference it.

`burp_scan` also takes a `paths` list, so the agent can batch every path
worth scanning on a host (e.g. everything `ffuf_scan` just discovered) into
one Burp task instead of one call per path.

### Broken access control / IDOR (`idor_check`)

Everything above tests one identity's own access. IDOR/broken access
control — probably the most common real bounty payout — only shows up
when you compare TWO different accounts against the same resource. Set
up a second test account and configure its session the same way as the
first:

```bash
export D3M0N_SESSION_HEADERS="Cookie: sessionid=alice-session"     # primary ("A")
export D3M0N_SESSION_HEADERS_B="Cookie: sessionid=bob-session"     # second account ("B")
```

`idor_check` then requests one resource URL (e.g. one you noticed while
browsing as A, like `/api/orders/4471`) as A, as B, and anonymously, and
returns all three side by side — status, length, a snippet, and how
similar B's response body is to A's. It never decides this is a real
finding; a high similarity plus a non-error status for B is a lead the
agent writes up with a manual verification recipe, same as everything
else here.

It's bounded the same way `http_probe` is, for the same reason: a query
string lets the caller embed an arbitrary value, so without a
restriction this would be a second request-tampering primitive. The
path/query (fully percent-decoded, so it can't be dodged by encoding,
including a double-encoded payload) must be plain resource-reference
characters — letters, digits, `/ _ . - ~ : = & ? ,` — or the tool refuses
rather than send it.

**ID enumeration.** Pass `enumerate_range` > 0 and it also probes that
many nearby numeric ids under session B alone — e.g. `/orders/4471` with
`enumerate_range=5` also tries 4466–4470 and 4472–4476 — the standard
IDOR-by-enumeration technique, which usually finds more than checking one
URL at a time. The new ids come from integer arithmetic on a number
already found in the URL, never from a new string the model supplies, so
this can't reopen the request-tampering question above — but every
generated URL is re-validated anyway before being requested, rather than
trusting the substitution code to be bug-free. Capped at 10 either side,
with a short pause between requests so this can't turn into a rapid-fire
scrape of a real target. It only works on a plain numeric id (path
segment or an `..._id=123`-shaped query value) — not on a UUID, where
"nearby" isn't a meaningful concept.

## Architecture

```
src/d3m0n/
  cli.py           entrypoint, argument parsing, authorization (prompt or file)
  safety.py         scope parsing, the authorization gate, scope-file loading
  config.py         settings (model name, timeouts, output dir, result-size cap)
  agent/
    graph.py         LangGraph state machine + the efficiency layer (below)
    prompts.py       system prompt + per-node prompt templates
    state.py         shared agent state (objective, scope, history, findings)
    events.py        best-effort JSONL event log, read by tui/
  tools/
    registry.py      tool schema registry + the scope-enforcing dispatcher
    recon.py          DNS, HTTP headers, TLS cert info
    subdomain.py      subfinder wrapper
    vuln.py           nuclei wrapper (template-based detection)
    fuzz.py           ffuf wrapper (content discovery)
    scan.py           nmap wrapper
    burp_scanner.py    Burp Suite Pro/Enterprise REST API (live Scanner)
    burp_traffic.py    Burp proxy-history export review (any edition)
    idor_check.py      cross-session (A/B/anonymous) access-control comparison
    crawler.py          bounded in-scope GET-only crawl
    js_secrets.py       fixed-pattern secrets/endpoint scan of a JS file
    graphql.py          GraphQL introspection check
    cors_check.py       CORS misconfiguration probe
    takeover_check.py   subdomain takeover (CNAME + fingerprint) check
    report.py         writes the findings report to disk
tui/                Go module: the live dashboard (see "Live TUI" above)
tests/
```

### How it loops

1. **Plan** — Claude sees the objective, scope, and findings so far, and
   picks the next tool call(s) — or decides it's done.
2. **Act** — tool calls run, but only after an independent scope check
   (`safety.enforce_scope()`); calls the model batches together in one
   response run **concurrently**, since they're all I/O-bound.
3. **Observe** — each result is capped to `D3M0N_MAX_RESULT_CHARS` (default
   4000) before it goes back into the conversation — the full, untruncated
   result still lands in the final report either way.
4. **Decide** — loop back to Plan, or stop once the objective is met or the
   step budget (`--max-steps`) runs out.

### Tools included

- `dns_lookup` — resolve A/AAAA/MX/TXT/NS records
- `http_probe` — fetch headers, status, server banner, title
- `tls_info` — certificate subject/issuer/expiry
- `subfinder_scan` — passive subdomain enumeration (needs `subfinder`
  installed: `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`)
- `nuclei_scan` — known-CVE/misconfiguration template matching, detection
  only (needs `nuclei`: `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`,
  then `nuclei -update-templates` once)
- `ffuf_scan` — hidden path/content discovery (needs `ffuf`:
  `go install github.com/ffuf/ffuf/v2@latest`; falls back to a small
  built-in wordlist if no wordlist file is found on disk)
- `nmap_scan` — service/version detection, `-sV -Pn`, no exploit scripts
  (needs the local `nmap` binary)
- `burp_scan` / `burp_traffic_review` — see "Burp Suite integration" above
- `idor_check` — see "Broken access control / IDOR" above
- `crawl_site` — bounded, in-scope, GET-only crawl; discovers pages/forms/JS
  files to feed the other tools instead of guessing at paths
- `js_secrets_scan` — fixed-pattern scan of a JS/text file for leaked keys,
  JWTs, private key headers, embedded hidden API paths
- `graphql_introspect` — checks whether a GraphQL endpoint's introspection
  is open, and summarizes the schema if so
- `cors_check` — sends a fixed set of Origin header values and flags
  reflected-arbitrary-origin, null-origin, and naive prefix/suffix
  allowlist patterns in the response's Access-Control-Allow-* headers
- `subdomain_takeover_check` — checks a subdomain's CNAME against known
  takeover-prone providers (GitHub Pages, S3, Heroku, Azure, Shopify, and
  others) and, if matched, checks the response body for that provider's
  "unclaimed resource" fingerprint — a dangling CNAME is a classic,
  often high-severity finding

Any tool whose binary/API isn't installed/configured returns a clear
`"error"` explaining what to install or set up, rather than crashing the run. Everything here is
read-only/detection-only by design — nothing throws exploits, brute-forces
credentials, or performs a destructive action. If you extend it with more
aggressive tooling, keep it inside what your engagement's rules of
engagement actually allow.

### Efficiency

Two things keep this from getting slow/expensive as a run goes long:

- **Prompt caching** — the system prompt, the tool schema list, and a
  rolling breakpoint on the message history are all marked
  `cache_control: ephemeral`, so a long run pays full price for new content
  each turn rather than re-pricing the entire growing conversation every
  step.
- **Parallel tool execution** — the system prompt tells Claude to batch
  independent checks (e.g. DNS + HTTP + TLS on the same host, or probing
  several discovered subdomains at once) into a single response; D3M0N runs
  those concurrently with a thread pool instead of one at a time.

Tune `--max-steps` (default 25) down for a quick pass and up for a
thorough one — cost scales with how many turns you let it take, so this is
still the main lever you control directly.

## Extending it

Add a new tool by writing a function in `tools/`, registering its schema in
`tools/registry.py`, and it's available to the planner automatically.
Everything funnels through `safety.enforce_scope()` first — there's no way
to register a tool that skips it.
