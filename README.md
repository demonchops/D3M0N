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
   the model decided, through `policy.PolicyEngine` (`registry.run_tool()`'s
   actual dispatch gate, not a parallel check), so a hallucinated or
   prompt-injected out-of-scope target just fails instead of running.
   The same `PolicyEngine` is also the tool whitelist — nothing outside
   the fixed, individually-reviewed tool set can even be looked up, let
   alone run.

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

## Running without an API key

D3M0N's "brain" — the planner that decides what to check next — is an LLM,
and that's a real external dependency either way. By default that's Claude
via the Anthropic API (`ANTHROPIC_API_KEY`). If you'd rather run fully
self-contained with no API key at all, point it at a self-hosted model
instead:

```bash
export D3M0N_BACKEND=local
export D3M0N_LOCAL_MODEL_URL=http://localhost:11434/v1   # Ollama's default
export D3M0N_MODEL=llama3.1:70b                           # the local model's name
# no ANTHROPIC_API_KEY needed at all

python -m d3m0n.cli --scope "*.example.com" --objective "..."
```

This works with **anything that speaks the OpenAI chat-completions
protocol** — Ollama, llama.cpp's `llama-server`, vLLM, LM Studio,
text-generation-webui, and others all do. Set `D3M0N_LOCAL_MODEL_URL` to the
server's base URL (ending in `/v1`); `D3M0N_LOCAL_MODEL_API_KEY` is almost
never needed (most local servers don't check it), and `D3M0N_MODEL` becomes
the local model's own name instead of a Claude model id.

**The one real requirement: the model needs genuine tool/function-calling
support.** This agent's entire loop is built on tool use — a model that only
emits plain text will never call a tool, and the run will just burn through
its step budget doing nothing. Most current mid-size-and-up open models
(Llama 3.1+, Qwen2.5+, and others) support this via their server's
OpenAI-compatible endpoint; smaller or older models often don't reliably.

**What doesn't change, on purpose:** scope enforcement, tool-call dispatch,
and the entire safety boundary live in `registry.run_tool()`, independent of
which model is driving the loop. That was always true — enforcement was
never designed to depend on the model cooperating — so pointing this at a
less-aligned local model doesn't weaken it. The prompt caching D3M0N uses for
the Anthropic backend is a no-op for a local one (local servers don't bill
per token the same way, so there's nothing to cache for), which is fine and
expected, not a bug.

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

### Structured engagement files: scope + objectives in one place

`--engagement-file` is a superset of `--scope-file` for a multi-step
engagement: the same scope/authorization fields, plus an ordered
`objectives` list (each one tagged with a `phase` — `recon`, `map`,
`detect`, `access_control`, `defend`, or `verify`) so you write the plan
down once instead of retyping `--objective` every run. JSON or YAML, by
file extension:

```bash
cp engagement.example.json engagement.json   # or .yaml -- then edit it
python -m d3m0n.cli --engagement-file engagement.json
```

It's the exact same authorization rule as `--scope-file` — `"authorized":
true` plus `confirmed_by`, enforced through the one shared function both
loaders call (`safety.validate_authorization_dict`), not a second,
divergently-maintained copy of that rule. The example ships with
`"authorized": false`, same fail-safe default as `scope.example.json`.

The agent's objective comes from the file's `objectives` (skipping any
already marked `"done": true`); pass `--objective` alongside it to add
one more ad-hoc instruction on top rather than replace the list. If you'd
rather just supply scope this way and keep typing a fresh `--objective`
each run, that works too — an engagement file with an empty (or
all-`done`) `objectives` list just requires `--objective` instead, same
as `--scope-file` does.

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
   file; `graphql_introspect` anything that looks like GraphQL;
   `security_headers_check` every live host for HSTS/CSP/clickjacking/
   cookie-attribute weaknesses.
4. **Access control**: `idor_check` (with `enumerate_range` set on numeric
   ids) on every resource-shaped URL found while browsing authenticated
   content.
5. Only then does it call `finish`.

It also raises the step budget (to 60, unless you've explicitly set
`--max-steps` yourself — an explicit value is always respected, never
second-guessed) and adds two extra, separate one-shot Claude calls after
the main run, neither of which can break a run that otherwise succeeded —
each falls back gracefully on its own failure:

- A **skeptical self-review pass**: reads the draft summary against the
  actual raw tool findings and revises anything that reads more confident
  than the evidence supports before the report is written. If it revises
  anything, both versions are saved (`summary` and
  `summary_before_critic_self_review` in the JSON report) so you can see
  what got toned down and why.
- A **DefenseMapper pass**: turns the run's findings into short, concrete
  remediation + detection-rule suggestions — a specific config/code/header
  change to make, and a specific log pattern or alert rule to catch it
  again — saved as `defense_recommendations` in the JSON report. If
  generation fails (a bad response, an unreachable backend), it saves
  `generation_error` instead of silently implying there was nothing to
  flag.

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

### `burp_scan`'s structured output

Each returned issue is a stable object, not just whatever Burp happened to
send: `severity_score` normalizes Burp's severity string to an integer
(4=critical, 3=high, 2=medium, 1=low, 0=information — `None` if Burp
reports something this doesn't recognize, rather than guessing) alongside
the original `severity` string; `context` is a best-effort request
method/path, response status, and a small sanitized response-body snippet
pulled from the issue's own evidence (useful because an issue's evidence
can literally BE the vulnerable request/response, e.g. the exact login POST
for a CSRF-on-login-form finding); `minified_content_warning` flags when
the description, remediation, or that response snippet looks minified
(same heuristic as `js_secrets_scan`) — informational, so dense-looking
content doesn't read as corrupted. A top-level `scan_metadata` block
reports what the call actually used — `scan_config_name`, an explicit
`authenticated`/`auth_method` flag, `paths_requested`, and whatever
`scan_metrics` Burp itself reports for the run.

Every piece of Burp-sourced text (errors, issue descriptions/remediation,
and the evidence-derived context) is redacted for the Burp REST API key,
the configured Burp login username/password, and — defense in depth — any
configured `D3M0N_SESSION_HEADERS` value, before being truncated. The
login-request evidence case above is the likeliest real leak path for the
login password specifically, which is exactly why this redaction has to
reach into `context`, not just the top-level error strings.

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

**Methods other than GET.** `idor_check` takes an optional `method` —
`GET` (default), `HEAD`, `OPTIONS`, `POST`, `PUT`, `PATCH`, `DELETE` —
plus `body`/`content_type` for the ones that carry a body. HEAD and
OPTIONS behave like GET (read-only, no extra setup; OPTIONS also
surfaces the response's `Allow` header, which on its own answers "can B
even PATCH this" without ever sending the PATCH). POST/PUT/PATCH/DELETE
are a different category: replaying one as session B doesn't just show
you B's *view* of A's data, it has B actually *create/modify/delete* it —
a real side effect caused by the test itself. So those four are refused
with a clear error unless you've explicitly opted in first:

```bash
export D3M0N_ALLOW_MUTATING_IDOR_CHECKS=1
```

Off by default, on the same footing as `scope.json`'s `authorized: true`
— a decision only you make, before the run starts, never something the
agent decides for itself mid-run. Enumeration (above) always probes via
GET regardless of `method`, since breadth-first ID discovery and repeated
mutation are not something you want bundled together.

## Architecture

```
src/d3m0n/
  cli.py           entrypoint, argument parsing, authorization (prompt or file)
  safety.py         scope parsing, the authorization gate, scope-file loading
  engagement.py     structured scope+objectives config (JSON/YAML), same
                     authorization rule as safety.py's scope-file loading
  policy.py         PolicyEngine (tool whitelist + scope, run_tool()'s actual
                     gate) + redact_known_secrets() over the agent's summary
  config.py         settings (model name, timeouts, output dir, result-size cap)
  agent/
    graph.py         LangGraph state machine: Planner/ToolRouter/
                     ResultInterpreter per turn + the efficiency layer (below)
    defense_mapper.py  --mode pentest's remediation/detection-rule pass
    backends.py       Claude vs. a local OpenAI-compatible model (see above)
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
    security_headers.py HSTS/CSP/clickjacking/cookie-attribute check
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
  JWTs, private key headers, embedded hidden API paths. Each kept finding
  carries a confidence (high/medium/low, downgraded when the value's
  entropy looks too low to be real random secret data), the entropy score,
  a character position, and a context snippet. Obvious placeholders
  ("your-api-key", repeated characters, sequential runs) are excluded from
  the main findings but reported in `filtered_placeholder_count`/
  `_examples` rather than silently dropped. `minified_heuristic` reports the
  fetched body's own line-length/whitespace shape (informational — it's
  why `context` is always a character window, never "the enclosing line")
- `graphql_introspect` — checks whether a GraphQL endpoint's introspection
  is open, and summarizes the schema if so
- `cors_check` — sends a fixed set of Origin header values and flags
  reflected-arbitrary-origin, null-origin, and naive prefix/suffix
  allowlist patterns in the response's Access-Control-Allow-* headers
- `security_headers_check` — checks HSTS/CSP/X-Content-Type-Options/
  Referrer-Policy/Permissions-Policy and every Set-Cookie header's Secure/
  HttpOnly/SameSite attributes; each finding has a severity and a `why`.
  `clickjacking` is an explicit verdict combining X-Frame-Options and CSP's
  `frame-ancestors` (either one alone prevents framing)
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
Everything funnels through `policy.PolicyEngine` first — there's no way to
register a tool that skips it.

### Policy Engine (`policy.py`)

`PolicyEngine` is the one object `run_tool()` actually asks before
dispatching — tool-whitelist and scope checks both go through it, so
"did this action pass policy" has a single, inspectable answer rather
than being implicit across a few call sites. It mostly wraps mechanisms
that already existed and were already mandatory (`safety.enforce_scope`,
the fixed `_DISPATCH` table); the one forward-looking addition is an
optional `allowed_tools` restriction below the global whitelist, which
nothing currently populates — it's a ready extension point, not a gap
being papered over.

It also exposes `redact_known_secrets()`: one consolidated redaction
pass covering every secret-bearing setting this project knows about
(both session-header accounts, the Burp REST API key and login
credentials, the local-model and Anthropic API keys). Every individual
tool already redacts its own result text, but none of that reaches the
agent's own free-text summary — `run_agent()` runs the final summary
through this before anyone sees it, which is the one place the per-tool
helpers don't reach.

What it deliberately doesn't do: scan the model's own prose for "unsafe
suggestions" by keyword or pattern. The system prompt instructs the
model to write manual verification recipes that can legitimately read
like "try X as the parameter value" — a filter broad enough to catch
something resembling an exploit would just as reliably mangle that
correct, intended output. Passive-only stays what it already was: an
architectural fact (no tool in the registry can exploit or tamper with
a target), checked here by the whitelist, not a runtime text heuristic.
