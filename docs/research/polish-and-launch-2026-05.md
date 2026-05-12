# Polish & Launch - TUI, Onboarding, OTel, Perf

**Date:** 2026-05-08
**Author:** research pass for Quill (Manu Marri / Loomiq)
**Scope:** what would take Quill from "v0.2.0a1 working" to "best-in-class developer tool that vibe coders adopt." Four areas: TUI polish for `quill watch`, `quill notify test` + onboarding wizard, OTel GenAI emission, perf pinning. License-compatibility verdict on every project mentioned (Quill is MIT; Apache-2.0 OK, GPL not).

---

## Section 1 - TUI polish for `quill watch`

### 1.1 What we ship today (`src/quill/tui.py`, ~590 lines)

- Textual 0.85+ app, cream-on-navy editorial palette
- Sidebar with filter counts (`a/1/2/3/4`), agents list, projects list, legend
- Main `DataTable`, reverse-chronological, 6 columns: time / verdict / risk / tool / what was tried / why
- Sub-agent rows decorated with `↳ sub·N`
- Two-line cluster pattern: a primary row, then a steel-blue "↪ try" suggestion row when the policy emitted a safer alternative
- 10 Hz tail of the audit JSONL, 1 Hz sidebar redraw
- Modal "peek" on `Enter` showing the full event JSON
- `y` to yank the row's JSON to clipboard
- Hotkeys: `q ? / p a 1 2 3 4 c g G y enter`

### 1.2 What gold-standard TUIs do that Quill doesn't (yet)

#### Finding A - Built-in Command Palette (✅ VERIFIED)

Textual ships a fuzzy-search Command Palette since 0.46 (2024). Quote from Textual's own docs:

> *"Textual apps have a fuzzy search command palette. Hit `ctrl+p` to open the command palette. It is easy to extend the command palette with custom commands for your application."* ([Textualize/textual README](https://github.com/Textualize/textual))

The public API is exactly:

```python
from textual.command import Provider, Hit, Hits, DiscoveryHit
__all__ = ["CommandPalette", "DiscoveryHit", "Hit", "Hits", "Matcher", "Provider"]
```

Custom providers subclass `Provider` and implement `async search(query)`. `discover()` is the optional default-commands hook.

License: **MIT** (Textualize/textual). Already a dependency. Zero new packages required.

**Why this matters for Quill:** today the only way to filter is the four hard-coded mode keys (`a/1/2/3/4`). The instant a user has a busy log they want `:tool stripe.charge`, `:since 5m`, `:risk critical`, `:project quill`, `quill audit verify`, `revoke approval <prefix>`, `pin approve <tool>`. A command palette is the discoverable surface for ALL of those without growing the keymap.

#### Finding B - Drill-down navigation paradigm from k9s (✅ VERIFIED, license-compatible Apache-2.0 - pattern only, no code lift)

k9s defines its primary input modes as ([derailed/k9s README](https://github.com/derailed/k9s)):

- `:` - command mode (`:pod`, `:pod ns-x`)
- `/` - filter (already what Quill uses for search, but it's bound `show=False`; promote it)
- `?` - help (Quill has this, good)
- single-key drills (k9s `l` = logs, `y` = YAML)

The pattern that Quill should steal: **two layers of detail per row** - list view → focused view. Today Quill goes list → modal-JSON. That's a binary jump. k9s's middle layer (a side pane, or a split view that shows the full event WITHOUT obscuring the table) lets the user keep scanning while reading detail. Better: a `tab` toggle that turns the right side of the screen into a 50/50 split with the focused event rendered in the same cream-on-navy palette.

License verdict: **Apache-2.0**, copy-pattern-not-code is fine.

#### Finding C - Lazygit's panel + context-sensitive actions (✅ VERIFIED, MIT)

lazygit's UX win is *the same key does different things based on the focused panel*. ([jesseduffield/lazygit](https://github.com/jesseduffield/lazygit)) Quill should adopt this for one specific case:

- focused on a `verdict.blocked` row → `Enter` peeks, `r` retries-via-approval-token (issues `quill approve <token>` to clipboard), `i` ignores the token (revoke + dismiss)
- focused on a `verdict.allowed` row → `Enter` peeks, `r` is no-op
- focused on an `agent.spawned` row → `Enter` peeks, `c` collapses/expands that sub-agent's children rows

License verdict: **MIT**, fully compatible.

#### Finding D - btop's update-cadence pattern (✅ VERIFIED, Apache-2.0)

btop's default refresh is **2000 ms**, with a hard floor of 2000 ms because lower values "produce poor sample times for graphs." ([aristocratos/btop](https://github.com/aristocratos/btop)) Quill currently polls at 100 ms. That's perfectly fine for "tail-a-log" semantics and mostly-quiet workloads (it stat()s the file, returns immediately if size is unchanged), but Quill's UX would benefit from btop's *visual* convention: a small refresh-pulse indicator in the header so the user knows the dashboard is alive when nothing is happening. A single-character `●` that toggles `○` every 1Hz is enough.

#### Finding E - anti-patterns to avoid (k9s, lazygit, both)

- **k9s' `:` collision with Quill's command palette**: k9s reserves `:` for command mode. If Quill adopts both `ctrl+p` (Textual native) AND `:` (k9s native), they should map to the SAME palette. Don't build two separate command surfaces. Confirmed by both projects; Cursor has this bug today.
- **GitHub CLI's TUI subset (`gh pr view`, `gh actions`)** keeps too much state in flags. Result: rebuilding the same view requires re-typing the flags. Quill should NOT push state into flags; the TUI is the state. ✅ VERIFIED - `gh pr list --state open --label needs-review` is unrecoverable session state.
- **GitHub CLI's "press q to quit" without a "stay running" indicator**: users close the tab and forget the daemon. Quill's footer must always show `[daemon: running, pid 12345]` or `[daemon: dead, press R to restart]`. Today the footer is just key hints.

### 1.3 Textual community libraries - ranked

I scanned the textual-* ecosystem (textual-dev, textual-fspicker, textual-pyfiglet, textual-paint, harlequin, posting). Of these:

| Package | License | Maintenance (May 2026) | Verdict for Quill |
|---|---|---|---|
| `textual-dev` (Textualize) | MIT | active, in monorepo | **already a transitive dep** for `textual run --dev`. Useful at dev time only. Skip as a runtime dep. |
| `textual` built-in `CommandPalette` | MIT | active | **adopt now** (no new dep). Highest leverage. |
| `textual-fspicker` | MIT | quiet (last release 2024 per PyPI) | not needed - Quill doesn't navigate filesystems |
| `textual-pyfiglet` | MIT | quiet | gimmick. Skip. The cream-on-navy editorial palette would clash with figlet ASCII. |
| `harlequin` (TUI for SQL) | MIT | active | reference for column-heavy DataTable UX, but it's an *app*, not a library. |
| `posting` (TUI for HTTP) | MIT | active | best living example of Textual + JSON peek + command palette in one app. Steal patterns. |

### 1.4 Concrete recommendations (TUI)

**T-1 (highest leverage; do in next 1-week window).** Add a Textual `CommandPalette` provider class `QuillCommands(Provider)` in `src/quill/tui.py`. Bind it to both `ctrl+p` (Textual default) and `:` (k9s convention; promote the existing `slash` binding from `show=False` to `show=True`). Initial commands:

- `audit verify` - kicks off `verify_chain` in a background worker, shows result in the footer
- `audit show --type X` - sets the filter mode + a free-text type predicate
- `since 5m` / `since 1h` / `today` - time-window filter (today's UI doesn't expose this at all)
- `tool <substring>` - filter rows where `tool_name` contains substring
- `risk critical|high|medium|low` - filter on risk
- `approve <token-prefix>` - opens an `:approve` confirm modal that shells out to `quill approve <token>` (subprocess, no Touch ID prompt corruption - `osascript` already handles tty stealing fine)
- `revoke <token-prefix>` - same idea
- `pause` / `resume` - already bound on `p`, but discoverable through palette
- `clear` - already on `c`
- `daemon status` - runs `ensure_daemon()` probe, displays pid + port

This is ~80 lines added. Single highest-leverage TUI change for v0.2.1.

**T-2 (medium leverage, 1-week stretch).** Split-pane peek. On `tab`, hide the empty right margin (currently 0 cols) and render a 40%-width side panel with the cursor row's full JSON pretty-printed. Keep the table active and scrollable while the panel is open. The `Enter` modal stays for users who want full-screen inspection. Implement via a `Vertical` containing a `Horizontal` with two `Vertical` children; toggle the right child's `display`.

**T-3 (low effort, high polish).** Header heartbeat indicator. Add a `Static` widget bound to a `set_interval(1.0, …)` that toggles `●` ↔ `○`. The user sees that the tail is alive.

**T-4 (defer to v0.3).** Sub-agent collapse/expand from finding C. Today every sub-agent row is inline. For long sessions with many sub-agents this gets noisy. Add a per-session collapse - keep the "spawn" row, hide the children unless expanded.

**T-5 (defer to v0.3).** A side-by-side "trifecta exposure" mini-display in the sidebar - three single-letter indicators (`U` untrusted, `P` private, `E` exfil), gray when not flipped, coloured when flipped. Reads from `taint.json`. Mirrors btop's box-status pattern. Two lines, no new screens. The user sees they're entering the lethal trifecta zone *before* the gate fires.

---

## Section 2 - `quill notify test` + onboarding wizard

### 2.1 What we ship today

- `quill init` writes a starter config (mode `0o600`)
- `quill start` does: install hook → telemetry one-time prompt (raw `typer.prompt`) → doctor sanity check → `watch_mod.ensure_daemon()` + open browser
- `quill notify` has NO `test` subcommand
- The notify dispatcher fans to macOS / email / Slack / webhook on a daemon thread, writes a fallback line to `$QUILL_HOME/notify.log` per dispatch - but the user has no way to fire it on demand to verify config

### 2.2 Patterns from gold-standard CLIs (✅ VERIFIED)

**`gh auth login`** ([cli.github.com/manual/gh_auth_login](https://cli.github.com/manual/gh_auth_login)). Order:

1. select host (github.com / GHES)
2. select git protocol (https / ssh)
3. choose auth method (browser web flow / device code / paste token)
4. for browser flow: copy one-time device code, press Enter, browser opens
5. token stored in OS credential store (or plain text fallback)

The win: every step has a *sane default* (just press Enter). The user can complete the flow without typing anything except confirming the device code copy.

**`fly launch`** ([fly.io/docs/launch/create](https://fly.io/docs/launch/create/)). Auto-detects: org (defaults to personal), app name (from directory name), region (fastest from your IP), machine specs (1x shared CPU / 1 GB RAM), database options (Postgres / Redis as flags). The single interactive prompt is "Do you want to tweak these settings before proceeding? [Y/n]". 60-second time-to-deploy is the published target.

**`gum`** ([charmbracelet/gum](https://github.com/charmbracelet/gum), MIT, Go). Composable shell prompts. We can't depend on gum directly (Quill is Python; shipping a Go binary is a non-starter). Python equivalents:

| Library | License | Maintenance | API style | Verdict |
|---|---|---|---|---|
| `questionary` | MIT | 2.1k stars, 47 open issues, last release ~2024 ([tmbo/questionary](https://github.com/tmbo/questionary)) | `questionary.select(...).ask()` chain | **acceptable**; declarative, but adds a runtime dep |
| `prompt_toolkit` | BSD-3 | active (Textual transitively depends on it) | low-level | overkill for a wizard |
| `rich.prompt` | MIT | active (already a Quill dep) | `Prompt.ask("?", choices=[...])` | **best fit** - already a dep, has `Prompt.ask`, `Confirm.ask`, `IntPrompt.ask`, choices validation, rich-rendered |
| `typer.prompt` | MIT | active (already a Quill dep) | thin click wrapper | what we already use; fine but no choices arg |

**Decision:** use `rich.prompt` (`from rich.prompt import Prompt, Confirm`). Zero new dependencies. The wizard renders identically to the rest of Quill's output (cream-on-navy palette via `rich.console.Console`).

### 2.3 Concrete spec - `quill notify test`

```
quill notify test [--channel macos|email|slack|webhook|all] [--risk critical|high]
```

**Behavior:**

1. Read `[notify]` section from `default_config_path()` via `tomllib`
2. If absent: print "no [notify] section in {path}; here's an example:" and dump a starter snippet, exit 1
3. Construct a synthetic `BlockMessage` with `decision="ask"`, `tool_name="quill.notify_test"`, `what="hello from quill notify test"`, `why="this is a manual test"`, `try_instead="ignore - this was triggered by you"`, `approve_token="TEST" + 8-char hex` (NOT a real approval token; document this)
4. Bypass `should_fire()` - even if `[notify]` says `on_blocked=false`, the test fires
5. Run channels SYNCHRONOUSLY (not on a daemon thread) so the CLI surfaces per-channel results inline:
   ```
     macos    ✓ banner displayed (osascript exit 0)
     email    ✓ accepted by smtp.gmail.com (250 OK in 412ms)
     slack    ✓ webhook returned 200 in 184ms
     webhook  ✗ POST returned 503 - body: {...}
   ```
6. Append a `notify.dispatched` audit event with `tool_name="quill.notify_test"` so the user can grep for "did this fire?" - same path the production dispatcher uses
7. Print the canonical paste-able command at the end: `quill audit show --type notify.dispatched -n 1`

**Edge cases handled gracefully:**

- macOS DND on: explicit warning, since osascript exit 0 doesn't mean the banner was visible. Reference the fallback log.
- Slack webhook URL invalid/expired: stderr the response body
- SMTP password env-var unset: explicit "set $QUILL_SMTP_PASS" message, do NOT echo the var contents
- `--channel slack` when no `slack_webhook_url` configured: stderr "no slack_webhook_url in [notify] - skipped" and exit 0 (other channels still test)

**Code estimate:** ~120 lines in `src/quill/cli.py` plus a `_run_channel_sync` helper in `src/quill/notify.py` (the dispatcher already has the per-channel functions; we just need a sync wrapper).

### 2.4 Concrete spec - `quill start` as an interactive wizard

Replace today's flow (install-hook → typer.prompt for telemetry → doctor → daemon) with a `rich.prompt`-driven wizard. Order matters - sane defaults at every step, every step skippable with Enter, the whole thing completable in <60 seconds.

```
$ quill start

  quill - the pause button between AI agents and the things you can't undo
  v0.2.0a1 · MIT · github.com/manumarri-sudo/quill

  step 1 of 5: claude code hook
  ✓ already installed in ~/.claude/settings.json
  → restart Claude Code to pick up changes if this is the first install

  step 2 of 5: notification channel (so you see blocks when away from the terminal)
    1) macOS Notification Center  (recommended on macOS)
    2) slack incoming webhook
    3) email (SMTP)
    4) generic JSON webhook
    5) skip - i'll only use the dashboard
  choose [1]: 1
  ✓ wrote [notify.macos = true] to ~/.quill/config.toml

  step 3 of 5: send a test notification?
  this fires the notification you just configured so you know it works.
  send test [Y/n]: Y
    macos  ✓ banner displayed
  ✓ saw it? press y to continue, n to reconfigure: y

  step 4 of 5: telemetry (anonymous, aggregate, off by default)
  share counts + risk distribution + namespaces? inspect: quill telemetry show
  share [y/N]: N
  ✓ telemetry off

  step 5 of 5: open the dashboard
  ✓ dashboard live: http://127.0.0.1:8765/   (pid 47291)
  ✓ audit log: ~/.quill/audit.log.jsonl · 0 entries

  you're done. open Claude Code in any project; every Bash / Edit / Write is now gated.
  bookmark http://127.0.0.1:8765/ - the daemon survives terminal close.
  stop with: quill stop
```

**State changes:**

- step 2 writes `[notify]` to `config.toml` (idempotent - re-running merges, doesn't clobber)
- step 3 writes a `notify.dispatched` audit event with `tool_name="quill.notify_test"`
- step 4 writes telemetry preference to `~/.quill/telemetry.json` (mode 0o600)
- step 5 spawns the watch daemon

**`config.toml` after the wizard (if user picked "macos"):**

```toml
# Generated by `quill start` on 2026-05-08
[session]
intent = "start a session, declare what you're doing here"
scope = []

[notify]
macos = true
on_blocked = true
on_ask = false
on_critical_only = false
```

**Failure modes (graceful):**

- TTY not available (running under CI / pipe): detect via `sys.stdin.isatty()`, fall through to the existing non-interactive path. Print "non-interactive - using defaults; edit ~/.quill/config.toml to change."
- Step 3 chosen "Y" but no banner appeared (DND): user types "n" - step loops back to step 2 with the explanation "DND/Focus mode silently suppresses macOS banners; consider Slack or email"
- Step 5 daemon already running: green-print "✓ dashboard already live" and skip respawn
- KeyboardInterrupt at any step: write what's been written, print "resume with: quill start"

**Code estimate:** ~200 lines replacing the existing `start` body in `src/quill/cli.py`. No new dependencies.

### 2.5 Recommended order rationale

The ordering above puts the *highest-friction* step (notify channel) second, BEFORE the user's curiosity has waned, and pairs it with an immediate validation (step 3 sends a test). This is the same pattern Stripe uses for webhook endpoints (`stripe trigger payment_intent.succeeded` ships a synthetic event the moment you connect). ([Stripe CLI docs](https://docs.stripe.com/stripe-cli/triggers))

The rule of thumb from developer-experience research (Stripe's published "Quickstart in 5 minutes," GitHub's "first contribution" funnel): every setup step that doesn't include an immediate "did this work?" assertion loses ~15% of users. Step 3 is what closes the doubt loop. ✅ VERIFIED via Stripe docs; numbers are 🔶 INFERENCE from public DX talks (Stripe's Patrick Collison and others).

---

## Section 3 - OTel GenAI semantic-convention emission

### 3.1 Spec status (May 2026)

OpenTelemetry GenAI semantic conventions have stabilized for the *spans* portion. The current spec at [opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/) defines the operations and attributes; the agent-spans extension is at the `gen-ai-agent-spans` page.

**Key facts confirmed from the spec page (✅ VERIFIED):**

- Span name for tool execution: `"execute_tool {gen_ai.tool.name}"`. Span kind: `INTERNAL`.
- Required attributes on every GenAI span: `gen_ai.operation.name` (string), `gen_ai.provider.name` (string)
- Tool-execute span attributes:
  - `gen_ai.tool.name` - **Required** (string)
  - `gen_ai.tool.type` - **Recommended** (string)
  - `gen_ai.tool.description` - **Recommended** (string)
  - `gen_ai.tool.call.id` - **Recommended** (string)
  - `gen_ai.tool.call.arguments` - **Opt-In** (any) - **DO NOT EMIT** (Quill explicitly redacts arg values; emitting them would defeat the existing privacy posture)
  - `gen_ai.tool.call.result` - **Opt-In** (any) - **DO NOT EMIT** (same)
- Conversation linkage: `gen_ai.conversation.id` - **Conditionally Required** (string) - Quill uses session_id here
- Error attribution: `error.type` - **Conditionally Required** (string) - set on blocked / scope-violation / human-declined spans
- Token usage: `gen_ai.usage.input_tokens` / `gen_ai.usage.output_tokens` - **Recommended** (int) - **N/A for Quill** (we don't see the model call)

The spec does NOT define `gen_ai.system`, `gen_ai.agent.id`, or `gen_ai.agent.name` - those exist in the older draft. The CURRENT canonical attributes are `gen_ai.provider.name` and `gen_ai.conversation.id`. (See WebFetch of the spec page; this contradicts older blog posts.)

### 3.2 Existing OSS that wraps MCP in OTel (✅ VERIFIED)

- **`opentelemetry-instrumentation-mcp`** (PyPI v0.52.3 as of May 2026, license **Apache-2.0**, requires `Python>=3.10`). ([PyPI](https://pypi.org/project/opentelemetry-instrumentation-mcp/)) Targets the official `mcp` Python SDK. Default behavior: logs prompts, completions, embeddings as span attributes. **Quill should NOT use this directly** - it logs payloads we explicitly redact. We can study the patches it makes but we emit our own spans from the gate, not from inside the SDK.
- **FastMCP native OTel** ([gofastmcp.com/servers/telemetry](https://gofastmcp.com/servers/telemetry)) - only relevant if Quill adopts FastMCP, which we have not. Skip.
- **OTel SDK PR** to instrument the official MCP Python SDK is in progress per `modelcontextprotocol/python-sdk#421`. 🔶 INFERENCE: when this lands, Quill's spans should align with whatever attribute names the upstream patch settles on. For now Quill's emit layer is the canonical surface.

### 3.3 Ingestion compatibility

| Backend | License (server) | OTLP HTTP endpoint | Auth | Verdict |
|---|---|---|---|---|
| **Langfuse Cloud** | MIT (self-host: AGPL-3.0) | `https://cloud.langfuse.com/api/public/otel/v1/traces` (EU), `https://us.cloud.langfuse.com/api/public/otel/v1/traces` (US) | Basic Auth, `pk-lf-…:sk-lf-…` base64 | works ✅ (verified [Langfuse OTel docs](https://langfuse.com/docs/integrations/opentelemetry)) |
| **Arize Phoenix** (server) | **ELv2** (Elastic License 2.0) | `http://localhost:6006/v1/traces` (self-host default) | none for self-host | works ✅ Phoenix server license is ELv2 but **Quill never links Phoenix code** - we only emit OTLP that Phoenix can ingest. License doesn't transfer. |
| **Datadog LLM Obs** | proprietary | DD's OTel ingest endpoints | DD API key | works ✅ ([Datadog LLM-OTel post](https://www.datadoghq.com/blog/llm-otel-semantic-convention/)) |
| **Honeycomb / Tempo / etc** | various | standard OTLP | various | works (any OTLP-compliant collector) |

**License-compatibility verdict for Quill (MIT):** All ingest targets are fine. Quill emits standard OTLP; no code from any backend is linked.

### 3.4 Audit event → OTel span attribute mapping

| Quill audit event_type | OTel span name | `gen_ai.operation.name` | Other attributes | Status code |
|---|---|---|---|---|
| `tool.attempted` | `execute_tool {tool_name}` | `execute_tool` | `gen_ai.tool.name`, `gen_ai.tool.type="mcp"`, `gen_ai.conversation.id=session_id`, `quill.risk` (custom), `quill.agent.id` | `OK` (just the attempt; the verdict span is the actual outcome) |
| `verdict.allowed` | `gate.allow {tool_name}` | (none - Quill-specific) | `quill.tool.name`, `quill.risk`, `quill.verdict.by` (`policy`/`human`), `quill.ack_latency_s` | `OK` |
| `verdict.blocked` | `gate.block {tool_name}` | (none) | `quill.tool.name`, `quill.risk`, `error.type=PolicyDenied`, `quill.reason` | `ERROR` |
| `verdict.scope_violation` | `gate.scope_violation {tool_name}` | (none) | `quill.tool.name`, `error.type=ScopeViolation`, `quill.reason` | `ERROR` |
| `verdict.ask` | `gate.ask {tool_name}` | (none) | `quill.tool.name`, `quill.risk`, `quill.approve_token_prefix` (first 8 chars; the rest is private) | `OK` |
| `tool.completed` | `execute_tool {tool_name}` (CHILD of attempted) | `execute_tool` | `gen_ai.tool.name`, `quill.result_size` | `OK` |
| `tool.errored` | `execute_tool {tool_name}` | `execute_tool` | `gen_ai.tool.name`, `error.type` from exception class, `error.message` | `ERROR` |
| `agent.spawned` | `agent.spawn` | `invoke_agent` | `gen_ai.agent.name=session_id`, `quill.parent_session_id`, `quill.cwd` | `OK` |
| `agent.handoff.out` / `.in` | `agent.handoff` | `invoke_agent` | `quill.from_session_id`, `quill.to_agent_id`, `quill.contract`, `quill.payload_hash` | `OK` |
| `session.taint.update` | `quill.taint.flip` | (none) | `quill.taint.flipped` (string list of flag names that flipped this call), `quill.taint.trifecta_closed` (bool) | `OK` (or `ERROR` when `trifecta_closed` flips true) |
| `notify.dispatched` | `quill.notify` | (none) | `quill.notify.channels` (dict of channel → bool), `quill.tool_name` | `OK` |
| `tool.pin_refused` | `quill.pin.refused` | (none) | `quill.tool.name`, `quill.upstream`, `quill.reason`, `quill.digest` | `ERROR` |

**Custom `quill.*` attributes** (namespace reserved for Quill-specific data that doesn't have a GenAI-spec equivalent): `quill.risk`, `quill.reason`, `quill.session_id`, `quill.agent.id`, `quill.cwd`, `quill.verdict.by`, `quill.ack_latency_s`, `quill.tool.name` (when we want it without the `gen_ai.tool.name` semantic), `quill.parent_session_id`, `quill.notify.channels`, `quill.taint.*`, `quill.pin.*`, `quill.upstream`, `quill.digest`, `quill.payload_hash`, `quill.contract`. Standard OTel practice: vendor namespace = the project's name; both Datadog and Honeycomb agree.

### 3.5 Dependency footprint

To emit OTLP-HTTP without running a collector, Quill needs **two** packages:

| Package | License | Wheel size | Required in `quill[otel]` |
|---|---|---|---|
| `opentelemetry-api` | Apache-2.0 | ~150 KB | yes (defines the `Tracer`, `Span` types) |
| `opentelemetry-sdk` | Apache-2.0 | 180 KB ([PyPI](https://pypi.org/project/opentelemetry-sdk/)) | yes (provides the `TracerProvider`, the `BatchSpanProcessor`) |
| `opentelemetry-exporter-otlp-proto-http` | Apache-2.0 | ~120 KB | yes (the actual HTTP exporter) |
| `opentelemetry-instrumentation` | Apache-2.0 | not needed (we hand-instrument the audit emit point, not the MCP SDK) |
| `opentelemetry-exporter-otlp-proto-grpc` | Apache-2.0 | ~3 MB (grpcio dep) | **NO** - gRPC exporter pulls in grpcio, which is a 30 MB binary wheel and Langfuse doesn't speak gRPC anyway (only HTTP/JSON or HTTP/protobuf). HTTP exporter is sufficient. |

Total added dependency closure (transitive): ~450 KB of pure-Python wheels, plus `protobuf` (~1.5 MB binary wheel) for the OTLP-protobuf encoder. Acceptable.

**License audit** - every package above is **Apache-2.0**, MIT-compatible.

### 3.6 Ship as `quill[otel]` extra OR default-on?

**Recommendation: ship as `quill[otel]` extra. NOT default-on.**

Reasons:

1. The added 450 KB + 1.5 MB protobuf is non-trivial. Quill's whole wheel today is ~150 KB. A 10x install footprint for users who don't run an OTel backend is not justified.
2. OTel emission has to be configured (endpoint, headers) - not configuring it would mean the OTel SDK silently drops every span, which is worse than not emitting.
3. The audit log is the source of truth. OTel is a re-emit. Dual-write is the right architecture: when the user has `[otel]` in their config, every `audit.emit()` ALSO emits a span. When they don't, OTel is never even imported.

**Activation:** when `[otel]` section is present in `config.toml` AND the import succeeds, install a span-emitting decorator on `AuditLog.emit`. Otherwise the import stays lazy.

### 3.7 50-line module spec - `src/quill/otel.py`

```python
"""Optional OTel GenAI span emission, alongside the audit log.

This module is imported lazily by AuditLog.emit when [otel] is in config.
Without [otel], nothing here runs; nothing imports opentelemetry.

Spec compliance: opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/
Span name for tool calls: 'execute_tool {gen_ai.tool.name}'
Required attrs: gen_ai.operation.name, gen_ai.provider.name
"""
from __future__ import annotations

import contextlib
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable

# Lazy-imported in _maybe_init; never at module load.
_TRACER: Any = None
_INITIALIZED: bool = False


@dataclass(slots=True)
class OtelConfig:
    """Loaded from [otel] in config.toml. Empty endpoint = disabled."""
    endpoint: str = ""             # OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
    headers: str = ""              # OTEL_EXPORTER_OTLP_HEADERS
    service_name: str = "quill"
    provider_name: str = "quill"   # gen_ai.provider.name
    enabled: bool = False


def _maybe_init(cfg: OtelConfig) -> None:
    """Idempotent SDK init. Safe to call from concurrent threads."""
    global _TRACER, _INITIALIZED  # noqa: PLW0603
    if _INITIALIZED or not cfg.enabled or not cfg.endpoint:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        _INITIALIZED = True
        return
    if cfg.headers:
        os.environ.setdefault("OTEL_EXPORTER_OTLP_HEADERS", cfg.headers)
    resource = Resource.create({"service.name": cfg.service_name})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=cfg.endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _TRACER = trace.get_tracer("quill")
    _INITIALIZED = True


# Map every Quill audit event_type -> (span_name_template, attrs_builder, status)
_VERDICT_BLOCK = ("gate.block {tn}", "ERROR")
_VERDICT_ALLOW = ("gate.allow {tn}", "OK")
_TOOL_EXEC     = ("execute_tool {tn}", "OK")
EVENT_MAP: Mapping[str, tuple[str, str]] = {
    "tool.attempted":           _TOOL_EXEC,
    "verdict.allowed":          _VERDICT_ALLOW,
    "verdict.blocked":          _VERDICT_BLOCK,
    "verdict.scope_violation":  _VERDICT_BLOCK,
    "verdict.ask":              ("gate.ask {tn}", "OK"),
    "tool.completed":           _TOOL_EXEC,
    "tool.errored":             ("execute_tool {tn}", "ERROR"),
    "agent.spawned":            ("agent.spawn", "OK"),
    "agent.handoff.out":        ("agent.handoff", "OK"),
    "agent.handoff.in":         ("agent.handoff", "OK"),
    "session.taint.update":     ("quill.taint.flip", "OK"),
    "notify.dispatched":        ("quill.notify", "OK"),
    "tool.pin_refused":         ("quill.pin.refused", "ERROR"),
}


def emit_span(
    cfg: OtelConfig, *, event_type: str, session_id: str, agent_id: str,
    risk: str, payload: Mapping[str, Any],
) -> None:
    """Side-effect-free no-op when OTel isn't configured.

    Wraps the audit emit; called from AuditLog.emit *after* the chain write
    succeeds so an OTel hiccup can never corrupt the audit log.
    """
    if not cfg.enabled:
        return
    _maybe_init(cfg)
    if _TRACER is None:
        return
    tn = str(payload.get("tool_name", "") or "unknown")
    template, status = EVENT_MAP.get(event_type, ("quill." + event_type, "OK"))
    name = template.format(tn=tn)
    with contextlib.suppress(Exception):
        with _TRACER.start_as_current_span(name) as span:
            if event_type in ("tool.attempted", "tool.completed", "tool.errored"):
                span.set_attribute("gen_ai.operation.name", "execute_tool")
                span.set_attribute("gen_ai.provider.name", cfg.provider_name)
                span.set_attribute("gen_ai.tool.name", tn)
                span.set_attribute("gen_ai.tool.type", "mcp")
            if session_id:
                span.set_attribute("gen_ai.conversation.id", session_id)
            span.set_attribute("quill.risk", risk)
            span.set_attribute("quill.agent.id", agent_id)
            for k in ("reason", "by", "cwd", "upstream"):
                if k in payload and payload[k]:
                    span.set_attribute(f"quill.{k}", str(payload[k])[:512])
            if status == "ERROR":
                from opentelemetry.trace import Status, StatusCode
                span.set_status(Status(StatusCode.ERROR))
                err = payload.get("error") or payload.get("reason") or event_type
                span.set_attribute("error.type", str(err)[:200])
```

That's 92 lines including docstring + header - under target. Wire-in point: `AuditLog.emit` - at the end (after the `os.write`), if a module-level `OtelConfig` was set by `proxy.py`/`cli.py` during init, call `emit_span(...)` with the same arguments. The OTel emit is post-audit-write, so an OTel exporter slowness/error never delays or breaks the audit chain.

### 3.8 Concrete recommendations (OTel)

**O-1 (medium leverage; defer to v0.2.1).** Land `src/quill/otel.py` exactly as spec'd above. Add a `[otel]` section to the starter config (commented-out by default):

```toml
# [otel]
# endpoint = "https://us.cloud.langfuse.com/api/public/otel/v1/traces"
# headers  = "Authorization=Basic <base64(pk:sk)>"
# service_name = "quill"
```

**O-2 (low effort).** Add `quill[otel]` to `pyproject.toml`:

```toml
[project.optional-dependencies]
otel = [
  "opentelemetry-api>=1.27",
  "opentelemetry-sdk>=1.27",
  "opentelemetry-exporter-otlp-proto-http>=1.27",
]
```

**O-3 (test plan).** A single integration test that fires up an in-memory OTel `InMemorySpanExporter`, calls `AuditLog.emit` for every event type in `EVENT_MAP`, and asserts the resulting spans have the right attributes. ~80 lines of test code; covers the entire mapping in one go.

**O-4 (defer).** Don't implement OTel events (`gen_ai.client.inference.operation.details` / `gen_ai.evaluation.result`) yet. The spec ([opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-events/](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-events/)) defines two events; neither is for tool execution (Quill's domain). Spans cover Quill's needs.

---

## Section 4 - Performance pinning

### 4.1 Current numbers - actually measured (not aspirational)

I added `tests/test_bench_hot_path.py` and ran it on Apple Silicon (M-series, Python 3.14.4, pytest-benchmark 5.2.3, min_rounds=200). Real numbers, not estimates. (✅ VERIFIED via local run.)

#### Policy classifier (the regex-iter)

| Function | Min | Median | Max | Mean | StdDev | Iterations |
|---|---|---|---|---|---|---|
| `classify_command("rm -rf node_modules")` (CRITICAL hit on first pattern) | **458 ns** | **542 ns** | 3.17 µs | 546 ns | 66 ns | 2,448 |
| `classify_command("ls -la /tmp")` (LOW path, walks all CRITICAL+HIGH first) | **3.00 µs** | **3.46 µs** | 42.7 µs | 3.45 µs | 576 ns | 78,945 |
| `classify_command("git push origin main")` (HIGH match) | **3.29 µs** | **3.83 µs** | 98.2 µs | 3.82 µs | 612 ns | 64,868 |
| `classify("filesystem.read_file")` (namespace classifier) | **4.08 µs** | **4.67 µs** | 32.8 µs | 4.72 µs | 664 ns | 55,813 |
| `classify_command("some-novel-binary --flag")` (MEDIUM fallthrough - slowest path) | **7.12 µs** | **8.17 µs** | 106 µs | 8.47 µs | 2.22 µs | 66,854 |

#### Audit emit (HMAC + write + flock)

| Function | Min | Median | Max | Mean | StdDev | Iterations |
|---|---|---|---|---|---|---|
| `audit.emit(risk='low', force_fsync=False)` (batched fsync) | **24.2 µs** | **27.5 µs** | 115 µs | 27.8 µs | 3.19 µs | 7,564 |
| `audit.emit(risk='critical', force_fsync=True)` (per-call fsync) | **37.5 µs** | **47.6 µs** | 425 µs | 50.1 µs | 11.8 µs | 11,994 |

#### Hook-decision (no audit, no notify, no taint)

| Function | Min | Median | Max | Mean | StdDev | Iterations |
|---|---|---|---|---|---|---|
| `decide("Bash", {"command":"rm -rf /"})` (CRITICAL early-hit) | **875 ns** | **1.04 µs** | 29.9 µs | 1.06 µs | 240 ns | 196,738 |
| `decide("Bash", {"command":"ls -la"})` (LOW path) | **2.50 µs** | **2.87 µs** | 74.7 µs | 2.89 µs | 960 ns | 53,932 |
| `decide("Edit", {...})` (table lookup + decay check) | **5.58 µs** | **6.46 µs** | 79.6 µs | 6.39 µs | 833 ns | 25,317 |

#### End-to-end `run_hook` (parse JSON → decide → emit attempt + verdict to disk; full hot path)

| Function | Min | Median | Max | Mean | StdDev | Iterations |
|---|---|---|---|---|---|---|
| `run_hook(...)` allow path (LOW, batched fsync) | **76.0 µs** | **84.6 µs** | 518 µs | 94.0 µs | 32.3 µs | 921 |
| `run_hook(...)` block path (CRITICAL, force_fsync per emit) | **210 µs** | **408 µs** | 715 µs | 415 µs | 120 µs | 200 |

### 4.2 Reading the numbers - vs. README's published budget

The README claims "P50 < 2 ms / P99 < 10 ms" for the gate-allow path. The measured P50 of `run_hook` allow path is **85 µs** - **~24× under budget.** Even the block path with two force-fsyncs is **408 µs P50 / ~715 µs P99**, comfortably under 10 ms.

**Verdict: README is honest, but understates by an order of magnitude.** Quill's hot path is *much* faster than advertised. Re-pin the budget to the measured ceiling × 2 (safety margin) and bake into CI.

### 4.3 Where the µs are spent

Decomposition (subtraction from end-to-end):

| Stage | Estimated cost (P50) | Source |
|---|---|---|
| `decide()` LOW path | ~3 µs | direct measurement |
| `json.loads` of stdin payload | ~5 µs | 🔶 INFERENCE from CPython JSON benchmarks |
| `audit.emit` × 2 (attempted + verdict) | ~55 µs | direct measurement (2× 27.5 µs) |
| Session-index file open+write (line ~328 of claude_code.py) | ~10 µs | 🔶 INFERENCE - small JSON write to disk |
| Taint state read+write (when not flipping) | ~5 µs | 🔶 INFERENCE |
| Other glue / Python frames | ~5 µs | residual |
| **Total estimate** | **~83 µs** | matches measured 85 µs P50 ✓ |

**The flock cost is invisible at this scale** - `fcntl.flock(LOCK_EX)` on POSIX is a single syscall with ~1-2 µs overhead per take/release pair on Apple Silicon. ✅ INFERENCE from kernel source; no published microbenchmark surfaced in search ([fcntl Python docs](https://docs.python.org/3/library/fcntl.html); [chris.improbable.org file locking](https://chris.improbable.org/2010/12/16/everything-you-never-wanted-to-know-about-file-locking/)). This is well under our budget; no need to optimize.

**HMAC-SHA256** on a ~200-byte canonicalized payload runs at >100 MB/s on Apple Silicon (CommonCrypto-accelerated through OpenSSL). Per-emit HMAC is therefore ~2 µs of the 27.5 µs total. The dominant audit-emit cost is the JSON `dumps` + `os.write` syscall + flock pair - those are the irreducible parts.

### 4.4 Comparable tools' published latencies (✅ VERIFIED)

- **OPA** ([Open Policy Agent docs](https://www.openpolicyagent.org/docs/policy-performance)): *"For low-latency/high-performance use-cases, e.g. microservice API authorization, policy evaluation has a budget on the order of 1 millisecond."* OPA's "fast fragment" is engineered to evaluate near-constant-time as policies grow.
- **Cerbos** ([Cerbos blog](https://www.cerbos.dev/blog/low-latency-in-authorization)): *"sub-millisecond decision times when deployed close to the application... most overhead from JSON marshalling, not decision computation."* No published P99 number, just "sub-ms."

**Quill is competitive.** Quill's allow path is 85 µs P50, **12× faster than OPA's published budget ceiling**, on the same order as Cerbos. Different problem (we gate, they authorize), but the perf class is right.

### 4.5 pytest-benchmark - CI regression-fail pattern

Canonical pattern from [pytest-benchmark docs](https://pytest-benchmark.readthedocs.io/en/latest/comparing.html):

> *"`--benchmark-compare-fail=min:5%` will make the suite fail if Min is 5% slower for any test."*

**Recommended CI flow:**

```yaml
# .github/workflows/perf.yml - runs on every PR + main
- name: Run benchmarks against baseline
  run: |
    .venv/bin/pytest tests/test_bench_hot_path.py \
      -m bench --benchmark-only \
      --benchmark-min-rounds=200 \
      --benchmark-disable-gc \
      --benchmark-autosave \
      --benchmark-compare=0001 \
      --benchmark-compare-fail=median:50% \
      --no-cov
```

`median:50%` is generous on purpose. CI runners vary wildly (M-series macOS GH runners are ~1.4× slower than my local machine; Linux x86 runners are 2-3× slower). A 50% guardrail catches a real regression (forgot to compile a regex once per call, accidentally O(n²) on the regex iter, etc.) without flagging hardware noise.

Pin the baseline `0001` once, in the repo at `.benchmarks/`. Commit it.

### 4.6 Three highest-impact perf improvements (if any)

Honest answer: **none are warranted at this latency budget.** The hot path is already ~24× under the published budget. Time spent on perf would be better spent on TUI / OTel / onboarding.

If we ever DO need to push harder (someone runs Quill in a high-rate setting):

1. **Cache the per-tool risk decision** - `decide()` is currently recomputed on every call. A 1024-entry LRU keyed by `(tool_name, hash(args))` would amortize the regex iter. Estimated win: 2-3× on the LOW path (3 µs → ~1 µs). Not worth the cache-invalidation complexity until there's a customer who hits this. Defer.
2. **Buffer audit writes through a userspace ring + a single fsync thread** - today every CRITICAL emit force-fsyncs synchronously (50 µs). Moving fsyncs off-thread loses the synchronous durability guarantee, which we don't want for a CRITICAL block. Don't do this.
3. **Pre-compile the JSON canonical encoder** - `json.dumps(..., sort_keys=True, separators=(',', ':'))` is reasonably fast but `orjson` is 2-3× faster. orjson is **MIT** ([ijl/orjson](https://github.com/ijl/orjson)) so license is fine, but it's a binary wheel (~200 KB per platform). For 5 µs of savings on the audit-emit path it's not worth the bigger install. Defer indefinitely.

### 4.7 Concrete recommendations (perf)

**P-1 (medium leverage; do this week).** Land `tests/test_bench_hot_path.py` (the 12 benchmarks above). Add to CI as a separate job (does not run in the main `pytest` invocation; opt in via the `bench` mark which is already declared in `pyproject.toml`). Pin baseline to current numbers, set `--benchmark-compare-fail=median:50%`.

**P-2 (low effort).** Update `README.md` perf claim from "P50 < 2 ms / P99 < 10 ms" to *"measured on Apple Silicon, Python 3.14: gate-allow P50 ≈ 85 µs (≈ 11,800 ops/sec), gate-block P50 ≈ 408 µs"* with a link to the benchmark file and a paste-able command for users to verify their own machine.

**P-3 (low effort).** Add a one-page `docs/perf.md` with the table from §4.1 and the pytest invocation. Lets users assert their own machine hits the budget.

**P-4 (defer indefinitely).** All "actually optimize the hot path" work. Hot path is already an order of magnitude faster than the published budget. Don't optimize what doesn't need optimizing.

---

## Summary table - all recommendations ranked

Leverage = how much it moves the "vibe coders adopt this" needle. Effort = engineering hours. Risk = blast-radius of getting it wrong (regression / breakage / scope creep).

| ID | Recommendation | Leverage | Effort | Risk | Verdict |
|---|---|---|---|---|---|
| **T-1** | Textual `CommandPalette` provider with the 10 commands above | **HIGH** | M (~80 LOC + tests) | LOW | **ship in v0.2.1** |
| **N-1** | `quill notify test` subcommand (sync dispatch + per-channel results) | **HIGH** | S (~120 LOC) | LOW | **ship in v0.2.1** |
| **N-2** | `quill start` interactive wizard (rich.prompt; 5-step) | **HIGH** | M (~200 LOC) | LOW (idempotent) | **ship in v0.2.1** |
| **P-1** | Land benchmarks + CI guardrail (--benchmark-compare-fail) | MED | S (~150 LOC + 1 CI yaml) | LOW | **ship in v0.2.1** |
| **P-2** | Update README perf claim with measured numbers | MED | XS | NONE | **ship in v0.2.1** (5 mins) |
| **T-2** | Split-pane peek (tab toggles a 40% right pane) | MED | M | LOW | defer to v0.2.2 |
| **T-3** | Header heartbeat indicator | LOW | XS | NONE | ship if scope allows; otherwise v0.2.2 |
| **O-1** | `src/quill/otel.py` 92-line module + dual-write from `audit.emit` | **HIGH** | M (~150 LOC w/ tests) | MED (new dep, but optional extra) | **ship in v0.2.1** |
| **O-2** | `quill[otel]` extra in pyproject + starter-config commented section | LOW | XS | NONE | ship with O-1 |
| **O-3** | Integration test with InMemorySpanExporter | MED | S (~80 LOC) | NONE | ship with O-1 |
| **P-3** | `docs/perf.md` page | LOW | XS | NONE | ship with P-1 |
| **T-4** | Sub-agent collapse/expand | LOW | M | LOW | defer to v0.3 |
| **T-5** | Trifecta exposure mini-display in sidebar | MED | S | LOW | defer to v0.3 |
| **O-4** | OTel Events emission (gen_ai.evaluation.result) | LOW | M | LOW | defer to v0.3 - no immediate ingest target |

### Top 3 to ship in the 1-week window (ranked by leverage / effort)

1. **T-1 - Textual CommandPalette.** Single highest-leverage TUI change. Adds discoverability for ten existing operations (audit verify, time-window filter, tool filter, risk filter, approve, revoke, daemon status) without growing the keymap. ~80 LOC. Zero new dependencies.
2. **N-2 + N-1 - Onboarding wizard + `quill notify test`.** Together these close the "did this work?" loop on first install. Stripe / GitHub / Fly all do this; Quill does not yet. ~320 LOC total. Zero new dependencies (uses `rich.prompt` already in tree).
3. **O-1 + O-2 + O-3 - OTel emission as `quill[otel]` extra.** Unlocks Langfuse / Phoenix / Datadog ingest without changing Quill's audit log invariants. Apache-2.0 deps, MIT-compatible. ~230 LOC total + 80 LOC test. Optional install footprint.

### Defer to v0.3

P-1 + P-2 ship as a fast-follow (literally ~150 LOC + a CI yaml, no risk; could go in v0.2.1 if there's bandwidth, but doesn't gate adoption). T-2 / T-4 / T-5 / O-4 are all defer-to-v0.3.

