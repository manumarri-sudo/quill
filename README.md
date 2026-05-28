# quill

> The pause button between your AI agent and the things you can't undo.

<!-- mcp-name: io.github.manumarri-sudo/quill -->

[![PyPI](https://img.shields.io/pypi/v/quillx.svg)](https://pypi.org/project/quillx/)
[![Python versions](https://img.shields.io/pypi/pyversions/quillx.svg)](https://pypi.org/project/quillx/)
[![CI](https://img.shields.io/github/actions/workflow/status/manumarri-sudo/quill/ci.yml?branch=main&label=ci)](https://github.com/manumarri-sudo/quill/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Typed](https://img.shields.io/badge/typed-strict-brightgreen.svg)](https://peps.python.org/pep-0561/)

`quill` sits between your MCP client (Claude Code, Cursor, Cline, Claude Desktop) and the upstream MCP servers your agent uses. It also plugs into Claude Code's `PreToolUse` hook so the *built-in* tools (Bash, Edit, Write, NotebookEdit) get the same treatment. Every tool call passes through three deterministic checks:

1. **camera**, logged to a signed JSONL audit log, always
2. **badge**, the call's namespace and resource must match a scope you declared at session start, or it's blocked before the agent even tries
3. **bank manager**, high-risk actions pause for a y/N; critical-risk actions (delete, drop table, force-push, deploy:production, refunds) require you to type the action name back so muscle-memory yes-spamming doesn't ship a $50,000 mistake

When the gate refuses a critical call, Quill ships you a notification on whatever channel you opted in to (macOS banner, email, Slack, generic webhook) carrying *what was tried*, *why it was blocked*, *what to try instead*, and a paste-able `quill approve <token>` you can run from your phone if you actually meant it.

```text
                                         ╭─────────────╮
   Claude Code   ─── stdio ──>  quill ─┼─→ filesystem
                                         ├─→ github
                                         ├─→ postgres
                                         ╰─→ slack
                                              │
                                     signed audit log
                                              │
                              ┌───────────────┴───────────────┐
                          receipts          trifecta        bridge
                       (did/changed/    (untrusted +     (A2A handoff
                        uncertain)      private + exfil)   edges)
```

## Why this exists

Last July, [Replit's coding agent deleted Jason Lemkin's production database during a vibe-coding session, ignored an explicit code-freeze instruction, and fabricated 4,000 fake users to cover the deletion](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/). Two weeks later a Cursor agent ran `rm -rf ~/` against a developer's home directory in a session a journalist later said "violated every principle of safe agent design." A few weeks after that, an autonomous coding agent leaked a customer's GitHub PAT into a public commit. The agents writing your code right now have the same authority. The pause button between them and your prod just hadn't been built into the framework yet.

`quill` is the smallest version of one I could write.

## What's mature in 0.2.0a2 vs framework-prepared

`quill` is built around three pillars and the maturity of each is honestly different. This section exists because dogfooding evidence matters more than design intent.

**Mature, with on-disk evidence in real-world dogfooding** (the gate + audit pillar):
- Destructive-action gate: hundreds of critical blocks observed across `rm -rf`, `vercel --prod`, `git push --force`, `DROP TABLE`, `TRUNCATE`, `npm publish`, `sudo`, `.env` reads, and the CVE-2025-59536 subcommand-chain bypass. Zero false positives in the critical class.
- HMAC-chained audit log: 10k+ entries verified end-to-end. Tamper-evident, mode `0o600`, EU AI Act Article 14 fields on every block.
- Out-of-band notification dispatch on real blocks: macOS banner, email, Slack, generic webhook. Synchronous-with-100ms-timeout on the hot path so the dispatch can't be killed mid-flight by the hook subprocess exiting.
- One-shot approve tokens, Touch ID hardware-attested approval, anti-yes-fatigue, type-to-confirm: full block-to-approve cycle observed end-to-end with audit chain evidence.
- Trust scope with trifecta enforcement priority: trusted directories suppress default-risk Edit/Write asks, but yield to trifecta enforcement when the session is at 2-of-3 flags and the call would close the third.
- Self-improving classifier: drift detection, suggestions CLI, learner persistence.

**Framework-prepared, with thinner dogfooded evidence** (the Trust Infrastructure pillar):
- Lethal-trifecta detection AND enforcement: detection observed across dozens of sessions; enforcement (escalate allow → deny when a call would close the trifecta) verified end-to-end on a synthetic test. Real-world enforcement triggers depend on operator workflow.
- A2A Bridge: handoff edge tracking works for the **Cursor adapter** and for tests; **Claude Code subagent capture is pending hook-API support from Anthropic** (the PreToolUse payload doesn't currently expose subagent session_ids, so subagent spawns audit-log under the parent session). If you're using Quill with Cursor, you get full A2A; with Claude Code today you get parent-level audit only.
- Permission Decay: tracking infrastructure is wired and tested; no overrides observed in single-developer dogfooding yet because the operator hasn't yet promoted a `loosening_candidate` via `quill suggestions promote`. The decay timer fires when overrides accumulate.
- Tool description pinning: pin recording, digest verification, and approval/revoke CLI all work; only one tool has been observed in dogfooding because the external MCP proxy path (Path B below) is less exercised than the Claude Code built-in tools path (Path A).

**On the v0.3 roadmap**: A2A bridge workaround for Claude Code via transcript-path heuristics, more external MCP server dogfooding to populate the pinning subsystem, real-world Permission Decay triggers as the suggestions CLI gets used, and tracking the IETF AIVS draft (`draft-stone-aivs-00`) so Quill's receipts stay interoperable with the agent-audit-trail standard.

## Install

```bash
uvx quillx start
```

That's the whole thing on a fresh machine if you have [`uv`](https://docs.astral.sh/uv/) installed. If you'd rather a persistent install, `pipx install quillx` then `quill start`, or `pip install quillx` inside an existing venv. For a development checkout: `git clone https://github.com/manumarri-sudo/quill && cd quill && pip install -e .`. Homebrew lands as a self-owned tap (`brew install manumarri-sudo/quill/quill`) shortly.

The PyPI dist name is `quillx` because the `quill` PyPI name is held by an unrelated package. The CLI binary (`quill`), import path, config directory (`~/.quill/`), env vars (`QUILL_KEY`), and brand all stay `quill`. A PEP 541 reclaim request for the canonical name is in flight; if it lands, `quillx` becomes a transitional alias for one release cycle and then sunsets.

`quill start` is idempotent: it merges Quill's hook into `~/.claude/settings.json`, runs `quill doctor`, and opens the live dashboard. From the next Claude Code session on, every Bash, Edit, Write, and NotebookEdit goes through Quill's classifier; every external MCP call (if you wire Quill into `mcpServers`) goes through the proxy.

## Two integration paths

Quill governs two surfaces. Both ship in v0.2; pick whichever fits how you code, or use both.

### Path A: Claude Code's built-in tools (recommended for vibe coders)

Claude Code's `Bash`, `Edit`, `Write`, and `NotebookEdit` are not MCP tools, they're internal. Quill plugs into Claude Code's `PreToolUse` hook so every built-in tool call is gated before it executes.

```bash
quill start                      # installs the hook, starts the dashboard
# restart Claude Code
```

That's it. From the next session on, every Bash command, every Edit, every Write goes through Quill's classifier. `rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, and `npm publish` are denied by default with a plain-English reason. Edits to files prompt Claude Code's confirm-this-action UI. Reads pass silently. Every decision lands in `~/.quill/audit.log.jsonl` with an HMAC-chained signature.

The hook is a content-aware classifier: `Bash("ls")` is low-risk, `Bash("rm -rf /")` is critical. The decision logic lives in [`quill.policy.classify_command`](src/quill/policy.py); patterns are explicit and testable.

### Path B: External MCP servers (filesystem, github, postgres, slack)

If you also use Claude Code's `mcpServers` config to point at upstream MCP servers, Quill can sit in front of those too. v0.2 ships a real schema-passthrough proxy: every upstream tool's `inputSchema`, description, and annotations are re-advertised to the client *as the upstream sent them*, so your client gets full autocomplete, the gate sees the real arguments, and JSON-RPC error codes are preserved end to end.

```bash
quill init                              # writes ~/.quill/config.toml
# edit config.toml - declare session intent, scope, [[upstream]] blocks, [notify] channels
```

Then in your Claude Code `mcpServers` config:

```jsonc
{
  "mcpServers": {
    "quill": { "command": "quill", "args": ["serve"] }
  }
}
```

The proxy factory at [`src/quill/_vendor/proxy_factory.py`](src/quill/_vendor/proxy_factory.py) is adapted from `sparfenyuk/mcp-proxy` v0.11.0 (MIT, attributed in [NOTICE](NOTICE)) with three Quill-specific changes: gate callable injection on `_call_tool` / `_read_resource` / `_get_prompt`, upstream-name namespacing (`filesystem.read_file`), and `McpError` preservation (the original swallowed upstream JSON-RPC errors into generic `CallToolResult(isError=True)`, breaking client retry logic).

## The notification + approval flow

When Quill blocks a critical-risk call, it fans an out-of-band message to every channel the user opted in to via `[notify]` in `config.toml`. Channels: macOS Notification Center (osascript), email (SMTP), Slack incoming webhook, generic JSON webhook. Zero new dependencies, stdlib only. Each channel runs on a daemon thread; the gate's hot path never blocks. Per-channel results are themselves audit-logged as `notify.dispatched`.

Every notification carries four fields:

- **WHAT** was attempted, one line. `"git push --force origin main"`, `"Edit /etc/passwd"`, `"DROP TABLE customers"`.
- **WHY** it was blocked, in plain English. `"force-push to a protected branch is critical-risk and rewrites shared history"`.
- **WHAT TO TRY INSTEAD**, a safer alternative the agent can paste back. `"git push --force-with-lease"` or `"open a PR and let CI rebase"`.
- A one-shot **APPROVE** command: `quill approve T7gQ2x9aB4`.

The token is bound to the exact `(tool_name, args_digest)` that was refused, single-use, 10-minute TTL. An attacker who hijacks the agent mid-session cannot reuse the token for a different command, and a multi-use approval would bypass Permission Decay.

### Concrete example

The agent runs `git push --force origin main`. Quill blocks. Notification on your phone:

```
quill blocked: git push --force origin main
why : force-push rewrites shared history; protected branch
try : git push --force-with-lease    (or open a PR)
approve once: quill approve T7gQ2x9aB4   (10 min, single-use)
```

You read the message, agree the agent meant well, paste the command in any terminal:

```bash
$ quill approve T7gQ2x9aB4
approved git push for one call · expires 2026-05-08T15:42:11
  the agent's next attempt of this exact call will go through.
```

The agent retries, the gate consumes the approval, the push lands. The `approve` action is itself audit-logged.

```bash
quill approvals list           # see pending tokens
quill approvals revoke <token> # drop a token if the notification looked surprising
```

## Trust Infrastructure layer

v0.2 adds three audit-log surfaces that derive directly from the chain. They're computed on read; nothing extra is written. Frameworks the user is publishing on (Trust Infrastructure, Agent Receipts, A2A Bridge, Permission Decay) underpin the design but the surfaces are usable without them.

### Agent Receipts

Per session, `did / changed / uncertain / to_verify`, the four-field mental model for what an agent actually did during a session. Derived from `session.open` / `session.close` / `session.receipt` / `agent.flag.uncertain` events.

```bash
quill receipts list            # one row per session, ordered by recency
quill receipts show ses_a4f1   # full did/changed/uncertain/to_verify
```

### Lethal-Trifecta exposure tracking

Did this session see *untrusted input* + *private data* + *an exfiltration vector* all together? That's the worst-case prompt-injection scenario per Meta's Agents Rule of Two and Simon Willison's Lethal Trifecta. Two of three is recoverable, three is the danger zone.

```bash
quill trifecta show            # per-session three-flag matrix + verdict
quill trifecta show --closed   # only sessions where all three closed
```

Trifecta in v0.2.0a2 is **observation AND enforcement**. The classifier surfaces the exposure on every tool call, and when a call would close the lethal trifecta (untrusted + private + exfil all in one session) for the first time, the gate escalates an otherwise-allow decision to a deny with a paste-able approve token. Trust scope yields to this enforcement so trusted directories can't silently bypass the trifecta gate. Verified end-to-end with on-disk evidence on 2026-05-17 (audit log entries at `verdict.blocked` with reason `trifecta close · ...`).

### A2A Bridge handoff edges

When agent A spawns agent B as a sub-task, the handoff itself is an event with a contract. The A2A Bridge tracks those edges, flags orphans (handoff-out with no matching handoff-in), and detects cascade failures (one bad handoff propagating downstream).

**Adapter maturity as of v0.2.0a2**: full handoff capture works for the **Cursor adapter** (Cursor 1.7+ surfaces subagent session_ids in its hook payload). For **Claude Code**, subagent spawns currently audit-log under the parent session because Claude Code's `PreToolUse` hook doesn't expose subagent session_ids; bridge capture there is **pending hook-API support from Anthropic**. See the "What's mature vs framework-prepared" section near the top of this README for the full breakdown.

```bash
quill bridge show              # all handoff edges, status (ok / orphan / cascade)
quill bridge show --orphans    # only the unmatched ones
```

## Tool description pinning

The Invariant Labs MCP tool-poisoning advisory (March 2025) and the silent-rug-pull attack class both rely on the same primitive: an upstream server changing a tool's *description* between first sight and the moment the agent decides to call it. Quill records a SHA-256 fingerprint of `(name, description, inputSchema, annotations)` the first time it sees each tool, persists it at `$QUILL_HOME/tool_pins.jsonl` mode `0o600`, and refuses to re-advertise tools whose digest changed without explicit user approval.

```bash
quill pins list                                    # all pinned tools, status, first-seen
quill pins approve filesystem read_file <digest>   # accept a new digest
quill pins revoke filesystem read_file             # hide the tool from the client
```

The pin cache invalidates automatically on any upstream `tools/list_changed` notification.

## Bidirectional notification forwarding

Every notification an upstream MCP server pushes (`tools/list_changed`, `resources/updated`, `prompts/list_changed`, `LoggingMessageNotification`, `ProgressNotification`) is audit-logged AND forwarded downstream to the connected MCP client unmodified. Pin cache invalidates on `tools/list_changed`. The dispatch idiom (class-name-substring matching against the notification root type) is adapted from `IBM/mcp-context-forge` (Apache-2.0, attributed in [NOTICE](NOTICE)); the rest is Quill's own.

## What it does, concretely

| Layer | Question | What it does |
|---|---|---|
| camera | did this happen? | every call gets a signed JSONL line, HMAC-SHA256-chained for tamper evidence |
| badge | is this in scope? | deterministic check; out of scope = refused, no AI deciding |
| bank manager | should this happen *right now*? | high-risk = y/N prompt; critical-risk = type the action name; out-of-band notification + one-shot approve token on every block |

Default risk classification is in [`src/quill/policy.py`](src/quill/policy.py). Out of the box, `fs.delete`, `git push --force`, `DROP TABLE`, `deploy:production`, `stripe.refunds.*`, `send_email`, `rm -rf`, `vercel --prod`, `npm publish`, `curl | sh`, `terraform destroy`, and `cat .env` are classified `critical` and require typed confirmation. Override per-tool in your config:

```toml
[policy]
"fs.delete"          = "critical"
"github.list_issues" = "low"
```

## Anti-yes-fatigue

If you approve three high-risk prompts in under four seconds each, the next prompt holds for three seconds before accepting input. This is the same anti-pattern Stripe, GitHub, and Sentry apply to their own dangerous-action UX. Tunable via `QUILL_FATIGUE_*` env vars. Type-to-confirm is anti-fatigue, not anti-hijack: WebAuthn-attested confirmation is on the roadmap, not yet wired.

## The signed audit log

Every event lands in `$QUILL_HOME/audit.log.jsonl`, mode `0o600`. Format:

```json
{"ts":"2026-05-08T01:14:22Z","session_id":"ses_a4f1","agent_id":"root","type":"tool.attempted","risk":"critical","prev_mac":"…","payload":{"tool_name":"fs.delete","arg_keys":["path"],"arg_count":1},"mac":"…"}
{"ts":"2026-05-08T01:14:24Z","session_id":"ses_a4f1","agent_id":"root","type":"verdict.blocked","risk":"critical","prev_mac":"…","payload":{"tool_name":"fs.delete","reason":"force-push rewrites shared history","try_instead":"git push --force-with-lease"},"mac":"…"}
```

Each entry's `mac` is `HMAC-SHA256(prev_mac || canonical(payload))` under your installation's key (auto-generated at first run, stored at `$QUILL_HOME/key`, mode `0o600`). The hot path uses `fcntl.flock(LOCK_EX)` around every emit and re-reads the tail mac inside the lock so concurrent hook subprocesses can't break the chain. Verify the chain at any time:

```bash
quill audit verify
# chain intact: 472 entries verified.
```

If you have a log broken by the pre-0.1.1 concurrent-write defect:

```bash
quill audit repair --legacy --yes
# emits a chain.repaired event so the operation is itself audit-logged
```

This is the artifact your auditor will want. EU AI Act Article 14 and AIUC-1 both require evidence of human oversight on high-risk AI actions, with timestamps, decision, and reason. The format above carries all of that.

## `~/.quill/` layout

`QUILL_HOME` (default `~/.quill/`) holds everything. Mode `0o600` on every file.

| File | Purpose |
|---|---|
| `config.toml` | session intent, scope, upstreams, `[notify]`, `[policy]` overrides |
| `audit.log.jsonl` | append-only HMAC-chained event log |
| `key` | 32-byte HMAC signing key, auto-generated on first run |
| `permissions.json` | Permission Decay state (use counts, last-reaffirmed timestamps) |
| `telemetry.json` | opt-in telemetry state (`asked`, `opted_in`, `install_id`) |
| `tool_pins.jsonl` | tool description pins, append-only |
| `approvals.json` | pending one-shot approval tokens |
| `taint.json` | per-session lethal-trifecta state (renamed user-facing to `trifecta`) |
| `sessions.json` | open/close index for fast Receipts derivation |
| `watch.pid` | pidfile for the background dashboard daemon |

Per-file env-var overrides still work: `QUILL_LOG`, `QUILL_KEY`, `QUILL_CONFIG`, etc.

## CLI surface

```
quill start          set up + open the dashboard (most users only run this)
quill watch          in-terminal live dashboard (TUI by default; --browser for HTTP)
quill audit          review what got blocked / allowed / asked (verify, repair, show)
quill decay          permissions that erode without reinforcement (Permission Decay)
quill receipts       per-session did / changed / uncertain / to-verify (list / show)
quill bridge         A2A handoff edges between agents (show, --orphans)
quill trifecta       exposure tracking: untrusted input + private data + exfil vector
quill pins           tool description pins (list / approve / revoke)
quill approvals      list / revoke pending one-shot approval tokens
quill approve <tok>  consume a token, allow the next exact-match call
quill doctor         diagnose the install (config / log / key / hook / upstreams)
quill stop           stop the background watch daemon
quill version        print the quill version
```

Hidden / power-user commands: `init` (write starter config), `serve` (run the MCP proxy), `tail` (live-stream audit log), `tree` (delegation tree, snapshot or live), `claude-hook` + `claude-hook-install` (the PreToolUse adapter), `journal` (write a session log to the AgentOS vault), `telemetry` (opt-in aggregate stats).

## Performance

Quill aims for invisible: P50 overhead < 2ms on the policy-allow path, P99 < 10ms. Hot path is pre-compiled regex + hash-table lookup; the audit log uses `O_APPEND` and batched fsync (force-fsync on `risk >= high`). Cross-process safety via `fcntl.flock(LOCK_EX)`. Benchmarks ship with the repo (`pytest -m bench`).

## What this is not

- Not an AI safety system. It does not predict whether an action is bad. It records, scope-checks, and asks a human on dangerous calls.
- Not a replacement for OAuth or RBAC. Identity says you are *allowed* to refund. Quill says *this specific* refund, in *this specific* session, deserves a confirmation.
- Not a hosted service. It is a single Python package. The audit log lives on your disk. You own the key, the log, the verdict.

## Known gaps for v0.2.0a2

Honest list of what is shipped vs. observation-only vs. not yet wired. See also the "What's mature vs framework-prepared" section near the top of this README for the dogfooding-evidence breakdown.

- **Claude Code subagent capture in A2A Bridge** depends on Anthropic shipping subagent session_ids in the `PreToolUse` hook payload. Until then, subagent spawns audit-log under the parent session; the bridge sees no edge. The Cursor adapter is unaffected and gets full A2A capture today.
- **Per-tool sampling adjudication.** Upstream-initiated `sampling/createMessage` calls are observed in the audit log as `upstream.request` but not yet adjudicated. Default behavior: forward to client unmodified. Will land before 0.2 final.
- **WebAuthn-attested confirmation is not wired.** Touch ID (macOS) is the hardware-attested option today; WebAuthn for cross-platform hardware attestation is on the v0.3 roadmap.
- **Telemetry pipeline.** Supabase ingest + analyze functions exist in `infra/supabase/` but are not deployed. Opt-in only; default off.
- **Schema-passthrough proxy is end-to-end** for tool calls and the gate sees real arguments. Resources, prompts, and notifications all forward; full lifecycle test coverage is in progress.
- **PyPI / Homebrew / npm wrapper / MCP registries**: not yet submitted. Distribution plan in [docs/distribution.md](docs/distribution.md).

## Security

`quill` is itself a security-critical piece of code. The threat model, hardening recommendations, and responsible-disclosure address are in [SECURITY.md](SECURITY.md). When PyPI publish lands, releases will be signed via [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) with PEP 740 attestations.

## Contributing

If you have a published red-team trace, a missed dangerous-action class, or a vibe-coding disaster I should be defaulting to critical, open an issue. If you have a framework adapter you want to see (LangGraph, AutoGen, CrewAI, OpenAI Agents SDK), open a PR; adapters live under `src/quill/adapters/`.

## License

MIT. See [LICENSE](LICENSE). Vendored third-party code is attributed in [NOTICE](NOTICE) (sparfenyuk/mcp-proxy MIT, IBM/mcp-context-forge Apache-2.0). Version history in [CHANGELOG.md](CHANGELOG.md). Repo: [github.com/manumarri-sudo/quill](https://github.com/manumarri-sudo/quill).

---

Built with assistance from Claude (Anthropic).
