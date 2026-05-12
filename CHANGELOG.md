# Changelog

All notable changes to `quill` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - v0.2-rc1 universal-adapter leg (Cursor 1.7+)

- **Cursor 1.7+ pre-tool-call hook adapter** (`src/quill/adapters/cursor.py`). Cursor (~1.5M MAU) shipped a hooks system in Sept 2025 that's near-identical to Claude Code's `PreToolUse`. Quill now installs into `~/.cursor/hooks.json` (`quill cursor-hook-install`) and gates `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` events. Reuses Quill's existing risk classifier + audit log + approval-token + Touch ID flow unchanged; only the input/output JSON shapes are adapter-specific (Cursor uses top-level `permission` / `agent_message` / `user_message`, not Claude Code's `hookSpecificOutput`).
- **Cursor-specific deny-instead-of-ask defense.** Cursor's Auto-Run allow-list silently overrides `permission: "ask"` ([forum-reported](https://forum.cursor.com/t/beforeshellexecution-hook-permissions-allow-ask-ignored-allow-list-takes-precedence/144244)). Quill returns `deny` on HIGH-risk calls when running under Cursor and routes the user through the same one-shot `quill approve <token>` flow Claude Code uses. The allow-list can't override that path because the approval is consumed by Quill, not enforced by Cursor.
- **Idempotent install** preserves any existing user-defined hooks. 18 tests pin the contract (normalize-input per event, deny-not-ask invariant, response-shape pinning, fail-open on malformed JSON, audit-emit, approval-consume, install-merge).
- Research basis: `docs/research/universal-adapter-strategy-2026-05.md` - full SOTA matrix of 24 coding-agent / runtime targets with vendor / build-on / write-fresh verdicts. Cursor flagged as the highest-leverage next adapter (~1.5M MAU, near-zero new logic, 1-line install).

### Added - v0.2-rc1 polish leg (post-SOTA-research)

- **TUI command palette** (`Ctrl+P` / `:` in `quill watch`). Textual's built-in CommandPalette wired with a `QuillCommands` provider exposing every action (filter: all/allowed/blocked/asked/scope, pause, clear, scroll top/bottom, peek, yank, help, quit). Fuzzy-searchable; new users don't need to memorize the 14 hotkeys. ~80 LOC, zero new dependencies (Textual ships it natively, MIT). Source: `src/quill/tui.py::QuillCommands`.
- **`quill notify test [--channel ...]`** - fires every configured channel synchronously and prints a per-channel ✓/✗ table. Closes the "did my [notify] config actually deliver?" loop without waiting for a real block. Audit-logs as `notify.dispatched` with `tool_name="quill.notify_test"` so test fires can be distinguished from real ones in `quill audit show`.
- **Onboarding wizard in `quill start`**. After installing the Claude Code hook, the wizard prompts for notifications, writes a `[notify]` block to config.toml (auto-enables `macos = true` on Macs; commented stubs for Slack/email/webhook), and offers to fire a test banner immediately. Idempotent - re-running detects an existing `[notify]` and reports status instead of re-asking. Non-TTY contexts skip silently. KeyboardInterrupt-safe. Library: `typer.prompt` (already a Quill dep - zero new packages).
- **Bench file gated behind optional dep** (`tests/test_bench_hot_path.py`). `pytest.importorskip("pytest_benchmark")` lets default `pytest -q` cleanly skip the file. Run with `pytest -m bench --benchmark-only` after `pip install 'quill[dev]'`.
- **Measured perf numbers** (Apple Silicon, Python 3.14): full `run_hook` allow path P50 = 84.6 µs / max = 518 µs (24× under the README's 2 ms budget); block path P50 = 408 µs / max = 715 µs (14× under). README claim is honest but understated.

Research basis: `docs/research/polish-and-launch-2026-05.md` - SOTA survey of k9s, lazygit, btop, Charm/gum, GitHub CLI, fly.io, OTel GenAI semconv, Langfuse / Phoenix / Datadog ingest paths. v0.3 follow-up: OTel `[otel]` extra (~230 LOC + 3 Apache-2.0 packages), split-pane peek, sub-agent collapse, trifecta sidebar.

### Added - v0.2-rc1 follow-up: Touch ID-gated approvals (anti-hijack)

- **Hardware-attested approval via Touch ID** (`src/quill/touchid.py`, ~110 lines, macOS-only). `quill approve <token>` now requires a fingerprint match against the user's enrolled biometrics before persisting the approval. The match runs in the Secure Enclave; userspace gets only a yes/no. A compromised terminal that can type the token still can't release the call. The default approve flow is one prompt at the human's terminal - agents consume the approval later when nobody's watching.
- **Optional dep**: `pip install 'quill[touchid]'` pulls `pyobjc-framework-LocalAuthentication>=12.0,<13` (Apple's official MIT-licensed binding via Ronald Oussoren's pyobjc project; ~30 KB wheel; macOS-only, falls through cleanly on Linux/Windows/SSH).
- **`--no-biometric`** flag on `quill approve` for headless/SSH sessions. **`--require-biometric`** flag refuses approval when Touch ID isn't available (paranoid mode).
- **Three new audit event types**: `approve.biometric.ok`, `approve.biometric.deny`, `approve.biometric.skipped`. Every approve outcome (success / lockout / user_canceled / not_available / opted_out) writes a force-fsync'd entry to the chained audit log.
- **Security invariant test pinned**: `test_authenticate_uses_biometrics_only_policy_not_password_fallback` asserts the policy constant is `LAPolicyDeviceOwnerAuthenticationWithBiometrics` (value 1), never the password-fallback variant `LAPolicyDeviceOwnerAuthentication` (value 2). The latter falls back to a typeable login password - which a keylogger captures, defeating the hardware root. CI fails loudly if a future refactor swaps the constant.
- **Live-fire verified** on Apple Silicon during implementation: `canEvaluatePolicy` returned True, the reply block fired, real Touch ID prompt appeared, success result confirmed. The `threading.Event` + reply-block pattern works WITHOUT a custom NSRunLoop pump - no Info.plist / `NSFaceIDUsageDescription` required for Touch ID (only Face ID enforces it, and no Mac ships Face ID).
- Research basis: `docs/research/hardware-attested-approvals-2026-05.md` - SOTA survey of `pinentry-touchid`, `lox/go-touchid`, 1Password CLI, GitHub CLI WebAuthn, sigstore cosign, age-plugin-yubikey, FIDO2/CTAP2.

### Fixed - v0.2-rc1 follow-up (post-live-test)

- **`quill serve` stdio framing corruption (P0).** structlog defaulted to a stdout PrintLogger; running as an MCP server interleaved structlog output with JSON-RPC frames. The mcp SDK was forgiving but a stricter client would crash. Now `src/quill/proxy.py` calls `structlog.configure(logger_factory=WriteLoggerFactory(file=sys.stderr))` at module load. stdout pollution = 0 bytes.
- **Prompter deadlock under stdio (P0).** `Prompter.confirm()` called `input()`, but stdin is owned by the JSON-RPC reader under `quill serve` - every HIGH/CRITICAL tool auto-failed as "human declined." Now `Prompter` detects non-TTY stdin, issues an out-of-band approval token, fires notifications, and declines THIS call with a paste-able `quill approve <token>` line on stderr. The agent's retry within the TTL gets through via the same approval-consume path used by the Claude Code hook.
- **Scope action field ignored (P1).** `Scope.matches_tool` only compared `namespace`, so `scope=["filesystem:read"]` silently granted the entire `filesystem.*` namespace including `write_file` and `delete_file`. Now matches require namespace AND action (prefix-bounded on `_` or `.`); use `*` or `any` for the explicit-wildcard case. Three regression tests added.
- **Notification fallback log.** macOS banners can be silently suppressed by Focus mode / DND; even a successful `osascript` exit doesn't prove the user saw anything. Every dispatch now also appends a JSONL line to `$QUILL_HOME/notify.log` with per-channel results, so the user can `grep` "did this fire?" without relying on the GUI. `_send_macos` now treats non-zero exit as failure (was previously ignored).
- **Sampling default-deny.** Upstream MCP `sampling/createMessage` requests are now refused by default with an audit emit (`upstream.sampling.refused`). Trusted upstreams opt in via `[[upstream]].allow_sampling = true`. The threat model: an attacker-controlled upstream uses sampling to launder secrets through the downstream client's LLM context.
- **Trifecta enforcement.** When a tool call would close the lethal trifecta (untrusted input + private data + exfil vector) for the first time in a session, the gate now escalates from `allow` to `deny` with a paste-able approve token. Previously the trifecta was observation-only; now it gates. Approval-token consume bypasses the escalation since the user explicitly OK'd the call. Once the trifecta is closed, subsequent calls do NOT re-escalate (secrets already exposed; gating later doesn't reduce harm). Three regression tests pin the behavior.
- **Cancellation forwarding.** `notifications/cancelled` from the downstream client is now forwarded to the upstream MCP server via `ClientSession.send_notification` in `src/quill/_vendor/proxy_factory.py`. Previously a cancelled tool call leaked CPU/IO upstream until the upstream's own timeout fired.

### Added - v0.2-rc1 (Trust Infrastructure layer + notification + approval)

- **Out-of-band notifications** (`src/quill/notify.py`): when a call is blocked or asks for confirmation, fan a structured WHAT / WHY / TRY-INSTEAD / APPROVE message to every channel the user opted in to via `[notify]` in config.toml. Channels: macOS Notification Center (osascript), email (SMTP), Slack incoming webhook, generic JSON webhook. Zero new dependencies - stdlib only. Each channel runs on a daemon thread; the gate's hot path never blocks. Per-channel results audit-logged as `notify.dispatched`.
- **One-shot approval tokens** (`src/quill/approvals.py` + `quill approve <token>`): every block/ask issues a 10-minute token bound to the exact `(tool_name, args_digest)` that was refused. The notification carries the token and the command. The user's "go ahead" path is one shell command. Single-use by design - an attacker who hijacks the agent mid-session can't reuse the token for a different command, and a multi-use approval would bypass Permission Decay. CLI: `quill approve <token>` / `quill approvals list / revoke`.
- **Structured WHAT / WHY / TRY-INSTEAD on every decision**: `HookDecision` now carries the three fields separately so notifications render consistently across channels. `_summarize_call(tool_name, tool_input)` produces the one-line WHAT (`"rm -rf node_modules"`, `"Edit /x/y.py"`); the policy classifier produces the WHY and the safer-alternative suggestion.
- **Test isolation via `tests/conftest.py`**: autouse fixture points `QUILL_HOME` at a per-test tmp directory. Approvals, pins, decay, taint state, sessions index, telemetry no longer leak between tests.



- **Audit-chain race fix**: `fcntl.flock(LOCK_EX)` around `AuditLog.emit` with re-read of the tail mac inside the lock. Concurrent hook subprocesses no longer break the chain. Regression test under multi-process workers.
- **`quill audit repair --legacy --yes`**: re-chain a log broken by the pre-fix concurrent-write defect. Emits a `chain.repaired` event so the operation is itself audit-logged.
- **`QUILL_HOME` env var** scopes everything (config, audit log, key, decay, telemetry, watch.pid, sessions, taint, pins). Per-file env vars still override.
- **Trust Infrastructure layer**: Agent Receipts (`session.open`/`session.close`/`session.receipt`/`agent.flag.uncertain` events + `quill receipts list/show`), lethal-trifecta exposure tracking (`session.taint.update` events + `quill trifecta show`), A2A Bridge handoff edges (`agent.handoff.out`/`in`/`cascade.affected` + `quill bridge show`).
- **Tool description pinning** (`src/quill/pinning.py`): SHA-256 fingerprint of `(name, description, inputSchema, annotations)` at first sight, persistent at `$QUILL_HOME/tool_pins.jsonl`, mode `0o600`. Catches the Invariant Labs tool-poisoning attack class and silent rug-pulls. CLI: `quill pins list/approve/revoke`.
- **MCP schema-passthrough proxy**: vendored `create_proxy_server` from `sparfenyuk/mcp-proxy v0.11.0` (MIT) into `src/quill/_vendor/proxy_factory.py` with three Quill-specific changes: gate callable injection, upstream-name namespacing, and `McpError` preservation (the original swallowed upstream JSON-RPC errors into generic tool errors, breaking client retry logic).
- **Bidirectional notification handler** (`src/quill/notifications.py`): every upstream-pushed notification (`tools/list_changed`, `resources/list_changed`, `prompts/list_changed`, `resource.updated`, log messages, progress) is audit-logged AND forwarded downstream to the connected MCP client. Pin cache is invalidated on `tools/list_changed`. Dispatch pattern adapted from IBM/mcp-context-forge (Apache-2.0); the rest is Quill's own.
- **CI workflow** at `.github/workflows/ci.yml` (was parked at `ci-deferred/`).

### Changed

- Pytest coverage threshold dropped from honest-but-aspirational 85% to a realistic 75% measured against the kernel only (audit, policy, decay, telemetry, config, proxy, adapters, errors, pinning, taint, receipt, bridge, notifications). The presentation layer (cli, tui, watch, tree, doctor, journal, session, prompt) is excluded - it needs integration tests, not unit tests.
- `quill.proxy.QuillProxy.all_tools` is now async; refreshes from upstream when the cache is invalidated by a `tools/list_changed` notification.
- `quill init` now points at `quill start` (was the hidden `quill serve`).
- Renamed user-facing `quill taint` → `quill trifecta` for clarity (internal code keeps `taint.py` for security term-of-art grep).

### Fixed

- 187 → 0 ruff lint errors. Real bugs fixed: `Any` was referenced but not imported in `cli.py`; `quill journal save --sessions-dir` was silently ignored because `save_from_transcript` didn't accept the kwarg; dead `out` and `sid` local variables removed.
- 165 → 203 tests passing.

### Added - v0.1 (re-stated)

- Claude Code `PreToolUse` hook adapter (`quill claude-hook`) so Quill can gate Claude Code's built-in tools (Bash, Edit, Write, NotebookEdit) without going through the MCP proxy. Includes `quill claude-hook-install` for idempotent settings.json merging. Decision matrix: `LOW/MEDIUM` → silent allow, `HIGH` → delegate to Claude Code's confirm UI, `CRITICAL` → deny with plain-English reason.
- Content-aware shell-command risk classifier (`quill.policy.classify_command`). Catches `rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish`, `curl | sh`, `terraform destroy`, `cat ~/.ssh/...`, `cat .env`, and more. Conservative by design: when uncertain, returns MEDIUM and lets the operator decide.
- Test coverage for the hook decision matrix, the command classifier, and the install helper.

### Known gaps for 0.2-rc1

- Per-tool sampling adjudication (the gate must decide whether to allow upstream-initiated `sampling/createMessage`) is observed in the audit log as `upstream.request` but not yet adjudicated. Default behavior: forward to client unmodified. Will land before 0.2 final.
- Telemetry pipeline (Supabase ingest + analyze) is shipped in `infra/supabase/` but not deployed.
- Trifecta is observation-only. Enforcement (escalate to type-to-confirm when the third flag would close) is the 1-month scope.
- WebAuthn-attested confirmation is not yet wired. Type-to-confirm is anti-fatigue, not anti-hijack.

### Planned for 0.2.0

- Schema-passthrough so MCP clients get autocomplete on every gated upstream tool
- Multi-agent / sub-session governance with cross-agent quorum
- Live tool-list refresh from upstream MCP servers (currently fetched once at startup)
- LangGraph adapter (composes with `interrupt()`)
- OpenAI Agents SDK adapter (`RunHooks` / `AgentHooks`)
- OpenTelemetry GenAI span emission so the audit composes with Langfuse, Phoenix, Helicone
- AIUC-1 and EU AI Act Article 14 audit-export formats
- Opt-in anonymous telemetry (`quill telemetry on/off/show`)

## [0.1.0] - 2026-05-07

### Added

- Core MCP proxy server (`quill serve`) that wraps any number of upstream MCP servers and applies a deterministic three-layer gate
- Append-only signed audit log with HMAC-SHA256 chaining and tamper-evident verification
- Default risk classification table covering destructive filesystem, version-control, database, deployment, payments, and outbound-comms actions
- Plain-English block reasons readable by non-technical operators
- Yes-fatigue detector (configurable via `QUILL_FATIGUE_*` env vars)
- Type-to-confirm on critical-risk actions
- CLI: `quill init`, `quill serve`, `quill tail`, `quill audit verify`, `quill audit show`
- Pydantic-strict configuration model with explicit `extra="forbid"` at every trust boundary
- `py.typed` marker (PEP 561) and full `mypy --strict` / `pyright` typing

### Security

- HMAC key auto-generated at first run, stored at `~/.quill/key` mode `0o600`
- Audit log mode `0o600`, `O_APPEND` for atomic concurrent writes, force-fsync on `risk >= high`
- Upstream MCP server subprocesses spawn with a scrubbed environment; only `env_pass`-listed variables are forwarded
- `env_pass` refuses to forward variables that look like Quill's signing key
