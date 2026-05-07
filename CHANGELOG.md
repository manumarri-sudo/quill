# Changelog

All notable changes to `quill` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Claude Code `PreToolUse` hook adapter (`quill claude-hook`) so Quill can gate Claude Code's built-in tools (Bash, Edit, Write, NotebookEdit) without going through the MCP proxy. Includes `quill claude-hook-install` for idempotent settings.json merging. Decision matrix: `LOW/MEDIUM` → silent allow, `HIGH` → delegate to Claude Code's confirm UI, `CRITICAL` → deny with plain-English reason.
- Content-aware shell-command risk classifier (`quill.policy.classify_command`). Catches `rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish`, `curl | sh`, `terraform destroy`, `cat ~/.ssh/...`, `cat .env`, and more. Conservative by design: when uncertain, returns MEDIUM and lets the operator decide.
- Test coverage for the hook decision matrix, the command classifier, and the install helper.

### Known gaps for 0.1

- The MCP proxy in `src/quill/proxy.py` connects to upstreams and the gate fires correctly, but tool re-advertising is currently a single generic `quill.call(tool_name, arguments)` rather than passing through full JSON schemas to the MCP client. Schema-passthrough is the v0.2 headline.
- Telemetry config exists in `src/quill/config.py` but the wire-up is opt-in and currently inert.

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
