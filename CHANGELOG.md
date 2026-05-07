# Changelog

All notable changes to `quill` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for 0.2.0

- Multi-agent / sub-session governance with scope attenuation and cross-agent quorum
- Live tool-list refresh from upstream MCP servers (currently fetched once at startup)
- Re-emission of upstream JSON-Schema upward so MCP clients get autocomplete
- LangGraph adapter (composes with `interrupt()`)
- OpenAI Agents SDK adapter (`RunHooks` / `AgentHooks`)
- OpenTelemetry GenAI span emission so the audit composes with Langfuse, Phoenix, Helicone
- AIUC-1 and EU AI Act Article 14 audit-export formats

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
