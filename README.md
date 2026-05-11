# quill

> The pause button between your AI agent and the things you can't undo.

[![PyPI](https://img.shields.io/pypi/v/quill.svg)](https://pypi.org/project/quill/)
[![Python](https://img.shields.io/pypi/pyversions/quill.svg)](https://pypi.org/project/quill/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Typed](https://img.shields.io/badge/typed-strict-brightgreen.svg)](https://peps.python.org/pep-0561/)

`quill` is a proxy that sits between your MCP client (Claude Code, Cursor, Cline, Claude Desktop) and the upstream MCP servers your agent uses. Every tool call passes through three deterministic checks:

1. **camera** &mdash; logged to a signed JSONL audit log, always
2. **badge** &mdash; the call's namespace and resource must match a scope you declared at session start, or it's blocked before the agent even tries
3. **bank manager** &mdash; high-risk actions pause for a y/N; critical-risk actions (delete, drop table, force-push, deploy:production, refunds) require you to type the action name back so muscle-memory yes-spamming doesn't ship a $50,000 mistake

Once you're inside the gate, you can breathe.

```text
                                           ╭─────────────╮
   Claude Code   ─── stdio ──>  quill ─┼─→ filesystem
                                           ├─→ github
                                           ├─→ postgres
                                           ╰─→ slack
                                                │
                                       signed audit log
```

## Why this exists

Last July, [Replit's coding agent deleted Jason Lemkin's production database during a vibe-coding session, ignored an explicit code-freeze instruction, and fabricated data to cover the deletion](https://www.reuters.com/article/saastr-replit-database-deletion). The agents writing your code right now have the same authority. The pause button between them and your prod just hadn't been built into the framework yet.

`quill` is the smallest version of one I could write.

## Install

```bash
pip install quill
quill init
```

This writes a starter config to `~/.quill/config.toml`. Edit it to declare your session intent, scope, and the upstream MCP servers Quill should proxy.

## Two integration paths

Quill governs two different surfaces. Both ship in v0.1; pick whichever fits how you code.

### Path A: Claude Code's built-in tools (recommended for vibe coders)

Claude Code's `Bash`, `Edit`, `Write`, and `NotebookEdit` are *not* MCP tools. they're internal. Quill plugs into Claude Code's `PreToolUse` hook so every built-in tool call is gated before it executes.

```bash
pip install quill
quill claude-hook-install        # idempotently merges the hook into ~/.claude/settings.json
# restart Claude Code
```

That's it. From the next session on, every Bash command, every Edit, every Write goes through Quill's classifier. `rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, and `npm publish` are denied by default with a plain-English reason. Edits to files prompt Claude Code's confirm-this-action UI. Reads pass silently. Every decision lands in `~/.quill/audit.log.jsonl` with an HMAC-chained signature.

The hook is a content-aware classifier: `Bash("ls")` is low-risk, `Bash("rm -rf /")` is critical. The decision logic lives in [`quill.policy.classify_command`](src/quill/policy.py); patterns are explicit and testable.

### Path B: External MCP servers (filesystem, github, postgres, slack)

If you also use Claude Code's `mcpServers` config to point at upstream MCP servers (filesystem, github, postgres, slack, ...), Quill can sit in front of those too.

```bash
quill init
# edit ~/.quill/config.toml. declare your session intent, scope, and upstreams
quill serve
```

Then in your Claude Code `mcpServers` config:

```jsonc
{
  "mcpServers": {
    "quill": { "command": "quill", "args": ["serve"] }
  }
}
```

> **v0.1 status:** the proxy connects to upstreams and the gate fires correctly, but tool re-advertising is currently a single generic `quill.call(tool_name, arguments)` rather than full schema passthrough. Schema-level passthrough is the headline feature for v0.2. For v0.1, prefer Path A for built-ins; use Path B if you want every external-MCP call signed and scope-checked but are willing to call upstream tools via the generic `call` adapter for now.

## What it does, concretely

| Layer | Question | What it does |
|---|---|---|
| camera | did this happen? | every call gets a signed JSONL line, HMAC-chained for tamper evidence |
| badge | is this in scope? | deterministic check; out of scope = refused, no AI deciding |
| bank manager | should this happen *right now*? | high-risk = y/N prompt; critical-risk = type the action name |

Default risk classification is in [`src/quill/policy.py`](src/quill/policy.py). Out of the box, `fs.delete`, `git push --force`, `DROP TABLE`, `deploy:production`, `stripe.refunds.*`, `send_email`, and similar dangerous-by-default actions are classified `critical` and require typed confirmation. Override per-tool in your config:

```toml
[policy]
"fs.delete"          = "critical"
"github.list_issues" = "low"
```

## Anti-yes-fatigue

If you approve three high-risk prompts in under four seconds each, the next prompt holds for three seconds before accepting input. This is the same anti-pattern Stripe, GitHub, and Sentry apply to their own dangerous-action UX. Tunable via `QUILL_FATIGUE_*` env vars.

## The signed audit log

Every event lands in `~/.quill/audit.log.jsonl`, mode `0o600`. Format:

```json
{"ts":"2026-05-07T01:14:22Z","session_id":"ses_a4f1","agent_id":"root","type":"tool.attempted","risk":"critical","prev_mac":"…","payload":{"tool_name":"fs.delete","arg_keys":["path"],"arg_count":1},"mac":"…"}
{"ts":"2026-05-07T01:14:24Z","session_id":"ses_a4f1","agent_id":"root","type":"verdict.blocked","risk":"critical","prev_mac":"…","payload":{"tool_name":"fs.delete","reason":"HumanDeclined"},"mac":"…"}
```

Each entry's `mac` is `HMAC-SHA256(prev_mac || canonical(payload))` under your installation's key (auto-generated at first run, stored at `~/.quill/key`, mode `0o600`). Verify the chain at any time:

```bash
quill audit verify
# chain intact: 472 entries verified.
```

This is the artifact your auditor will want. EU AI Act Article 14 and AIUC-1 both require evidence of human oversight on high-risk AI actions, with timestamps, decision, and reason. The format above carries all of that.

## Multi-agent (v0.2 roadmap)

When agent A spawns agent B as a sub-task, B inherits a strict subset of A's scope and writes to the same audit log. Critical actions can require quorum (N of M agents must agree) before executing. Coming in v0.2; the architecture is in place in v0.1.

## Performance

Quill aims for invisible: P50 overhead < 2ms on the policy-allow path, P99 < 10ms. Hot path is pre-compiled regex + hash table lookup; the audit log uses `O_APPEND` and batched fsync (force-fsync on `risk >= high`). Benchmarks ship with the repo (`pytest -m bench`).

## What this is not

- Not an AI safety system. It does not predict whether an action is bad. It records, scope-checks, and asks a human on dangerous calls.
- Not a replacement for OAuth or RBAC. Identity says you are *allowed* to refund. Quill says *this specific* refund, in *this specific* session, deserves a confirmation.
- Not a hosted service. It is a single Python package. The audit log lives on your disk. You own the key, the log, the verdict.

## Security

`quill` is itself a security-critical piece of code. The threat model, hardening recommendations, and responsible disclosure address are in [SECURITY.md](SECURITY.md). The releases are signed via [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) with PEP 740 attestations.

## Contributing

If you have a published red-team trace, a missed dangerous action class, or a vibe-coding disaster I should be defaulting to critical, open an issue. If you have a framework adapter you want to see (LangGraph, AutoGen, CrewAI, OpenAI Agents SDK), open a PR. adapters live under `src/quill/adapters/`.

## License

MIT.

---

Built with assistance from Claude (Anthropic).
