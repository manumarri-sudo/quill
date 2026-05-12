# Launch notes

Internal-facing notes for shipping `quill` publicly. Edit / discard before posting.

## Repo description (GitHub)

> An MCP proxy that gates risky AI-agent actions. Pauses high-risk tool calls for a human, blocks critical ones outright, and signs every decision into a tamper-evident audit log. Drops into Claude Code's PreToolUse hook so it gates Bash, Edit, Write before the agent runs them.

## Suggested GitHub topics

`mcp` `model-context-protocol` `ai-agents` `claude-code` `cursor` `agent-governance` `ai-safety` `human-in-the-loop` `audit-log` `python`

## Three taglines, ranked

1. **The pause button between your AI agent and the things you can't undo.** (current README)
2. **Your AI coding agent has the keys to prod. Quill puts a gate in front of them.**
3. **Sign every tool call. Pause the dangerous ones. Audit-log everything.**

## Short X / Twitter post

> AI coding agents now have shell, file write, and deploy access. None of them ask before doing anything irreversible.
>
> quill is a 6KB Python proxy that gates `rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish` and signs every decision into an audit log.
>
> Drops into Claude Code's PreToolUse hook in one command.
>
> [link]

## LinkedIn post

> Last summer Replit's coding agent deleted Jason Lemkin's production database in a vibe-coding session, ignored an explicit code-freeze instruction, and fabricated data to cover it. The agents writing your code right now have the same authority. The pause button between them and prod just hadn't been built into the framework yet.
>
> I shipped a small one: quill. It's an MCP proxy + Claude Code hook that gates the destructive moves before they execute, asks the human to confirm the high-risk ones, and signs every decision into a tamper-evident audit log. The format carries everything EU AI Act Article 14 and AIUC-1 want for human-oversight evidence.
>
> Open source, MIT, six dependencies. v0.1 alpha is up. Feedback welcome - especially missed dangerous-action patterns.
>
> [link]

## Show HN blurb

> Show HN: quill - a tiny Python proxy that gates risky AI-agent tool calls
>
> The agents in Claude Code, Cursor, and Cline can run shell commands, edit files, and call deploy APIs. None of them pause before doing irreversible things. quill is a 6KB Python package that sits between the agent and the tools.
>
> Three layers, all deterministic (no LLM in the gate):
> - Camera: every call gets a signed JSONL line, HMAC-chained for tamper evidence.
> - Badge: out-of-scope calls are refused before the human is even asked.
> - Bank manager: high-risk calls pause for a y/N; critical ones (rm -rf, git push --force, DROP TABLE, vercel --prod, npm publish) require typing the action name.
>
> v0.1 ships a Claude Code PreToolUse hook adapter that gates Bash/Edit/Write/NotebookEdit. Plus a generic MCP proxy for the external servers (filesystem, github, postgres, slack).
>
> Honest about what's not done: the MCP proxy in v0.1 re-advertises upstream tools through a single generic call adapter rather than passing schemas through. That's the v0.2 headline.
>
> No telemetry by default. Audit log lives on your disk. You own the key, the log, the verdict.
>
> [link to repo]

## Five demo ideas

1. **30-second GIF: the rm -rf save.** Open Claude Code in a real repo. Ask it to "clean up node_modules and reinstall." Show Quill catching `rm -rf node_modules` with the plain-English reason in the deny dialog.
2. **The deploy save.** Same setup, prompt "deploy this to prod." Quill blocks `vercel --prod` and `npm publish` with reasons.
3. **The compliance demo.** Run a 20-action session, then show `quill audit show --last 30` and `quill audit verify`. Frame as "this is what your EU AI Act Article 14 evidence looks like."
4. **Live-tail streaming.** Split-pane Terminal: Claude Code on the left mid-task, `quill tail --live` on the right showing each gate decision as it lands.
5. **Multi-agent attenuation.** Run `examples/multi_agent_demo.py`, show the tree visualizer with three agents (planner, coder, reviewer) each operating under attenuated scopes.

## Ten good-first-issue ideas

1. Adapter for **Cursor** (PreToolCall hook contract - likely similar to Claude Code's).
2. Adapter for **Aider** (file-edit gating via Aider's pre-commit shim).
3. Adapter for **Cline** (VS Code extension - needs an IPC bridge).
4. **PostgreSQL MCP** integration test that connects to a real Dockerised Postgres and runs `DROP TABLE`, verifying the gate fires.
5. **Stripe MCP** integration test stubbing the Stripe API and verifying `stripe.refunds.create` requires type-confirm.
6. **Risk-classifier coverage report**: run `classify` over a published list of MCP tools (Anthropic's official servers + 20 community ones) and report the risk distribution - output a `docs/coverage.md` so users can see what's covered.
7. **`quill doctor` command** that verifies the install: config valid, key file 0o600, audit log writable, hook installed, upstream MCPs spawn cleanly.
8. **JSON-LD `auditExport` command** that produces an EU AI Act Article 14-shaped export from the audit log. Schema first, then implementation.
9. **Anti-fatigue tunables docs**: a one-page page in `docs/` explaining the fatigue detector with worked examples.
10. **Windows path-traversal hardening**: replace string-based path checks in scope-resource matching with `pathlib.PurePath` operations so backslash paths can't sneak past.

## Honest disclaimers (do not skip in launch posts)

- v0.1 is alpha. The audit-log primitives and the Claude Code hook are well-tested; the MCP proxy schema-passthrough is not.
- We don't claim to defeat prompt-injection. Quill records, scope-checks, and asks. If the model is tricked into not calling a tool at all, Quill has nothing to gate. Pair with model-level guardrails.
- No public security audit yet. SECURITY.md describes the threat model; we're aiming for an external review post-1.0.
