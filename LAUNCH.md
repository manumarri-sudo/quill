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

## Show HN blurb (current, drafted 2026-05-26, updated 2026-05-27 for v0.2.0a4)

> Show HN: Quill - a tiny Python proxy that gates risky AI-agent tool calls
>
> The coding agents in Claude Code, Cursor, and Cline can run shell commands, write files, push to git, and call deploy APIs, and none of them pause before doing irreversible things. Last summer Replit's agent deleted Jason Lemkin's production database during a vibe-coding session, ignored an explicit code-freeze instruction, and fabricated 4,000 fake users to cover the deletion; a Cursor agent ran `rm -rf ~/` against a developer's home directory two weeks later; an autonomous coding agent leaked a customer's GitHub PAT into a public commit a few weeks after that. The pause button between those agents and your prod just hadn't been built into the framework yet, so I built the smallest version of one I could.
>
> Quill is a small Python package that drops into Claude Code's `PreToolUse` hook in one command and gates every Bash, Edit, Write, and NotebookEdit before it executes. It can also sit in front of your external MCP servers (filesystem, github, postgres, slack) as a real schema-passthrough proxy, so your client still gets full autocomplete and JSON-RPC error codes are preserved end to end. Three layers, all deterministic, no LLM in the gate so nothing is jailbreakable:
>
> - **Camera:** every call gets a signed JSONL line, HMAC-chained to the previous entry for tamper evidence
> - **Badge:** out-of-scope calls are refused before the human is even asked, based on a scope you declared at session start
> - **Bank manager:** high-risk calls pause for a y/N, and critical ones (rm -rf, git push --force, DROP TABLE, vercel --prod, npm publish, .env reads, the CVE-2025-59536 subcommand-chain bypass) require you to type the action name back so muscle-memory yes-spamming can't ship a $50,000 mistake. When the gate refuses, you get a notification on whatever channel you opted in to (macOS banner, email, Slack, generic webhook) carrying what was tried, why it was blocked, and a paste-able `quill approve <token>` you can run from your phone with Touch ID
>
> Dogfood evidence, since the only honest version of this claim is the audit log: over 20 days on my own machine, 5,682 tool calls observed, 1,266 paused for input, 130 critical-class blocks, 8 real outbound notify dispatches, 1 Touch ID approval consumed, full chain still verifying at 10k+ entries. Two `chain.repaired` events from a pre-0.1.1 concurrent-write race are recorded in the log itself with the reason and line ranges, which is what tamper-evident logging is supposed to do.
>
> Honest about what's mature vs framework-prepared: the gate, audit, notification dispatch, approve-token, type-to-confirm, Touch ID, and trifecta-close enforcement pillars have on-disk evidence; the A2A bridge captures handoffs for Cursor 1.7+ today but Claude Code subagent capture is pending hook-API support from Anthropic; tool-description pinning works end-to-end but the external-MCP path is undogfooded relative to the built-in tools path. No public security audit yet, one is scheduled post-1.0. v0.2.0a4 is alpha; pair with model-level guardrails and your own legal review before production use.
>
> How this compares to others in the agent-gate-and-audit space: AEGIS (USC/UC Davis, MIT-licensed, March 2026, arXiv 2603.12621) is the closest academic analog with a 22-pattern detection library across 7 categories and a published 1.2% FP rate; it instruments via SDK wrappers across 14 frameworks and ships an enterprise web "Compliance Cockpit" for approvals. Snyk's Invariant Gateway (post-acquisition) is the enterprise MCP-gateway play. Anthropic's Claude Code Auto Mode (March 2026) adds cascaded-classifier permission decisions natively at a 0.4% FP rate. Quill's intentional lane is the developer-laptop, MCP-proxy form factor with Touch ID on the Secure Enclave for per-call hardware-attested approval; different audience, different surface, complementary rather than competing for the same buyer. On the v0.3 roadmap: track the IETF AIVS draft (`draft-stone-aivs-00`) so Quill's receipts are interoperable with the emerging agent-audit-trail standard before it's frozen.
>
> 598/598 tests passing. MIT, six runtime dependencies. The HMAC key and audit log live on your disk in mode 0o600, and you own the key, the log, and the verdict.
>
> Repo: https://github.com/manumarri-sudo/quill
> Install: `pipx install quillx` (or `uvx --from quillx quill ...` for a no-install run). PyPI: https://pypi.org/project/quillx/.
>
> Note on the name: the PyPI dist is `quillx` because the `quill` name on PyPI was held by an unrelated package. The CLI binary, import path, config directory, env vars, and brand all remain `quill`.

## Show HN blurb (archived v0.1 framing, do not use)

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

## PEP 541 reclaim — `quill` name on PyPI

The PyPI dist is `quillx` because the `quill` name is held by an unrelated package. State of the squatter as of 2026-05-26:

- Project: `pypi.org/project/quill/`
- Maintainer email on file: `robert@arweave.org`
- Linked repo: `github.com/usedispatch/Quill`
- Description: "Generate comprehensive README files for your project via LLM" (different domain)
- Releases: 1 total (1.0.0)
- Last upload: 2024-12-09 (17+ months silence as of 2026-05-26)

This meets PEP 541's abandonment criteria comfortably. Path is direct outreach first, six-week silence window, then file at `github.com/pypi/support`. If granted, ship a deprecation 1.0.1 of the original codebase that points users at Robert's repo, then start releasing this project under the reclaimed name (`quillx` becomes a transitional alias for a release or two, then sunsets).

### Email draft to current maintainer (send first)

> **Subject:** PyPI project name "quill" — request to discuss
>
> Hi Robert,
>
> I'm writing about the PyPI project page at https://pypi.org/project/quill/. I'm working on an open-source AI-agent governance tool (audit logging, action gating, tamper-evident chain) that I've been distributing under the name "quill" via GitHub (https://github.com/manumarri-sudo/quill) for several months, and I noticed your package shares the name on PyPI.
>
> Your package's last release was 1.0.0 in December 2024 and the listed purpose (README generation via LLM) is a different domain from mine, so I wanted to reach out directly rather than file anything administratively. Two possibilities, in order of preference for you:
>
> 1. If you're no longer actively developing the package, would you consider transferring the PyPI name to me? I'd be happy to attribute the prior project clearly in the release notes and to publish a deprecation 1.0.1 that points users at your repo for as long as PyPI allows.
> 2. If you'd prefer to keep the name, no problem — I'll ship under a different distribution name (currently `quillx`). Just wanted to ask before adopting that as the permanent choice.
>
> I'm filing this as a regular outreach under PEP 541. If I haven't heard back within six weeks I'll follow PyPI's standard process and file at https://github.com/pypi/support, but I'd much rather resolve it directly.
>
> Happy to share more about what I'm building if that's useful for your decision. Thanks for considering.
>
> Best,
> Manu Marri
> manu.marri@gmail.com
> https://github.com/manumarri-sudo/quill

### PyPI Support issue draft (file ONLY after 6+ weeks of silence or a decline-without-alternative)

> **Title:** PEP 541 request: transfer of project "quill" — abandoned
>
> Hi PyPI support team,
>
> I'm requesting transfer of the project name `quill` (https://pypi.org/project/quill/) under PEP 541's abandoned-project criteria.
>
> **Current project state:**
> - Single release: 1.0.0, uploaded 2024-12-09
> - No subsequent uploads in 17+ months as of this request
> - Project description: "Generate comprehensive README files for your project via LLM"
> - Linked repository: https://github.com/usedispatch/Quill
> - Maintainer email on file: robert@arweave.org
>
> **Abandonment evidence per PEP 541:**
> - 17+ months since last upload (exceeds the 1-year inactivity bar PEP 541 cites)
> - One total release, no maintenance activity visible on the linked repository
> - I contacted the current maintainer directly on YYYY-MM-DD and received [no response / declined without offering an alternative] within the six-week window (email thread attached / pasted below)
>
> **My project:**
> - Name: Quill (currently distributed as `quillx` on PyPI, https://pypi.org/project/quillx/)
> - Repository: https://github.com/manumarri-sudo/quill (public, MIT, 0.2.0a3 alpha, 586 passing tests)
> - Purpose: an MCP proxy + Claude Code PreToolUse hook that gates risky AI-agent tool calls and produces a tamper-evident audit log
> - Active development since early 2026; on-disk dogfood data covers 20+ days of real usage with 5,000+ audit events
> - Different domain from the existing project (AI agent governance vs README generation), so end-user confusion would be minimal
>
> **What I'm requesting:**
> Transfer of the `quill` project name to the PyPI user `manumarri-sudo` (https://pypi.org/user/manumarri-sudo/). I will publish a deprecation 1.0.1 release of the original codebase that points users at the original maintainer's repository, then begin shipping my project under the reclaimed name with `quillx` retained as a transitional alias for one release cycle.
>
> Happy to provide additional evidence, the full email thread with the current maintainer, or any other information you need.
>
> Thanks,
> Manu Marri (manumarri-sudo)
> manu.marri@gmail.com

## AEGIS author outreach (collegial pre-launch flag)

Architectural overlap with AEGIS (USC/UC Davis, MIT, March 2026) is real and worth flagging before launch so the relationship is collegial rather than adversarial when the two tools get compared in HN threads or follow-on academic write-ups. See `docs/research/aegis-comparison-2026-05.md` for the pattern-library comparison stub.

### Email draft to AEGIS authors

> **Subject:** Quill — an MCP-proxy / Touch-ID-native take on the AEGIS pattern
>
> Hi [author],
>
> I'm building Quill (https://github.com/manumarri-sudo/quill), an open-source Python package that gates AI-agent tool calls via Claude Code's PreToolUse hook plus an MCP proxy, with per-call Touch ID approval on macOS and an HMAC-chained audit log. I read the AEGIS paper (arXiv 2603.12621) and the architectural overlap is real — I wanted to flag the project to you ahead of a public launch so the relationship can be collegial rather than competitive when the two tools eventually get compared.
>
> Quill's intentional differences from AEGIS: MCP-proxy form factor instead of SDK wrappers (so it gates any MCP-compliant client without framework-specific shims), Touch ID on the Secure Enclave for per-call hardware-attested approval, and individual-developer audience rather than enterprise compliance buyers. I see Quill and AEGIS as complementary surfaces of the same gating thesis (deterministic gate, no LLM in the hot path, signed audit log), not direct substitutes.
>
> If useful, I'd love to compare pattern libraries once I've worked through your detection categories properly, share Quill's dogfood audit-log corpus (20+ days, 5,000+ events, two real chain-repair incidents recorded), and discuss whether there's a collaboration path on a shared attack-instance benchmark. Happy to chat any time.
>
> Best,
> Manu Marri
> manu.marri@gmail.com
> https://github.com/manumarri-sudo/quill
