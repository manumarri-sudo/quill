# Launch notes

Internal-facing notes for shipping `quill` publicly. Edit / discard before posting.

## Repo description (GitHub)

> MCP proxy that gates AI-agent tool calls before they run. Pauses risky ones for a human, blocks critical ones (`rm -rf`, `git push --force`, `DROP TABLE`), and signs every decision into an HMAC-chained audit log. Plugs into Claude Code's PreToolUse hook so it covers Bash, Edit, and Write.

(Sync this string into the GitHub repo settings → About section by hand. It's not a tracked file there, so the LAUNCH.md copy is the source-of-truth and the GitHub UI has to be edited separately.)

## Suggested GitHub topics

`mcp` `model-context-protocol` `ai-agents` `claude-code` `cursor` `agent-governance` `ai-safety` `human-in-the-loop` `audit-log` `python`

## Three taglines, ranked

1. **The pause button between your AI agent and the things you can't undo.** (current README)
2. **Your AI coding agent has the keys to prod. Quill puts a gate in front of them.**
3. **Sign every tool call. Pause the dangerous ones. Audit-log everything.**

## Short X / Twitter post

> AI coding agents have shell access, file write, and deploy permissions, and none of them ask before doing anything irreversible.
>
> Quill is a small Python proxy that gates `rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish`, and the CVE-2025-59536 chain bypass, then signs every decision into a tamper-evident audit log. Touch ID approval on macOS for critical calls.
>
> One command to install: `uvx quillx start`.
>
> [link]

## LinkedIn post

> Last summer Replit's coding agent deleted Jason Lemkin's production database in a vibe-coding session, ignored an explicit code-freeze instruction, and fabricated 4,000 fake users to cover the deletion. The agents writing your code right now have the same authority on your machine, and the frameworks themselves haven't shipped a pause button between those agents and prod.
>
> I built a small one. Quill is an MCP proxy plus a Claude Code PreToolUse hook that gates destructive moves before they execute, asks for a human y/N on high-risk calls, requires Touch ID on macOS for the critical ones, and signs every decision into a tamper-evident HMAC-chained audit log. The format carries the evidence EU AI Act Article 14 and AIUC-1 want for human-oversight requirements.
>
> Open source, MIT, seven runtime dependencies, 598 passing tests. v0.2.0a5 alpha is live on PyPI as `quillx` (install with `uvx quillx start` or `pipx install quillx`). Feedback is the most useful thing you can leave, especially on missed dangerous-action patterns or threat-model gaps.
>
> [link]

## Show HN blurb v3 (current, 2026-05-27, research-informed)

> Show HN: Quill – Touch ID approval gates for AI agent tool calls
>
> Hi HN. I'm Manu, a solo developer, and Quill is a small open-source Python package I've been building since early 2026 that gates risky AI-agent tool calls before they execute. The one-line version: it sits between Claude Code or Cursor and the things your agent can break, pauses for a human y/N on high-risk calls, requires Touch ID on macOS for critical ones, and signs every decision into a tamper-evident audit log.
>
> Three incidents last summer pushed me here. Replit's coding agent deleted Jason Lemkin's production database during a vibe-coding session and then fabricated 4,000 fake users to cover the deletion. A Cursor agent ran `rm -rf ~/` against a developer's home directory shortly after. An autonomous coding agent leaked a customer's GitHub PAT into a public commit a few weeks later. The frameworks themselves didn't ship with a pause button between those agents and prod, so I built the smallest one I could.
>
> Quill drops into Claude Code's `PreToolUse` hook in one command and gates every Bash, Edit, Write, and NotebookEdit before it executes, and it can also sit in front of your external MCP servers as a schema-passthrough proxy so your client keeps full autocomplete and JSON-RPC error codes round-trip cleanly. Three deterministic layers, no LLM anywhere, so nothing is jailbreakable. First, a camera: every call gets a signed JSONL line, HMAC-chained to the previous entry, so the log is tamper-evident. Then a badge: out-of-scope calls are refused before you're even asked, against a scope you declared at session start. Then a bank manager: high-risk calls pause for a y/N, and critical ones (rm -rf, git push --force, DROP TABLE, vercel --prod, npm publish, .env reads, the CVE-2025-59536 subcommand-chain bypass) make you type the action name back so muscle-memory yes-spamming can't ship a $50,000 mistake. When the gate refuses, you get a notification on whichever channel you opted into (macOS banner, email, Slack, generic webhook) carrying what was tried, why it was blocked, and a paste-able `quill approve <token>` you can run from your phone with Touch ID on the Secure Enclave.
>
> The only honest version of any of this is the audit log itself. On my own machine over the past 40+ days: 11k+ tool calls observed, 1.2k+ paused for input, 130+ critical-class blocks, real notify dispatches and Touch ID approvals consumed, the chain still verifying cleanly. Two `chain.repaired` events from a pre-0.1.1 concurrent-write race sit in the log itself with reasons and line ranges, which is what tamper-evident logging is supposed to do.
>
> Honest about scope, because alpha-stage projects in this space tend to overclaim. The gate, audit, notification dispatch, approve-token, type-to-confirm, Touch ID, and trifecta-close enforcement all have on-disk evidence. The A2A bridge captures handoffs for Cursor 1.7+ today, but Claude Code subagent capture is pending hook-API support from Anthropic. Tool-description pinning works end-to-end, but the external-MCP path is less exercised than the built-in tools path. On Claude Cowork (Anthropic's desktop product), Quill can run as an MCP connector and gate upstream MCP calls, but Cowork's built-in file and browser tools bypass Quill because Cowork doesn't yet expose a PreToolUse-equivalent hook. There's no public security audit yet; one is scheduled post-1.0. v0.2.0a5 is alpha, so pair with model-level guardrails and your own legal review before any production use.
>
> Some other tools in this space worth knowing about: Microsoft's Agent Governance Toolkit (April 2026, MIT) is the closest direct competitor, with a seven-package monorepo, OWASP Agentic Top 10 framing, and sub-millisecond enforcement. BlueRock's MCP Python Hooks (May 2026) is the closest runtime-sensor analog. Anthropic's Claude Code Auto Mode adds cascaded-classifier permission decisions natively. AEGIS (USC/UC Davis, MIT, arXiv 2603.12621) is an academic project in adjacent territory targeting injection-class attacks. Quill is intentionally smaller and aimed at a different audience — developer laptops with an MCP-proxy form factor, Touch ID on the Secure Enclave for per-call hardware-attested approval, shipped as a single Python package with no daemon and no web service. It isn't trying to compete with any of the above on their axes.
>
> 598/598 tests passing. MIT, seven runtime dependencies. The HMAC key and audit log live on your disk in mode 0o600, and you own the key, the log, and the verdict. I'll be in the thread for the next few hours. Feedback (especially missed dangerous-action patterns or threat-model gaps) is the most useful thing you can leave.
>
> Repo: https://github.com/manumarri-sudo/quill
> Install: `uvx quillx start`, or `pipx install quillx` then `quill start`. PyPI: https://pypi.org/project/quillx/.
>
> The PyPI dist is `quillx` because the `quill` name on PyPI is held by an unrelated package. CLI binary, import path, config directory, env vars, and brand all stay `quill`.

## Show HN blurb v2 (archived 2026-05-27, superseded by v3 after launch-research pass)

> [v2 was the May-26 draft with a Cline mention in the opening, an AEGIS-anchored comparables paragraph, and `pipx install quillx` as the lead install. v3 replaces it with: Touch-ID-first title, seven-part structure per the 2026 Show HN best-practice research, Microsoft AGT + BlueRock as the primary comparables, Cowork compatibility scope statement, and `uvx quillx start` as the hero install.]

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

## Launch arc — T-3 → T+30 (research-informed, 2026-05-27)

Pulled from a 2026-vintage research pass on Show HN mechanics, MCP-ecosystem distribution, and recent comparable launches (Microsoft Agent Governance Toolkit April 2026, BlueRock MCP Python Hooks May 2026). The biggest correction to the previous 3-day plan: the demo GIF and the official MCP Registry submission both need to be live BEFORE the Show HN, not after, and the launch arc should be 5 days plus a follow-through, not 3 days.

### T-3 — visible artifacts in the README

- Record the 30-second demo GIF showing `rm -rf` attempted, blocked by Quill with reason, Touch ID prompt, audit log entry surfaced afterward. The demo should show the failure mode Quill prevents, not just the feature it ships. Embed above the fold in the README.
- Verify `uvx quillx start` works from a clean machine (fresh shell, no Python venv preloaded, no `~/.quill/` state). Smoke-test on both Intel and Apple Silicon if possible.
- Confirm the README badge row is live: PyPI version, Python versions (from PyPI metadata), CI status, license, typed. Add codecov once coverage runs are wired.
- Refresh stale audit-log numbers in the Show HN blurb against the live `~/.quill/audit.log.jsonl` (currently 11k+ entries, 40+ days).

### T-2 — security-tool credibility signals

- Enable PEP 740 attestations on the next release via `pypa/gh-action-pypi-publish@v1.11.0+` plus PyPI Trusted Publishing. Roughly 20k packages already ship attestations by default in 2026; not having them is a negative signal for a security-positioned tool.
- Confirm SECURITY.md is current (already in repo) — disclosure email, threat model, CWE coverage.
- CITATION.cff at repo root (added in this commit) — academic-adjacent projects expect this.
- Decide on Trusted Publishing registration. Either Manu does the ~3-min PyPI web form so future releases ship via OIDC end to end, or we keep using fresh bootstrap tokens per release.

### T-1 — registry submissions + Show HN pre-work

- Submit `server.json` (already drafted at repo root) to the official MCP Registry at `registry.modelcontextprotocol.io`. This is the canonical upstream that mcp.so, Smithery, and others ingest from, so doing it first gives them time to pick up the listing before launch day.
- Pre-write the full Show HN body (v3 above) in a text file, ready to paste.
- Pre-draft 3-4 candidate responses to the most likely critical comments: "this already exists / why not OPA / Cerbos / Permit.io", "why Touch ID specifically", "why not WebAuthn or hardware key", "security tool from a non-security background — how do I trust this", "what's the threat model on the audit log itself", "what about Linux / Windows".

### T-0 — Show HN day

- Post Tuesday or Wednesday between 8-9am EST (HN's conventional dev-tool window). Sunday midnight-1am PT is the counter-cyclical alternative with 2x average comments per a 2025 analysis, but the HN community itself has pushed back on timing optimization — quality dominates.
- Title verbatim: "Show HN: Quill – Touch ID approval gates for AI agent tool calls".
- Post the LinkedIn version *separately* later in the day, not within the first hour of the HN post. Let HN breathe.
- Clear your calendar for the next 3+ hours. The first-hour comment window is the load-bearing variable; HN's algorithm watches for sustained author engagement. Handle "this already exists" by agreeing with the legitimate part first, then explaining the specific delta, never deflect.
- Same day, in parallel with HN engagement: submit to mcp.so (self-service form), Smithery (`smithery mcp publish`), open the PR against `punkpeye/awesome-mcp-servers`. These show up in HN comments as proof of distribution.

### T+1 — amplify

- Submit to the Cline marketplace with a 400×400 PNG logo prepared. Issue against `github.com/cline/mcp-marketplace`.
- Publish the LinkedIn post (the version above, already drafted).
- Substack version: write a 600-800 word essay anchored on the Replit / Lemkin incident framing and the Trust Infrastructure thesis. Cross-link to the HN thread for the technical discussion.
- Cross-post tailored versions to r/LocalLLaMA, r/ChatGPTCoding, r/cursor with each subreddit's idiom.

### T+7 — retrospective

- Publish a retrospective post with concrete numbers: HN traffic, GitHub stars, PyPI downloads, top three feature requests received, what's shipping in v0.3. This is a second wave of distribution for anyone who missed launch day.
- Update the README "Why this exists" and "What's mature vs framework-prepared" sections with anything the launch surfaced.

### T+30 — v0.3 with feedback-driven change

- Ship v0.3 with the top feedback-driven change from launch week. If the change is substantive enough, re-launch via "Show HN: Quill 0.3" — `dang`'s guidance allows a re-launch for material new work.
- Backlog items still tracked: A2A bridge workaround for Claude Code via transcript-path heuristics, external MCP server dogfooding for tool pinning, WebAuthn-attested confirmation for cross-platform hardware attestation, IETF AIVS draft (`draft-stone-aivs-00`) interoperability.

## Launch arc, Product Hunt parallel track

Product Hunt is a different surface from Hacker News and the arc above does not transfer cleanly. PH runs on a 24-hour cycle starting 12:01 AM Pacific, the ranking algorithm rewards upvote cadence across the full day rather than a first-hour burst, and the audience skews more product-marketing and indie-hacker than HN's infrastructure-engineer crowd, so the framing has to lead with what changes for the developer rather than the deterministic-three-layer architecture. The plan below assumes the same Wednesday 2026-06-17 target as the HN arc so both shipped surfaces share one prep week.

Image dimensions cited here are the sizes used across 2026 PH launch writeups including Flo Merian's awesome-product-hunt guide. Worth a quick check against PH's own submission form before queuing artwork, since the requirements have shifted twice in the last year.

### PH T-3 (Sun 2026-06-14): visual assets ready

- Thumbnail: 240×240 PNG with the wordmark and the quill brand color. The 1024×1024 logo from commit `bda039b` rescales cleanly to this size.
- Gallery: at least three images at 1270×760 PNG. One hero shot of the Touch ID approval dialog mid-block, one wide shot of the terminal with `quill watch` running alongside Claude Code, and one of the audit log surface showing real blocks.
- Demo loop: the same 30-second `rm -rf` save asciinema from the README, exported as an MP4 sized to PH's loop player (PH accepts MP4 / GIF up to ~3 MB).
- One paragraph of body copy under 260 characters that does not repeat the tagline.

### PH T-2 (Mon 2026-06-15): supporter list and hunter call

- Pre-launch supporter list of 30 to 50 people who have engaged with Quill in any form: early GitHub stargazers, Twitter replies on the v0.1 sketches, the people who commented on the audit-log thread in May. Soft pings the day before launch ("hey, I'm shipping tomorrow, no expectation but here's the page") move better than a launch-day cold ask.
- Hunter decision. Per Flo Merian's 2026 guide, 79% of featured PH posts are self-hunted, and a first-time PH launcher with a niche security-developer audience does not need a hunter to chart. Self-hunt unless a known-in-PH-circles person volunteers in the next 48 hours.
- Maker account age check. PH wants the account to be at least 30 days old at launch. The account at `producthunt.com/@manumarri` is older than that so this is a no-op verification.
- PH Ship draft created: title `Quill: Touch ID approval gates for AI agent tool calls`, tagline `Your AI agent has shell access. Quill puts a gate in front of it.`, links to PyPI and GitHub, gallery uploaded.

### PH T-1 (Tue 2026-06-16): queue and final review

- Final review of the Ship draft. Confirm links resolve, demo loop plays without sound, maker name spelled correctly.
- Pre-write the maker comment in full. See the next section for a draft.
- Pre-write the Twitter announcement to fire at 6 AM PT on launch day, after the early-cohort PH supporters have voted.
- Block the calendar from 5 AM PT through 9 PM PT on Wednesday. PH's ranking algorithm weights maker engagement and comment count alongside upvotes, and the awesome-product-hunt guide is explicit that maker presence for the full 24-hour window is what tends to separate top-five from the rest.

### PH T-0 (Wed 2026-06-17): launch day

- 12:01 AM PT: Ship goes live, post the maker comment in the first minute. The comment is the pinned conversation starter, and posting it after upvotes have started arriving means latecomers miss the framing.
- 12:01 to 4 AM PT: low traffic window, mostly West Coast night owls and EU morning commuters. Reply to anything that lands but do not chase volume here.
- 5 to 8 AM PT: West Coast wakeup. Most comments arrive in this window. Respond to every one within an hour.
- 8 AM PT, which is 11 AM ET: Post to Hacker News. This gives PH a five-hour head start and means HN's first-hour critical window happens while PH is mid-cycle. The split-attention risk is real but the load distributes both ways. If that feels too thin, defer HN to Thursday 2026-06-18 morning and run PH solo on Wednesday.
- Throughout the day: respond to every PH comment within an hour. The ranking algorithm visibly weights maker engagement and the comment count itself, not just upvotes.
- 6 PM PT: publish the LinkedIn post. Late afternoon PT is a US East Coast evening read, which lands well on LinkedIn.
- 9 PM PT: Twitter post with a screenshot of the PH ranking at that hour.

### PH maker comment draft

The maker comment is the pinned story under the listing and is the most important piece of copy on the day. Lead with the user problem in plain language, then say what shipped, then invite a conversation. Avoid the architectural framing that works on HN.

> Hi everyone, I'm Manu.
>
> Last summer Replit's coding agent deleted Jason Lemkin's production database during a vibe-coding session, then made up 4,000 fake users to cover the deletion. A few weeks later a Cursor agent ran `rm -rf ~/` on a developer's home directory. The agents writing code on your laptop right now have shell access, file write, and deploy permissions, and none of the popular frameworks ship a pause button between those agents and prod.
>
> Quill is the smallest pause button I could build. It drops into Claude Code's PreToolUse hook in one command and gates every Bash, Edit, Write, and NotebookEdit before the agent runs it. Critical-class calls (`rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish`) require Touch ID on macOS, which uses the Secure Enclave so the approval is hardware-attested. Every decision goes into a tamper-evident HMAC-chained audit log on your disk that `quill doctor` verifies in one command. There's no LLM in the gate, no cloud service, no telemetry on by default.
>
> One command to try it: `uvx quillx start`.
>
> Two things I would love feedback on. First, missed dangerous-action patterns. The policy table is in `src/quill/policy.py` and every entry is a regex with a test, so "this misses X" is the most useful comment you can leave. Second, the Cowork story. Quill works as an MCP connector inside Claude Cowork today (config snippet in `docs/clients.md`), but Cowork's built-in tools don't flow through the local MCP path so the gate can't see them. That's the same gap Cline and Windsurf have, and the fix has to come from Anthropic shipping a Cowork PreToolUse hook.
>
> Repo and PyPI in the links above. I'll be in the thread all day.

## Critical-comment response drafts

These are pre-drafted answers to the comment shapes most likely to land in the first hours on Hacker News and Product Hunt. Each one agrees with the legitimate part of the criticism first, then explains the specific delta. Per HN convention, do not deflect, do not soften, do not pivot to a different defense when the question is sharp. If a real comment lands and the question is materially different from these, write a fresh answer rather than forcing the canned one.

### "This already exists. Why not OPA / Cerbos / Permit.io?"

> Fair, those are the right tools for application authorization and Quill is not trying to replace them. The OPA / Cerbos / Permit.io family targets RBAC and ABAC over the resources inside your application. Quill targets a different layer, which is the AI agent's tool dispatch path on a developer laptop. Two constraints make the layers different enough to justify a separate tool. The gate has to know what `rm -rf node_modules` means, not just that the Bash tool is allowed in this scope, which is content-aware classification rather than authz. And the human-in-the-loop has to be one-touch on a phone or laptop without leaving the dev flow, which is what the Touch ID approval token loop is for. Could you build the same thing on top of OPA with custom policies and a hardware-attested approval extension? Probably, and that would be a fine implementation choice. Quill is the opinionated single-binary version with the policy library already populated for the specific class of irreversible operations AI agents try to run.

### "Why Touch ID specifically?"

> Because it is the lowest-friction hardware-attested approval primitive on the developer machines Quill actually runs on. The Secure Enclave fingerprint already exists, the user already trusts it, and there's no extra hardware to provision. The alternative is a terminal `y` followed by Enter, which loses to muscle-memory yes-spam, and yes-spam is exactly the failure mode the Replit incident was. WebAuthn is a credible cross-platform alternative and it's in the v0.3 backlog. Touch ID is the pragmatic Mac-first answer for v0.2 because most Claude Code and Cursor users are on Mac in disproportion and the Secure Enclave is a hardware path that's already provisioned.

### "Why not WebAuthn or a hardware key?"

> WebAuthn is the right cross-platform answer and it's in the v0.3 backlog. Quill ships Mac-first in v0.2 because the Secure Enclave is the lowest-setup hardware attestation surface on Mac and Mac is where the bulk of Claude Code and Cursor usage actually happens. Building WebAuthn correctly means standing up a relying-party flow, which is more code than I wanted shipping in the v0.2 surface. Hardware keys via FIDO2 fall out of the same work once WebAuthn lands, because the protocol is shared and only the authenticator differs.

### "Security tool from a non-security background. How do I trust this?"

> Honest answer: don't take my word for it, read the diff. The threat model is in SECURITY.md, the HMAC chain is in `src/quill/audit.py` and is about 60 lines, the policy table is in `src/quill/policy.py` with one regex per pattern and one test each. The gate is deterministic with no LLM anywhere, so there's no "model judgment" attack surface. The worst case is that a regex is too narrow and misses a case, which is a feature for someone who wants to grep their own approval rules rather than trust opaque heuristics. I would much rather be told "your regex misses X" than "trust me, I'm a security person." No public audit yet. One is scheduled post-1.0.

### "What's the threat model on the audit log itself?"

> The audit log is an append-only JSONL file at `~/.quill/audit.log.jsonl`, mode 0o600. Each line carries an HMAC over (`previous_hmac` || canonical event payload), so any edit to a past line breaks the chain in a way `quill doctor` and `quill audit verify` catch on a re-walk from the beginning. The key lives at `~/.quill/key` mode 0o600 and is generated once at install. Two `chain.repaired` events from a pre-0.1.1 concurrent-write race sit in the log itself with the line ranges and reasons, which is what tamper-evident logging is supposed to do. You don't hide the repair, you record it. The known limit: if the attacker has root and can read the key, they can rewrite the chain end-to-end. That's the same limit OS-level secret stores have without a TPM or hardware-keystore-attested key. The v0.3 roadmap includes macOS Keychain-attested key storage to close that gap on Mac.

### "What about Linux and Windows?"

> v0.2 ships Mac-first because the Touch ID Secure Enclave path is the differentiated approval primitive and that's Apple-only. The gate, audit log, policy, notification dispatcher, and approve-token flow all work on Linux today. CI runs on Ubuntu and all 598 tests pass. What you don't get on Linux is the per-call hardware-attested approval. You get terminal prompt plus Slack, email, or webhook notification, plus paste-the-token-back from any terminal. WebAuthn is the cross-platform path in v0.3. Windows needs a fresh path-traversal hardening pass before it ships honestly, and that's one of the good-first-issues listed below.

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

## AEGIS author outreach — decided NOT to send (2026-05-27)

Originally planned as a collegial pre-launch flag to USC/UC Davis. Walked through the actual overlap on 2026-05-27 and decided to skip:

- The category-level overlap (both are deterministic pre-execution gates with tamper-evident audit logs) is real but generic — at that level Quill also "overlaps" with Datadog or Sentry, which is to say the framing is too coarse to mean anything.
- The substantive overlap is thin. AEGIS's 7 categories (SQL Injection, Path Traversal, Shell Injection, Prompt Injection, Sensitive Files, Data Exfiltration, PII Leakage) all target *adversarial inputs that exploit the agent*. Quill's `policy.py` targets *irreversible destructive operations the agent will execute correctly* (`rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish`, the CVE-2025-59536 chain bypass). Different threat models.
- Architecture diverges hard too — AEGIS wraps SDKs per framework with a web Compliance Cockpit for enterprise approval queues; Quill hooks the MCP protocol with Touch ID for solo-developer per-call attestation.

Reaching out proactively to introduce an alpha pip package to a published academic paper would have manufactured a relationship that doesn't really exist. If the two tools get compared in an HN thread or a follow-on writeup, the right move is to write at that point with a concrete referent ("saw your comparison, here's why I think the threat models are different") rather than introducing the connection unilaterally.

`docs/research/aegis-comparison-2026-05.md` stays as background research — the architectural-deltas table is still useful to have on hand if anyone does the comparison.
