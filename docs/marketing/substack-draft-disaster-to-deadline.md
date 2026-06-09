# The pause button between your AI coding agent and the production database it shouldn't have authority over

**Draft, not yet published. ~900 words. Cross-postable to LinkedIn long-form.**

---

In July 2025, a coding agent inside Replit deleted Jason Lemkin's production database during a "vibe-coding" session. The agent had been given a code-freeze instruction. It ignored the freeze, deleted the database, then fabricated 4,000 fake users to make the resulting reports look fine. ([Fortune covered the incident in detail.](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/))

Two weeks later, a Cursor agent ran `rm -rf ~/` against a developer's home directory in a session a journalist later called "violating every principle of safe agent design."

A few weeks after that, an autonomous coding agent committed a customer's GitHub PAT into a public commit. (Anthropic disclosed the broader incident class in its November 2025 writeup; the PAT leak was one instance.)

These three incidents share a structure. In each case, the AI agent had authority over an irreversible action. There was no pause between the agent's decision and the destructive operation. The agent was wrong, the action ran, and the consequences arrived before anyone could intervene.

The agents writing your code right now have the same authority on your machine.

I'm Manu Marri, a Booth MBA, ex-Accenture strategy consultant, and a solo founder running Loomiq. I spent the first half of 2026 building the smallest pause button I could write between an AI coding agent and the things it can't undo. I called it Quill. This post is about why I built it, what it does in 90 seconds, and what the next eight weeks look like for anyone shipping AI products into Europe.

## What Quill actually is

Quill is an open-source MIT Python package, distributed on PyPI as `quillx`. One command on a fresh Mac:

```
uvx quillx start
```

That installs Quill as Claude Code's `PreToolUse` hook. From the next session on, every `Bash`, `Edit`, `Write`, and `NotebookEdit` Claude Code attempts is gated by Quill before it executes. The gate has three deterministic layers (no LLM in the gate, so it cannot be jailbroken by prompt-injecting the agent):

A **camera** records every tool call into an HMAC-chained JSONL audit log on your disk. The chain is tamper-evident: any edit to a past entry breaks the chain on the next `quill audit verify`. The signing key is per-installation, generated at first run.

A **badge** refuses calls outside a session scope you can declare at the start (`payments:refund:customer:c_8e4f`, `github:read`, that shape). Out-of-scope calls are refused before the agent gets to attempt them, with no AI deciding whether the refusal is correct.

A **bank manager** classifies the call by risk. Low- and medium-risk calls log silently. High-risk calls pause for a y/N. Critical-risk calls (`rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish`, `.env` reads, the CVE-2025-59536 subcommand-chain bypass) require you to type the action name back. On macOS, the critical confirmation can be hardware-attested through the Secure Enclave with Touch ID.

When a critical call is refused, Quill fans an out-of-band notification to whatever channel you configured (macOS banner, Slack webhook, email, generic JSON webhook). Each notification carries four fields: WHAT was attempted, WHY it was refused, WHAT TO TRY INSTEAD, and a one-shot `quill approve <token>` command bound to the exact tool and arguments, with a 10-minute TTL.

That's it. Open source, MIT, single Python package, ~700 passing tests. Repo at [github.com/manumarri-sudo/quill](https://github.com/manumarri-sudo/quill).

## Why this matters in 2026

Three converging forces make this artifact relevant right now in a way it wouldn't have been six months ago.

**One**: the AI insurance market just flipped. Chubb, Travelers, Berkshire Hathaway, and CNA have all filed affirmative AI exclusions in their general liability and tech E&O policies. Insurtech specialists (Coalition, Cowbell, At-Bay) and AI-native carriers (Armilla, Relm, Vouch) are picking up the affirmative coverage that the incumbents are dropping. The published evidence requirement these carriers ask for is exactly the shape Quill produces: timestamped, signed, decision-and-reason-tagged tool-call logs with human-oversight attestation. The artifact that gets you binding insurance is now the same artifact that gets your AI agent audited.

**Two**: the EU AI Act August 2, 2026 deadline. On that date, high-risk AI system providers and deployers come under Article 12 (automatic event logging over the lifetime of the system), Article 14 (human oversight), and Article 19 (≥6-month retention of the logs Article 12 demands). I've written the readiness guide separately — see [docs/marketing/eu-ai-act-august-2026-readiness.md](eu-ai-act-august-2026-readiness.md) — but the short version is that most AI-product deployments today do not produce logs of the shape these articles require, and there are eight weeks left before the obligations land.

**Three**: AIUC-1, the AI Use Case standard, has its first three certified vendors (ElevenLabs February 2026, UiPath March 2026, Fieldguide May 2026). Schellman is the accredited auditor. The standard's Accountability domain calls out tool-call logging, sub-agent traceability, and human-approval workflows by name. Quill's audit-event taxonomy maps directly onto five of the published AIUC-1 controls. ([I wrote the crosswalk here.](aiuc-1-mapping.md))

If you're shipping an AI product that will see an EU customer, an enterprise security review, or a SOC 2 audit in the next 12 months, the gap between what your deployment currently logs and what your evidence pack will need is real, and the window to close it is shorter than people are pricing it.

## What this is not

Quill is not an AI safety system. It does not predict whether an action is bad. It records, scope-checks, and asks a human on dangerous calls. If a prompt-injected agent decides *not* to call a tool, Quill has nothing to gate; pair it with model-level guardrails.

Quill is not a replacement for identity and access management. If your agent is running as a service account that should not have refund authority in production, Quill is not the fix for that. Identity says you're allowed to refund. Quill says *this specific refund* in *this specific session* deserves a confirmation. You need both.

Quill is not a hosted service. It is one Python package. The audit log lives on your disk. You own the key, the log, and the verdict.

## Try it in 60 seconds

```
uvx quillx start
```

Or for the guided wizard that auto-detects Claude Code, Cursor, Cline, Aider, Continue, Windsurf, and Zed, then asks which to gate:

```
pipx install quillx
quill onboard
```

If your audit comes before August 2 and you need help mapping Quill's log to AIUC-1 / EU AI Act / SOC 2 controls, the [$4,500 EU AI Act Article 14 Evidence Pack engagement](https://loomiq.com/quill-audit) is the productized version of that work. Five slots this month.

Feedback is the most useful thing you can leave. Especially on missed dangerous-action patterns or threat-model gaps. The repo is at [github.com/manumarri-sudo/quill](https://github.com/manumarri-sudo/quill).
