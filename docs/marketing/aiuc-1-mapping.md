# Quill ↔ AIUC-1 control mapping

**For:** AIUC-1 auditors (Schellman et al.), AI insurance underwriters (Armilla, Relm, Vouch), and AIUC-1 cert candidates.
**Updated:** 2026-06-09
**Quill version:** v0.3-prep (preceding 0.3.0)
**Status:** Quill ships the audit-event taxonomy described below today. Verifiable against the source: every event type in this doc resolves to a constant in [`src/quill/events.py`](../../src/quill/events.py), and every audit log entry is HMAC-SHA256-chained per [`src/quill/audit.py`](../../src/quill/audit.py).

---

## The one-sentence pitch

Quill is an open-source MIT pause button between an AI coding agent and the things it could break. The audit log it produces (HMAC-chained JSONL, mode 0o600, ≥6-month-retainable on the operator's own disk) is the artifact AIUC-1 auditors and AI-liability underwriters need to evidence specific control claims that today require manual screenshot-and-narrative work.

---

## What's mapped

This document covers the **Accountability**, **Reliability**, and **Security** domains of AIUC-1 where Quill produces direct evidence. Where the underlying control is satisfied entirely by Quill, it's marked **✓ direct**. Where Quill is one of several evidence sources, it's marked **▲ partial**. The full crosswalk lives in [`src/quill/controls.toml`](../../src/quill/controls.toml) and drives the `quill audit export --pack` deliverable.

### Accountability domain (5 controls)

| AIUC-1 Code | Title | Quill evidence | Coverage |
|---|---|---|---|
| **E015** | Log AI system activity | `tool.attempted`, `verdict.allowed`, `verdict.blocked`, `verdict.ask` events with timestamp, session_id, agent_id, tool_name, args_digest, decision, reason. HMAC-chained per entry. | ✓ direct |
| **E015.2** | AI agent logging implementation (intermediate steps, tool calls, sub-agent actions, metadata across execution chains) | Every tool call from agent → MCP → upstream is logged; sub-agent spawns produce `agent.handoff.out` and `agent.handoff.in` events with a `payload_hash` that chains parent to child. | ✓ direct (Cursor 1.7+); ▲ partial (Claude Code; subagent capture pending Anthropic hook-API support) |
| **D003.1** | Tool authorization and validation | Deterministic regex classifier in [`policy.py`](../../src/quill/policy.py); per-tool overrides in `[policy]` config; out-of-scope calls produce `verdict.scope_violation`. | ✓ direct |
| **D003.3** | Tool call log including MCP server calls | MCP-proxy form factor at `quill serve`; every MCP call routed through Quill is logged via the same chained format as built-in tool calls. | ✓ direct |
| **D003.4** | Human-approval workflows for chained operations | Critical-risk calls trigger type-to-confirm + (on macOS) Touch ID via Secure Enclave; approval events are `approve.biometric.ok` / `approve.biometric.deny`, plus paste-able one-shot `quill approve <token>` flow with 10-minute TTL and single-use semantics. | ✓ direct |
| **C007.3** | Human review workflow auditing (anti-automation-bias) | Anti-yes-fatigue (3-in-4-seconds rule), type-to-confirm, and Touch ID are defenses against rubber-stamping; each interaction is itself audit-logged. | ✓ direct |

### Reliability domain (2 controls)

| AIUC-1 Code | Title | Quill evidence | Coverage |
|---|---|---|---|
| **AIUC-REL-01** | Every tool call audited (no call executes without a log entry) | The HMAC chain is unbroken by construction: `tool.attempted` is emitted before the gate runs, and `verdict.{allowed,blocked,ask}` is emitted before the call is dispatched to the upstream. Concurrent hook subprocesses serialize via `fcntl.flock(LOCK_EX)`. | ✓ direct |
| (paired) | Restrict unsafe tool calls (AIUC-1 Reliability scope language) | Default-critical patterns block `rm -rf`, `git push --force`, `DROP TABLE`, `TRUNCATE`, `vercel --prod`, `npm publish`, `cat .env`, `stripe.refunds.*`, `banking.send_money`, the CVE-2025-59536 subcommand-chain bypass, plus 18 secret-pattern detections on file-write content. | ✓ direct |

### Security domain (3 controls)

| AIUC-1 Code | Title | Quill evidence | Coverage |
|---|---|---|---|
| **AIUC-SEC-01** | Tool poisoning + rug-pull detection | SHA-256 fingerprint of `(tool name, description, inputSchema, annotations)` recorded on first sight; silent changes emit `tool.pin_refused` and refuse the call. Mitigates the Invariant Labs March 2025 tool-poisoning advisory class. | ✓ direct |
| **AIUC-SEC-02** | Lethal-trifecta exposure detection and enforcement | Three-flag taint tracking per session (untrusted input, private data, exfiltration vector); when a call would close the trifecta for the first time, the gate escalates an otherwise-allow verdict to a deny. Implements Simon Willison's "Lethal Trifecta" and Meta's "Agents Rule of Two" (Oct 2025). | ✓ direct |
| **AIUC-1 Society SOC-01** | Operator self-flagged uncertainty surfaced | `agent.flag.uncertain` events persisted to the session receipt for human review at session-end. | ✓ direct |

---

## What a sampled audit event looks like

Pulled directly from the on-disk audit log (`~/.quill/audit.log.jsonl`):

```json
{"ts":"2026-06-09T01:14:22Z","session_id":"ses_a4f1","agent_id":"root","type":"tool.attempted","risk":"critical","prev_mac":"…","payload":{"tool_name":"Bash","arg_keys":["command"],"arg_count":1},"mac":"…"}
{"ts":"2026-06-09T01:14:22Z","session_id":"ses_a4f1","agent_id":"root","type":"verdict.blocked","risk":"critical","prev_mac":"…","payload":{"tool_name":"Bash","reason":"force-push rewrites shared history; protected branch","try_instead":"git push --force-with-lease"},"mac":"…"}
{"ts":"2026-06-09T01:14:51Z","session_id":"ses_a4f1","agent_id":"root","type":"approve.biometric.ok","risk":"critical","prev_mac":"…","payload":{"tool_name":"Bash","approve_token":"T7gQ2x9aB4"},"mac":"…"}
```

Three events: the attempt, the deny verdict with reason + safer-alternative, and the operator's biometric approval. Each `mac` is HMAC-SHA256 over (`prev_mac` || canonical(payload)). The chain integrity check (`quill audit verify`) walks all entries and reports the first break.

---

## Mapping to underwriter expectations

The published carrier-grade specification for AI audit trails (Swept.ai's eight-field minimum, [referenced here](https://www.swept.ai/post/compliance-ai-audit-trail-specification-insurance)) names: timestamp (millisecond, timezone-aware), model + version, hash of inputs, output with confidence, normalized confidence indicator, reviewer identity + timestamp, override boolean + structured reason code, downstream consequence.

Quill's per-event payload covers seven of those eight by construction (the model + version field is added by the agent runtime at session_open and propagated; output-with-confidence is not Quill's layer). Underwriters who currently accept the Swept.ai-shape specification can ingest Quill's log without translation.

---

## What this is not

- **Not AIUC-1 certification.** AIUC-1 is granted by an accredited auditor (Schellman is currently the only one) on the full management system, not on the artifact alone. Quill is one evidence source. The operator still owns the rest of the controls (model evals, red-team results, data lineage, etc.).
- **Not an attestation.** This document is a crosswalk, not a SOC 2 or AIUC-1 attestation letter. An auditor would sample Quill's log alongside other evidence to opine on the system as a whole.
- **Not a substitute for an auditor.** Quill is the artifact the auditor will accept; the auditor still has to sample, opine, and sign.

---

## The calibrated three-tier insurance pitch

Three claims about what Quill does for an AI-liability submission, ranked from "load-bearing, lead with this" to "weakest, do not lead with this." Read top-to-bottom.

**Tier 1 (strongest, lead with this): Quill speeds binding.** Underwriters bind faster when evidence packages arrive pre-formatted to their spec. Quill's log plus a five-minute `quill audit export --pack` against AIUC-1 controls is a 90%-reduction in submission-cycle friction. This is the load-bearing claim and is defensible without overclaiming on any single outcome.

**Tier 2 (credible, secondary): Quill anchors a documented retention reduction.** The published template is **Cowbell Prime One MDR Endorsement** (US, April 2026): $25,000 retention reduction for subscribing to Cowbell's Managed Detection and Response service. The "subscribe to a specific control, get a documented retention concession" mechanism is in market. The Quill-shaped equivalent would be a named per-deployment retention concession tied to deploying Quill-style tamper-evident agent logging. This requires one carrier to anchor a published number; that's the next milestone.

**Tier 3 (weakest, do NOT lead with this): Quill unlocks new coverage.** The carriers writing affirmative AI coverage (Coalition, Cowbell, Armilla, Relm, Vouch, Klaimee) will write it with or without Quill; the carriers excluding AI (Chubb, Travelers, Berkshire Hathaway, CNA per their 2026 state filings) will not write it for any artifact. The only honest version of this claim is *"Quill is what makes a contested claim defensible after the fact,"* which is a coverage-survival argument, not a binding-availability argument.

> **The honest one-line positioning:** *"Quill is the evidence package the underwriter wants on Monday morning. It doesn't unlock new coverage, but it shortens binding from weeks to days and gives you a documented control to anchor a retention concession."*

## How to use this document

**If you're an AIUC-1 auditor:** the audit-log format is stable, the HMAC chain is verifiable in 60 seconds via `quill audit verify`, and `quill audit export --pack` produces the full evidence pack as a PDF (covering EU AI Act Art 12 + 14 + 19, AIUC-1, NIST AI RMF + GenAI Profile, ISO/IEC 42001 A.6.2.8, SOC 2 Common Criteria, and MITRE ATLAS) in one command. Open-source, MIT, no vendor lock-in.

**If you're an AI insurance underwriter:** the controls in the Accountability and Security tables above are exactly the evidence shape your underwriting workflow expects. Quill ships the log; you sample the log; binding decisions accelerate. The Cowbell Prime One MDR Endorsement (US, April 2026, $25K retention reduction) is the structural precedent for the Quill-shaped equivalent we'd love to discuss.

**If you're an AIUC-1 cert candidate:** deploy Quill against your AI agent stack, run it for ≥30 days to build a representative log, then `quill audit export --pack` produces the evidence PDF you hand your auditor. Pair with the rest of your AIUC-1 controls. The 30-day window aligns with AIUC-1's quarterly retest cadence.

---

## Contact

- Repo: [github.com/manumarri-sudo/quill](https://github.com/manumarri-sudo/quill)
- Maintainer: Manu Marri (Loomiq LLC) — manu.marri@gmail.com
- License: MIT
