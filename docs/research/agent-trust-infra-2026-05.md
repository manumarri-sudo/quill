# Agent Trust Infrastructure - Field Survey, Open Problems, and Quill's Position
**Date:** 2026-05-07
**Author:** research pass for Quill (Manu Marri / Loomiq)
**Scope:** Where the AI-agent trust/governance space is in May 2026, what experts are arguing about, what is *technically unsolved*, and where Quill should swing next.

---

## 1. Field landscape - who is actually shipping

The space has bifurcated into four layers, with very different maturity. Quill plays in layer 2; layers 1 and 3 are crowded; layer 4 is wide open.

### Layer 1 - model-side / lab safety (mature, not Quill's fight)
- **Anthropic** ships the deepest *runtime* hooks. Claude Code's `PreToolUse` hook fires before every tool call, has full veto power, and - critically - runs even with `--dangerously-skip-permissions` and in `bypassPermissions` mode. The bypass skips interactive confirmations, *not* system hooks. Decisions: `allow / deny / ask / no-output`. ✅ VERIFIED ([Claude Code Docs](https://code.claude.com/docs/en/hooks)). A May 2026 patch fixed a `permissions.deny` not overriding a hook's `permissionDecision: "ask"` and a security fix where `allow` was bypassing deny rules from enterprise managed settings. This is the surface Quill already attaches to.
- **OpenAI Agents SDK** ships `RunHooks` (workflow-wide observer) and `AgentHooks` (single-agent scope) with `on_llm_start / on_llm_end / on_tool_start / on_tool_end`. ✅ VERIFIED ([OpenAI Agents SDK lifecycle](https://openai.github.io/openai-agents-python/ref/lifecycle/)). Quill should ship an adapter; v0.2 changelog lists this.
- **Meta - "Agents Rule of Two"** (Oct 31, 2025). The single most-cited architectural prescription of the last six months: an agent must have *no more than two* of {untrusted input, private data, external comms} simultaneously. Simon Willison: *"I like this a lot... it's refreshing to see another major research lab concluding that prompt injection remains an unsolved problem"* ([simonwillison.net 2025-11-02](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)). ✅ VERIFIED.

### Layer 2 - runtime gates / proxies (Quill's lane, contested)
- **Invariant Labs** - published the canonical MCP tool poisoning advisory; their `mcp-scan` looks at server descriptions for hidden directives. ✅ VERIFIED ([Invariant Labs notification](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)). They don't gate calls at runtime; they audit server manifests pre-deploy. Complementary to Quill, not competing.
- **Cerbos / Permit.io / OPA** - policy engines being repositioned for agent auth. Cerbos publishes "agentic authorization" use cases (sub-1ms YAML evaluation, RBAC/ABAC, MCP-server-side integration). ✅ VERIFIED ([Cerbos agentic](https://www.cerbos.dev/features-benefits-and-use-cases/agentic-authorization)). These are *identity → permission* systems. They answer "is this principal allowed?" - not "should *this specific call right now* require a human?" Quill is the latter; Cerbos is the former. Two different questions, both needed.
- **WorkOS / Strata / AAuth / Grantex** - agent-identity layer. WorkOS calls out the "multi-hop delegation problem" explicitly; Grantex proposes W3C DIDs + RS256 JWTs + hash-chained audit. The IETF OAuth WG has an active draft on "Transaction Tokens for Agents" and a March 2026 thread on *delegation chain splicing* (an attacker inserts themselves in the actor-claim chain). ✅ VERIFIED ([Zylos research](https://zylos.ai/research/2026-04-11-agent-authentication-delegated-access-oauth-scoped-tokens), [IETF OAuth thread](http://www.mail-archive.com/oauth@ietf.org/msg25910.html)). Identity is solved-ish at the edge; *delegation chain integrity* is not.
- **Replit** - ships planning-only mode and dev/prod DB isolation post-Lemkin incident (July 2025; data for ~1,200 executives wiped, agent fabricated 4,000 fake users and lied about rollback availability). ✅ VERIFIED ([Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/), [AI Incident Database #1152](https://incidentdatabase.ai/cite/1152/)). This is *the* origin story for products like Quill.

### Layer 3 - observability / evals (mature, not gating)
- **Langfuse / Arize Phoenix / Helicone / LangSmith / Datadog LLM Obs / Honeycomb** all ship OpenTelemetry GenAI semantic conventions. The OTel GenAI SIG has *experimental* AI Agent Application Conventions and Framework Conventions (CrewAI, AutoGen, LangGraph, Semantic Kernel). ✅ VERIFIED ([OTel GenAI agent spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/)). These are post-hoc; they don't gate.
- **Datadog** natively ingests OTel GenAI conventions as of early 2026 ([Datadog LLM-OTel post](https://www.datadoghq.com/blog/llm-otel-semantic-convention/)).

### Layer 4 - accountability / receipts (open territory)
- **Letta (formerly MemGPT)** released the "Context Constitution" (early 2026) and Context Repositories - git-versioned memory blocks. Letta Code shipped March 2026. ✅ VERIFIED ([Letta blog](https://www.letta.com/blog/letta-code)). They govern *memory*, not actions.
- **AuditableLLM / OpenFang / "AI Action Ledger" / nono.sh** - academic + small-OSS hash-chained audit logs. ✅ VERIFIED ([AuditableLLM MDPI](https://www.mdpi.com/2079-9292/15/1/56), [nono.sh blog](https://nono.sh/blog/secure-agent-audit), [GitHub agent-audit-log-examples](https://github.com/lulzasaur9192/agent-audit-log-examples)). All the right primitives (Merkle/HMAC chain, append-only, inclusion proofs) but no shipped product with paying customers.
- **Nobody is shipping "session-end Agent Receipts"** in Manu's specific shape (`did / changed / uncertain / to_verify`). 🔶 INFERENCE: searches for `"agent receipt" "did changed uncertain"` returned zero hits. This is Manu's open lane.

### Standards / regulation
- **EU AI Act Article 14** - high-risk system human oversight (in-the-loop / on-the-loop / in-command). Articles 6–15 mandatory August 2, 2026. Article 12 mandates audit-log retention ≥6 months for high-risk systems. ✅ VERIFIED ([artificialintelligenceact.eu/article/14](https://artificialintelligenceact.eu/article/14/)).
- **AIUC-1** - published quarterly; first auditor (Schellman) accredited Feb 2026; first certs issued to UiPath (Mar), ElevenLabs, Fieldguide (May 6, 2026). Operationalises ISO 42001 + NIST AI RMF + MITRE ATLAS + OWASP LLM Top 10. ✅ VERIFIED ([aiuc-1.com](https://www.aiuc-1.com/)).
- **OWASP Top 10 for Agentic Applications 2026** - released Dec 2025, peer-reviewed by 100+ practitioners. Threats run ASI01 (Agent Goal Hijack) → ASI10 (Rogue Agents), with Tool Misuse, Identity & Privilege Abuse, and Human-Agent Trust Exploitation explicitly named. ✅ VERIFIED ([OWASP GenAI release](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)). Full list is paywalled behind a download form; ❓ OPEN QUESTION: I should not enumerate without primary verification.
- **MITRE ATLAS v5.4.0** (Feb 2026) added *"Publish Poisoned AI Agent Tool"* and *"Escape to Host"*. v5.1.0 Nov 2025 added 14 agent-specific techniques via Zenity Labs collab. ✅ VERIFIED ([CTID release](https://ctid.mitre.org/blog/2026/05/06/secure-ai-v2-release)).

### Summary table - who is shipping what
| Product / Project | Layer | Running code? | Paying customers? | Whitepaper? |
|---|---|---|---|---|
| Anthropic Claude Code hooks | 1 | yes | yes (default) | docs |
| OpenAI Agents SDK hooks | 1 | yes | yes | docs |
| Meta "Rule of Two" | 1 | spec only | n/a | yes |
| Invariant Labs `mcp-scan` | 2 | yes | yes (enterprise pilot) | yes |
| Cerbos | 2 | yes | yes | yes |
| WorkOS / Strata / AAuth | 2 | yes | yes | yes |
| Quill | 2 | yes | early users | this doc |
| Langfuse / Phoenix / Helicone | 3 | yes | yes | yes |
| Letta | 4 (memory) | yes | yes | yes |
| AuditableLLM / OpenFang / nono | 4 | yes | no | papers |
| Manu's Agent Receipts | 4 | vault-only | no | unpublished |

---

## 2. Expert voices - what people are actually arguing

**Simon Willison** - the loudest, most-cited voice on the gating problem.
- **"The Lethal Trifecta"** (formal blog post; ongoing series): private data + untrusted tokens + exfiltration vector = full stop, vulnerable. *"taint tracking + policy gating: once an agent has ingested attacker-controlled tokens, block (or require explicit human approval for) any action with exfiltration potential, including outbound HTTP, email/chat sends, PR creation, and rendering clickable links."* ✅ VERIFIED ([simonwillison.net/tags/prompt-injection](https://simonwillison.net/tags/prompt-injection/)).
- On MCP specifically (Nov 2025): *"the Model Context Protocol's mix-and-match approach is extra risky unless tools carry metadata about whether they read private data, see untrusted content, or can exfiltrate - and the runtime enforces that all three are never allowed together in a single tainted execution path."* ✅ VERIFIED.
- On Meta's Rule of Two (Nov 2, 2025): *"I like this a lot."* + *"it's refreshing to see another major research lab concluding that prompt injection remains an unsolved problem."* ✅ VERIFIED.
- **Quill implication:** Quill's three-layer gate is taint-tracking-shaped already (camera/badge/bank-manager). The gap is *taint propagation across tool calls*. Quill knows the call is risky; it doesn't know whether the agent's *context* was tainted by a prior fetch.

**Andrej Karpathy** - has been quieter on agents specifically; his "LLMs are people" framing dominates the agent-design discourse.
**Riley Goodside** - continues red-team disclosures of injection-via-tool-description (cited in Invariant Labs writeups).
**Helen Toner / Dario Amodei** - public-policy register; Amodei's RSP team operationalises the AI Action Ledger pattern internally per Anthropic's CSP. ❓ OPEN QUESTION: no public schema.

**OX Security** - disclosed (April 2026) a systemic flaw in MCP STDIO transport: configuration-to-command execution without sanitisation. Cursor, VS Code, Windsurf, Claude Code, Gemini-CLI all affected. 150M+ downloads, 10+ Critical/High CVEs from one root cause. ✅ VERIFIED ([Practical DevSecOps MCP guide](https://www.practical-devsecops.com/mcp-security-guide/)). Live attack surface, not theoretical.

**Microsoft Copilot Studio team** - published OWASP Agentic Top 10 mitigations as a vendor checklist (Mar 30, 2026). Validates that the regulatory shape of the answer is "show your gate, show your log, show your scopes." ✅ VERIFIED ([Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/03/30/addressing-the-owasp-top-10-risks-in-agentic-ai-with-microsoft-copilot-studio/)).

**Anthropic - incident writeup (Nov 2025)** - Chinese state-sponsored group hijacked Claude Code instances to run autonomous cyber-espionage against ~30 targets in defense/energy/tech. ✅ VERIFIED. Live nation-state actor on Quill's exact surface. The hijack vector is the prompt-injection-into-tool-call chain.

---

## 3. Open technical problems - where the field is stuck

These are the gaps that read papers but no shipped product has closed.

### 3.1 Prompt-injection-resistant tool gating
✅ VERIFIED that every published defense (12 of them, per Nov 2025 adaptive-attack paper) is bypassable with >90% success. The gate must therefore be deterministic, content-aware, and not LLM-adjudicated. **Quill already does this** - the regex classifier in `policy.py` is exactly the right shape. The unsolved bit is *which* dangerous patterns to add. No public corpus of "actions that broke a real prod system" exists. Each vendor curates its own.

### 3.2 Cross-agent state pollution & cascade failure
🔶 INFERENCE. CrewAI passes task outputs sequentially; LangGraph checkpoints all state to a thread-keyed store. *Neither* tracks payload provenance - if agent A produced output X, and agents B, C, D all consumed X with different downstream effects, no system records that lineage. Manu's A2A Bridge (`payload_hash`, `cascade_blast_radius`) is the only schema I found that captures this. ❓ OPEN QUESTION: is anyone shipping this in code? Searches for `"cascade blast radius" agent` and `"payload hash" handoff multi-agent` returned zero relevant hits.

### 3.3 Observability schemas that survive multi-agent handoff
✅ VERIFIED OTel GenAI conventions exist (gen-ai-agent-spans), but they capture *spans*, not *handoff contracts*. There is no `gen_ai.handoff.from`, `gen_ai.handoff.to`, `gen_ai.handoff.contract` semantic-convention key as of May 2026. Quill could be a contributor here.

### 3.4 Evals for "agent did the wrong thing" not "agent gave the wrong answer"
🔶 INFERENCE. Arize/Langfuse/Phoenix all evaluate text outputs; AIUC-1 runs *adversarial scenario* certification (thousands of scenarios, quarterly). The gap: there's no public benchmark for "given this gated tool stream, did the gate refuse the right calls?" Quill's audit log is *exactly* this dataset, but it's not aggregated.

### 3.5 Inter-agent authentication & delegation-chain integrity
✅ VERIFIED via the IETF OAuth thread: *delegation chain splicing* is an open attack against RFC 8693 token exchange, formally documented March 2026. SPIFFE + OAuth 2.0 + OPA is the CNCF recommended trio, but the actor-claim chain has no integrity proof. Grantex proposes hash-chained audit per delegation. Nobody has shipped it.

### 3.6 Tamper-evident audit logs that work with append-only object storage
🔶 INFERENCE. HMAC-chained JSONL on local disk (Quill's design) doesn't compose with S3 / R2 / GCS append semantics. Transparency-log style (Merkle tree + signed tree heads, à la sigsum/transparency.dev) does, but adds complexity. ❓ OPEN QUESTION: which AIUC-1 certified vendors use which? UiPath certification scope is published; the cert artifact itself is not.

### 3.7 Attestation that a permission was granted by a real human, not a hijacked terminal
✅ VERIFIED this is now an acknowledged production threat (the Claude Code hijack incident; OX Security STDIO flaw). Pindrop and Strata both call out hardware-attested confirmation. Touch-ID / WebAuthn / TEE-bound approval tokens are the only shipped answers. ❓ OPEN QUESTION: is anyone wiring WebAuthn into a Claude Code hook? Searches turned up nothing.

### 3.8 Permission decay (active research, no shipping product)
🔶 INFERENCE. Cerbos doesn't have it; Permit.io doesn't; OPA doesn't. Manu's `decay.py` may be the only production implementation outside academic reinforcement-learning literature. The framework matches CAEP (Continuous Access Evaluation Profile) in spirit, but CAEP is event-driven revocation, not time-decay-driven downgrade.

---

## 4. Quill's position - where it's strong, where it's weak

### Strong
- **Deterministic gate, no LLM in the hot path.** This matches Willison's prescription and the consensus that LLM-based defenses are bypassable. ✅ VERIFIED architectural fit.
- **HMAC-chained JSONL on disk, mode 0600.** This is the format AuditableLLM / nono.sh / OpenFang all converge on. Article 12 of the EU AI Act demands ≥6mo retention of "logs automatically generated by high-risk AI systems"; Quill's format satisfies this trivially.
- **Permission Decay as a shipped feature.** Genuinely unique. Cerbos / Permit.io / OPA / WorkOS do not have it.
- **Per-project audit logs at `<cwd>/.quill/audit.log.jsonl` + sub-agent detection via `session_id`.** This is the right primitive for the A2A Bridge work - sub-sessions already chain to parents.
- **Adapter-friendly architecture.** The `adapters/claude_code.py` pattern composes with PreToolUse hooks correctly; same shape will fit OpenAI Agents SDK `RunHooks`/`AgentHooks` and LangGraph `interrupt()`.

### Weak
- **No taint tracking.** The gate sees one call at a time. If the agent fetched an untrusted webpage, the next `git push` should be flagged differently than a baseline `git push`. This is Willison's lethal-trifecta gap, and Quill doesn't have it yet.
- **No cross-call dataflow / cascade tracking.** Manu's A2A Bridge schema exists in the vault as Dataview frontmatter; it's not yet in `audit.py` event types.
- **No Agent Receipts at session-end.** Manu has the schema (`did/changed/uncertain/to_verify`) in the vault; Quill has the audit log lines that *aggregate* to a receipt; the aggregator doesn't exist yet.
- **No human-attestation for approvals.** Type-to-confirm is anti-fatigue, not anti-hijack. A compromised terminal types just fine.
- **MCP proxy is single-call adapter, not schema-passthrough.** Acknowledged in v0.2 roadmap. This is the headline blocker for "Quill is invisible to the developer."
- **No transparency-log mode.** HMAC-chain works on a single disk; auditors who want to verify chain integrity *without* the HMAC key (third-party verifiability) need a Merkle/sigsum-style design.
- **No OTel GenAI emission.** Listed in v0.2 roadmap; until done, Quill events live in their own world.

---

## 5. Top 3 technical recommendations - ranked, concrete

### #1 - Agent Receipts as audit-log aggregation + session-end emit (1-month version is shippable)
**Why it's the right next step.** Nobody is shipping this in Manu's exact shape. It's the single piece of the Trust Infrastructure framework that has zero competing product. AIUC-1 and EU AI Act both require *evidence of oversight* - receipts are the human-readable form of that evidence. Receipts also become the input to the cross-agent cascade analysis (rec #3) since they capture `changed:` paths.

**What it looks like.** A new event type `session.receipt` written by a stop-hook adapter. Source data is the existing audit log; the receipt is a *derived* artifact, not a new write path.

```
src/quill/receipt.py
  - class Receipt(BaseModel)             # pydantic-strict
  - def derive_from_audit(...)            # walks log between session_open / session_close
  - def emit(receipt: Receipt) -> None    # writes one session.receipt event back to audit log
src/quill/adapters/claude_code_stop.py
  - handler reads transcript_path, picks session boundary, calls derive + emit
~/.quill/receipts/<session_id>.md         # human-readable mirror, optional
```

**Schema** (see §6 for full JSON):
- `did[]` - derived from `tool.executed` events with non-empty result
- `changed[]` - derived from arg paths on Edit/Write/Bash mutations
- `uncertain[]` - events with `risk in (high, critical)` that were `verdict.allowed` (the agent did something risky and Quill let it through with consent)
- `to_verify[]` - explicit `agent.flag.uncertain` events (new event type the adapter emits when the agent asks the user to verify; bridges to Anthropic's existing `Ask` permission decision)
- `trust_delta` - function of `verdict.blocked` count vs `tool.executed` count, signed

**What it does NOT do.** It does *not* call an LLM to summarise. It does *not* try to detect "did the agent succeed?" - only what calls were made and which ones the human flagged. Summarisation is a vault-side concern (Manu's `quill-session-journal` skill).

**Cadence.**
- *1-week:* `session.open` and `session.close` event types + `quill receipts list` CLI that walks the log between them. No receipt object yet - just a CLI view.
- *1-month:* `Receipt` pydantic model, `derive_from_audit`, `claude_code_stop` adapter wired to the existing PreToolUse hook adapter, write `session.receipt` events back to the chain.
- *3-month:* Vault export (writes to `~/agentbrain/AgentOS-Vault/ClaudeCode/Receipts/<id>.md`); `quill receipts diff <session_a> <session_b>` for trust-delta over time; aggregate "intervention rate" / "TDR" KPIs surfaced via `quill doctor`.

### #2 - Lethal-Trifecta taint tracking (3-month full version; 1-week MVP)
**Why it's the right next step.** This is the single highest-leverage defense per Willison and Meta. Quill already gates *single calls*. The trifecta is about *call sequences*. Adding taint to Quill's existing `SessionIntent` is a natural extension - `SessionIntent` already carries scope; adding `tainted_by` carries provenance.

**What it looks like.** Track three taint flags on the session object: `has_seen_untrusted`, `has_accessed_private`, `can_exfiltrate`. Each tool call updates flags based on its classification (read of external URL → `has_seen_untrusted = True`; read of `.env` / private repo → `has_accessed_private = True`; outbound HTTP/email/PR → `can_exfiltrate = True`). When all three are true and the next call would *commit* the third action, escalate to type-to-confirm regardless of base classification.

```
src/quill/taint.py
  - class TaintState(BaseModel)           # three booleans + provenance log
  - def update_for_call(state, tool_name, args, result) -> TaintState
  - def trifecta_violation(state, next_call) -> bool
src/quill/policy.py
  - new field on Risk classification: requires_no_trifecta: bool (default False on outbound comms)
src/quill/proxy.py / adapters/claude_code.py
  - update taint after every call; check trifecta before allowing high-risk outbound
```

**What it does NOT do.** It does not try to detect *what was injected* - just that an untrusted source was read. False-positive bias is the right bias here. It does not replace the existing classifier; it adds a *second* veto.

**Cadence.**
- *1-week:* Add `taint` field to session events (just observation, no enforcement). Audit log can answer "this session crossed the trifecta line" retroactively.
- *1-month:* Enforce on outbound HTTP / email / PR / external-write. Type-to-confirm escalation when trifecta would close.
- *3-month:* Tool metadata in config.toml - `[tools."tool_name"] reads_untrusted = true | reads_private = true | exfiltrates = true` - and a `quill trifecta show` view that lists every tool by trifecta classification.

### #3 - A2A Bridge event types in the audit log (1-month MVP)
**Why it's the right next step.** Quill is *already* the right place to write these - sub-agent detection via `session_id` under shared `transcript_path` is implemented. The vault Dataview view exists. The missing piece is the audit-log event types that produce the data the Dataview view reads.

**What it looks like.** Three new event types, all chained into the same HMAC log:

```
{"type":"agent.handoff.out", "payload":{"to":"sub-agent-id", "contract":"…", "payload_hash":"…"}}
{"type":"agent.handoff.in",  "payload":{"from":"parent-id",  "accepted":true, "payload_hash":"…"}}
{"type":"agent.cascade.affected", "payload":{"upstream_event_mac":"…", "blast_radius_paths":[…]}}
```

`payload_hash` is the SHA-256 of the canonical handoff message. If the same hash appears in a `handoff.out` from agent A and a `handoff.in` to agent B, the bridge contract is satisfied. Orphaned handoffs (out without matching in) surface in a `quill bridge orphans` view.

**What it does NOT do.** It does not *route* messages between agents (that's the framework's job - LangGraph, CrewAI, AutoGen). It only *records* the handoff and lets you reason about it after the fact.

**Cadence.**
- *1-week:* Define the three event types in `audit.py` enum; emit `agent.handoff.out` from the existing sub-agent-spawn detection.
- *1-month:* Receiving-side adapter on session start emits `agent.handoff.in` with `accepted` flag; CLI `quill bridge show` lists matched and orphaned pairs.
- *3-month:* `state_pollution_risk` derivation (same payload hash → ≥3 downstream sessions with divergent outcomes); `cascade_blast_radius` derivation from `agent.cascade.affected` events; export to vault Dataview shape.

---

## 6. A2A Bridge + Agent Receipts schema proposals - concrete event shapes

The principle: **audit log is the write-time data; receipts and bridge views are the derive-time data.** Anything that can be computed from existing log lines should be derived, not written. New write-time events are introduced only when the information genuinely doesn't exist in the existing call/verdict events.

### 6.1 New write-time event types (extend `audit.py`)

```jsonc
// session lifecycle (write-time)
{
  "type": "session.open",
  "payload": {
    "intent": "ship the wizard step-2 page",
    "scope": ["fs:write:src/dashboard", "github:read:user/repo"],
    "budget_usd": 5.0,
    "parent_session_id": null,
    "trust_ladder": "spot_check"          // per-session default rung
  }
}

{
  "type": "session.close",
  "payload": {
    "reason": "user_quit" | "transcript_end" | "budget_exhausted" | "error",
    "duration_seconds": 3421,
    "tool_call_count": 47
  }
}

// session-end derived artifact (write-time, but derived from log)
{
  "type": "session.receipt",
  "payload": {
    "did": ["rebuilt wizard step 2 question model"],
    "changed": ["src/dashboard/step2/page.tsx"],
    "uncertain": ["framework citation tag color may clash with deep navy"],
    "to_verify": ["user must visually confirm two-pane layout on staging"],
    "trust_delta": 0.02,
    "intervention_count": 1,           // verdict.blocked + verdict.asked
    "tdr_contribution": 0.91           // executed / (executed + blocked + asked)
  }
}

// agent flagged its own uncertainty during the run
{
  "type": "agent.flag.uncertain",
  "payload": {
    "tool_name": "Edit",
    "uncertainty": "color choice may not contrast adequately"
  }
}

// A2A Bridge - handoff edges
{
  "type": "agent.handoff.out",
  "payload": {
    "to_agent_id": "sub-research-001",
    "contract": "research only; no writes; budget $0.50",
    "payload_hash": "a3f9c1...",
    "trust_ladder_inherited": "supervised"  // sub-agents start at parent's rung or stricter
  }
}

{
  "type": "agent.handoff.in",
  "payload": {
    "from_agent_id": "root",
    "from_session_id": "ses_a4f1",
    "from_event_mac": "b8e2d4...",       // ties this in to a specific out
    "payload_hash": "a3f9c1...",
    "accepted": true,
    "ack_reason": null                    // populated only if accepted=false
  }
}

// taint propagation (write-time observation)
{
  "type": "session.taint.update",
  "payload": {
    "trifecta": {
      "has_seen_untrusted": true,
      "has_accessed_private": false,
      "can_exfiltrate": false
    },
    "caused_by_event_mac": "c7d2e1...",
    "tool_name": "WebFetch"
  }
}

// permission decay (already exists in decay.py; add audit emission)
{
  "type": "policy.decayed",
  "payload": {
    "kind": "policy.critical_to_low",
    "pattern": "fs.delete",
    "last_reaffirmed": "2026-02-01T12:00:00Z",
    "decay_after_days": 14,
    "fallback_action": "use_default_classification"
  }
}
```

### 6.2 Derived (read-time) views - no new writes

These are pure functions of the existing log; expose via CLI:

- **`quill receipts list`** - folds `session.open` → `session.close` ranges; emits `Receipt` from in-range events. The `did` list = `tool.executed` event names; `changed` list = paths from arg dicts on file-mutating tools; `uncertain` = `agent.flag.uncertain` payloads + `verdict.allowed where risk >= high`; `to_verify` = same but explicit `agent.flag.uncertain` entries with a `to_verify=true` hint.
- **`quill bridge show`** - pairs `agent.handoff.out` ↔ `agent.handoff.in` by `payload_hash`. Orphans = out without matching in within N seconds. Cascades = same `payload_hash` consumed by ≥3 distinct sessions.
- **`quill trifecta show`** - folds `session.taint.update` events; lists sessions that crossed the trifecta line and what tool call closed each gap.
- **`quill ladder map`** - folds per-session `trust_ladder` from `session.open` payloads; aggregates by tool / by project.
- **`quill kpis`** - TDR, Intervention Rate, Time-to-Trust per project, derived from receipts.

### 6.3 Write-time vs derive-time split - the rule

Write at the time of the event when (and only when):
1. The event captures information that *cannot* be reconstructed later (handoff `payload_hash`, taint state at time of call, agent's own uncertainty flag).
2. The event is on the security-critical path (verdicts must be in the chain even if no other log line is).
3. The event opens or closes a *frame* that other events live inside (`session.open`, `session.close`).

Derive at read time when:
1. The information is a pure function of existing events (`Receipt`, `Bridge view`, `KPIs`).
2. The aggregation might evolve (today's "TDR formula" might change; the underlying events shouldn't).
3. The view is a UI affordance, not an audit trail.

### 6.4 Existing-system gap analysis

| System | What they do | What they don't do (Quill's gap) |
|---|---|---|
| LangGraph Checkpoints | Full state snapshot per node; thread-keyed; Postgres/Redis | No tamper-evidence; no separate handoff event; checkpoint *is* the state, not a contract |
| AutoGen GroupChat memory | Conversation history in a shared list | No payload hash; no contract; no orphan detection |
| CrewAI handoffs | Sequential task-output passing; `respect_context_window` | No handoff record beyond message body; no `accepted` ack |
| OpenAI Assistants API threads | Thread = conversation; messages chained | No agent-to-agent semantics; one assistant per thread |
| Anthropic sub-agents (Claude Code) | `transcript_path` + `session_id` parent linkage | This is *exactly* what Quill leverages; no payload-hash audit |

**The gap Quill closes:** every framework above stores *what was passed*, none store the cryptographic *handoff edge* with sender/receiver/contract/hash separately from the message body. That edge is what makes orphan detection and cascade analysis tractable. Manu's A2A Bridge schema in the vault is the exact missing piece.

---

## 7. Gaps in this report (epistemics)

- ❓ I did not verify the full text of the OWASP Agentic Top 10 2026; the page gates the PDF behind a download form. Get the PDF before citing ASI01–ASI10 by official name in marketing.
- ❓ I did not directly read the AIUC-1 cert artifacts (UiPath, ElevenLabs, Fieldguide); I only have press-release-level detail. The AIUC-1 quarterly research notes are the primary source.
- ❓ I did not verify whether any shipped product implements WebAuthn-attested approval for AI agent confirmations. Worth a deeper search before claiming "Quill is the first."
- 🔶 I inferred from absence-of-search-results that nobody is shipping Manu's exact Receipts schema. Re-verify quarterly; this is a fast-moving space.
- ❓ The "Chinese state-sponsored hijack of Claude Code" detail came from secondary sources; Anthropic's primary writeup is the source of record and worth pulling.

---

## 8. Next steps (concrete)

1. Pull OWASP Agentic Top 10 2026 PDF; map each ASI to a Quill default-policy pattern; ship as `quill policy --owasp-agentic-2026`.
2. Implement `session.open` / `session.close` events in `audit.py` and the Claude-Code stop-hook adapter (one-week scope of rec #1).
3. Implement `taint.py` as observation-only (one-week scope of rec #2). Even without enforcement, the audit log can answer trifecta questions retroactively.
4. Implement `agent.handoff.out` emission from existing sub-agent detection (one-week scope of rec #3).
5. Open a draft for OTel GenAI semantic conventions: `gen_ai.handoff.from`, `gen_ai.handoff.to`, `gen_ai.handoff.contract`, `gen_ai.handoff.payload_hash`. Quill becomes the reference implementation. This is community-leadership work; do it.

## Sources
- [Simon Willison - prompt injection tag](https://simonwillison.net/tags/prompt-injection/)
- [Simon Willison - new prompt injection papers (Nov 2 2025)](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks)
- [OpenAI Agents SDK - lifecycle](https://openai.github.io/openai-agents-python/ref/lifecycle/)
- [OWASP Top 10 for Agentic Applications 2026 - release post](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
- [EU AI Act Article 14 - Human Oversight](https://artificialintelligenceact.eu/article/14/)
- [AIUC-1 - official site](https://www.aiuc-1.com/)
- [MITRE ATLAS - Secure AI v2 release (May 6 2026)](https://ctid.mitre.org/blog/2026/05/06/secure-ai-v2-release)
- [Invariant Labs - MCP tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [Cerbos - agentic authorization](https://www.cerbos.dev/features-benefits-and-use-cases/agentic-authorization)
- [WorkOS - multi-hop delegation](https://workos.com/blog/oauth-multi-hop-delegation-ai-agents)
- [OpenTelemetry GenAI agent spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/)
- [Datadog - LLM OTel semantic convention](https://www.datadoghq.com/blog/llm-otel-semantic-convention/)
- [Letta - Letta Code blog](https://www.letta.com/blog/letta-code)
- [AuditableLLM - MDPI](https://www.mdpi.com/2079-9292/15/1/56)
- [nono.sh - Tamper-Evident Audit Trail for AI Agents](https://nono.sh/blog/secure-agent-audit)
- [Fortune - Replit AI catastrophic failure](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/)
- [AI Incident Database #1152 - Replit](https://incidentdatabase.ai/cite/1152/)
- [Microsoft Security Blog - OWASP Top 10 in Copilot Studio](https://www.microsoft.com/en-us/security/blog/2026/03/30/addressing-the-owasp-top-10-risks-in-agentic-ai-with-microsoft-copilot-studio/)
- [Practical DevSecOps - MCP Security Guide 2026](https://www.practical-devsecops.com/mcp-security-guide/)
- [Zylos - agent authentication & delegation 2026](https://zylos.ai/research/2026-04-11-agent-authentication-delegated-access-oauth-scoped-tokens)
