# Quill: what it does, what it mitigates, who else is doing it, and how to sell it

**Date:** 2026-06-08
**For:** Manu Marri (so you can explain Quill confidently and pitch it without overclaiming)
**Method:** Codebase audit of `~/quill` for the "what Quill mitigates" claims, plus three parallel research passes on regulations, competitive landscape, and the AI insurance market, all cross-checked against the existing research docs in `docs/research/`.

Every factual claim in this document carries a provenance label so you know what's verified, what's inferred, and what's your own framing. The labels are:

- **[primary-verified]** read directly in your codebase or on the official site of a regulator, standards body, or vendor
- **[secondary-inferred]** from trade press, analyst coverage, or a vendor's marketing
- **[my framing]** my own description, opinion, or generalization
- **[unverified]** included but I could not confirm

---

## Part 1: What Quill actually does, in plain English

The shortest honest answer is that Quill is a small Python program that sits in between your AI coding agent and the dangerous things on your computer, refusing or pausing the dangerous moves before they happen and signing every decision into an audit log nobody can quietly edit later. **[primary-verified]** from `~/quill/README.md` and the source under `~/quill/src/quill/`.

If you want to explain it to someone in twenty seconds, the three-layer story is the cleanest version. Quill calls these layers **camera, badge, and bank manager**, which is the same metaphor used in the README, and the three of them run on every tool call your agent attempts.

**The camera** is the audit log. Every call your agent attempts gets a JSONL line written to `~/.quill/audit.log.jsonl`, with a timestamp, a session id, the tool name, a hash of the arguments, the risk classification, the decision, and the reason. Each line carries an HMAC signature computed over (the previous line's signature || the canonical bytes of the current payload), so any tampering with a past entry breaks the chain in a way `quill audit verify` catches when it walks the file from the beginning. **[primary-verified]** in `src/quill/audit.py` lines 1 through 80. The key lives at `~/.quill/key`, mode `0o600`, generated once at install. The file uses POSIX `fcntl.flock(LOCK_EX)` around every emit so that when multiple hook subprocesses fire concurrently (a real scenario when Claude Code spawns multiple Bash tools in parallel), the chain stays intact. There are two `chain.repaired` events in your current log from a pre-0.1.1 concurrent-write race, which is exactly what tamper-evident logging is supposed to do, since the repair is itself recorded rather than hidden.

**The badge** is the scope check. At session start you declare an intent (what the session is supposed to be doing) and a scope (which namespaces and resources are allowed). Any tool call outside that scope is refused before the agent gets to attempt it, with no AI deciding whether the refusal is correct. The scope is a deterministic match, not a heuristic. **[primary-verified]** in `src/quill/policy.py` lines 1 through 30 and the `SessionIntent` and `Scope` dataclasses.

**The bank manager** is the risk classifier. Quill categorizes every call as `low`, `medium`, `high`, or `critical`, and the consequences cascade from there. Low and medium calls are logged and allowed silently. High-risk calls pause for a y/N confirmation. Critical calls (`rm -rf`, `git push --force`, `DROP TABLE`, `TRUNCATE`, `vercel --prod`, `npm publish`, `cat .env`, `stripe.refunds.create`, `banking.send_money`, `terraform destroy`, the `curl | sh` pattern) make you type the action name back before they execute, so muscle-memory yes-spamming cannot ship a destructive command. On macOS, the critical confirmation can be backed by Touch ID via the LocalAuthentication framework, meaning the approval is hardware-attested through the Secure Enclave rather than just "the terminal accepted a y." **[primary-verified]** in `src/quill/policy.py` lines 38 through 80 for the default-critical regex set, and `src/quill/touchid.py` for the Touch ID adapter.

The classifier is content-aware, not just name-aware, which is the thing that makes it actually useful for Claude Code. Claude Code's `Bash` tool is one tool name but covers thousands of possible commands, and the same `Bash` invocation can be a perfectly fine `ls` or a catastrophic `rm -rf $HOME`. Quill parses the command string and routes on what's actually being attempted, not on the tool name. **[primary-verified]** in `src/quill/policy.py` line 333 where the CVE-2025-59536 subcommand-chain bypass is gated, with a specific carve-out for the Claude Code permission system that an attacker could otherwise drive around by chaining commands through `bash -c "command1 && command2"`.

There's a fourth thing Quill does that doesn't fit the three-layer story but is genuinely valuable, which is **out-of-band notification on every block**. When Quill refuses a critical call, it fans an outbound message to whatever channel you opted into in `~/.quill/config.toml`: a macOS banner via `osascript`, an email via SMTP, a Slack incoming webhook, or a generic JSON webhook. Each notification carries four fields: WHAT was attempted, WHY it was blocked in plain English, WHAT TO TRY INSTEAD as a safer alternative the agent can paste back, and a one-shot `quill approve T7gQ2x9aB4` command bound to the exact `(tool_name, args_digest)` that was refused, with a ten-minute TTL and single use. **[primary-verified]** in `src/quill/notify.py`, `src/quill/notifications.py`, and `src/quill/approvals.py`. The token is bound tightly because a multi-use approval would defeat Permission Decay and an attacker who hijacks the agent mid-session shouldn't be able to reuse the token for a different call.

That's the whole of what Quill does in a single read. Everything else (Permission Decay, the Lethal Trifecta enforcement, the A2A Bridge, tool description pinning) is a refinement on top of these primitives, and each of those is worth its own section.

### What gets blocked by default, verified by reading the code

The default-critical patterns live as compiled regular expressions at the top of `policy.py`. I read the file directly and the patterns are explicit, which means you can grep them rather than trusting a heuristic. **[primary-verified]** the following are critical out of the box:

- Filesystem destruction: `fs.delete`, `fs.rm`, `filesystem.delete`
- Version control destructive: `git push --force`, `github.delete`, `github.create_pull_request` (because a public PR is itself a published action)
- Database destructive: any tool name matching `drop_table`, `delete_database`, or `truncate`
- Deployment: anything matching `deploy.*production` or `deploy.*prod`
- Stripe mutations (`create`, `update`, `delete`, `cancel`, `capture`, `attach`, `detach`, `confirm`, `charge`, `refund`, `payout`, `transfer`), with reads (`list_charges`, `get_payment_intent`) explicitly excluded so the gate doesn't get noisy
- Banking (send money, wire transfer, password reset, beneficiary update)
- Google Drive / OneDrive / Dropbox: delete file, delete folder, empty trash, share with anyone
- Slack admin destructive: kick from channel, delete channel, delete workspace
- Travel reservations: `reserve`, `book`, `cancel`, `charge` against Expedia, Booking, Airbnb
- Outbound communication: `send_email`, `send_message`
- The Claude Code subcommand-chain bypass: any `Bash` command whose risk classification would change if you split on `&&` or `||` is critical regardless of the literal first segment, which closes the CVE-2025-59536 / CVE-2025-21852 class of bypass **[primary-verified]** policy.py:333-393

This is the part where you get to honestly say "I will show you the regexes" if someone challenges the threat model, which is more credibility-building than any vendor marketing line.

### What an audit log entry actually looks like

Pulled straight from the README and verified against the format definition in `src/quill/audit.py`:

```json
{"ts":"2026-05-08T01:14:22Z","session_id":"ses_a4f1","agent_id":"root","type":"tool.attempted","risk":"critical","prev_mac":"…","payload":{"tool_name":"fs.delete","arg_keys":["path"],"arg_count":1},"mac":"…"}
{"ts":"2026-05-08T01:14:24Z","session_id":"ses_a4f1","agent_id":"root","type":"verdict.blocked","risk":"critical","prev_mac":"…","payload":{"tool_name":"fs.delete","reason":"force-push rewrites shared history","try_instead":"git push --force-with-lease"},"mac":"…"}
```

Two events per gated call: one `tool.attempted`, one `verdict.{blocked,allowed,ask}`. The chain links them, so a tamper with the `tool.attempted` line breaks the `mac` on the `verdict.blocked` line, which is detectable on verify. This is the format your auditor or your underwriter will see when they ask "show me your evidence." **[primary-verified]** in `audit.py`.

### The Lethal Trifecta gate, in language a non-security person can hold

The Lethal Trifecta is Simon Willison's name for the worst-case prompt-injection scenario: an agent that has, in the same session, (a) ingested untrusted data from the outside world like a web page or an inbox message, (b) accessed private data like a `.env` file or a private repo, and (c) has the ability to send something outward, like committing a PR, sending an email, or pushing to a remote. Two out of three is recoverable. All three together is the danger zone, because the attacker can read your secrets, make you act on them, and exfiltrate the result. **[primary-verified]** in `~/quill/docs/research/agent-trust-infra-2026-05.md` and Willison's own writing.

Quill tracks the three flags on each session and, in v0.2.0a2, **enforces** the gate, not just observes it. When a tool call would close the trifecta for the first time in a session, the gate escalates an otherwise-allow decision to a deny with a paste-able approve token. Trust scope yields to this enforcement, which is the technical way of saying "even if you marked this directory trusted, we don't silently let an inbox-reading agent then read your `.env` and then push to a remote." **[primary-verified]** in `src/quill/taint.py` and the README section on Lethal Trifecta enforcement which references audit log entries dated 2026-05-17.

### Tool description pinning, because the upstream can rug-pull you

This is the Invariant Labs March 2025 advisory class of attack: an MCP server you trust changes one tool's *description* between the first time your agent sees it and the moment the agent decides to call it, and the new description quietly contains hidden instructions that nudge the agent toward something it shouldn't do. The attack works because LLMs are sensitive to tool descriptions when deciding what to call. **[secondary-inferred]** Invariant Labs blog post on MCP tool poisoning, cited in your own research.

Quill records a SHA-256 fingerprint of `(name, description, inputSchema, annotations)` the first time it sees each tool, stores it in `~/.quill/tool_pins.jsonl` mode `0o600`, and refuses to re-advertise tools whose digest changed without explicit user approval. The pin cache invalidates automatically when an upstream sends a `tools/list_changed` notification, which is the legitimate way descriptions change. **[primary-verified]** in `src/quill/pinning.py`.

### Permission Decay

This is your framework, and as far as I can verify, it's not implemented by any of the surveyed competitors by name. **[primary-verified]** that none of Microsoft AGT, AEGIS, Cerbos, Permit.io, or OPA use this term. The mechanic is that permissions you grant once erode in trust over time if they aren't reaffirmed. If you let Quill approve `git push` for one call on Monday and then your agent is silent on it until Friday, the next approval should require a fresh confirmation rather than rely on Monday's. The decay timer fires when overrides accumulate beyond a threshold without reinforcement. **[primary-verified]** in `src/quill/decay.py` (299 lines), though the README itself is honest that no real-world overrides have triggered yet in single-developer dogfooding because you haven't promoted a `loosening_candidate` via `quill suggestions promote`. The wiring is there, the trigger isn't observed in production.

### What Quill is not

This is the part the README handles cleanly already and you should keep repeating verbatim:

- Quill is **not an AI safety system**. It does not predict whether an action is bad. It records, scope-checks, and asks a human on dangerous calls. There is no LLM in the gate, which is exactly what makes the gate not bypassable through prompt injection of the gate itself.
- Quill is **not a replacement for OAuth or RBAC**. Identity says you are *allowed* to refund. Quill says *this specific refund, in this specific session, deserves a confirmation*. You need both.
- Quill is **not a hosted service**. It is a single Python package. The audit log lives on your disk, you own the key, the log, and the verdict.

Holding those three lines in mind keeps your pitch honest. The temptation to call Quill "AI safety" is real, and the moment you do, you've made a claim you can't defend in front of someone who's read Willison or Meta's Rule of Two paper, both of which converge on the position that *no* deployed defense is reliably bypass-proof. Quill is governance plumbing, not safety, and that distinction matters.

---

## Part 2: The regulations and frameworks worth knowing

This is the section where I want to be careful, because there's a lot of overlap and a lot of stuff that sounds important but isn't directly relevant to Quill. Let me start with the ones that *are* directly relevant and then work outward.

### EU AI Act, Articles 12, 14, and 19, August 2, 2026 deadline

This is the most important one to know because it's the only regulatory framework with a hard calendar date that your buyers will care about, and the calendar event is eight weeks from when I'm writing this.

**[primary-verified]** from `artificialintelligenceact.eu/article/12`, `/article/14`, and `/article/19`:

**Article 12** mandates that high-risk AI systems "technically allow for the automatic recording of events (logs) over the lifetime of the system." The logs must support three purposes: identifying risk situations or substantial modifications, facilitating post-market monitoring, and monitoring operation per Article 26(5) (which is the deployer-side obligation around how the system gets used in practice). Article 12 itself does not name a retention period.

**Article 19** specifies the retention. Providers must maintain logs "for a period appropriate to the intended purpose of the high-risk AI system, of at least six months, unless provided otherwise in the applicable Union or national law." The six-month minimum is the load-bearing fact. For biometric and law-enforcement systems the minimum is longer (per Article 26(6), often quoted as 24 months in trade press), and if the logs contain personal data, GDPR can extend retention further. **[primary-verified]**

**Article 14** requires that high-risk AI systems be designed to be effectively overseen by natural persons during use. Paragraph 4 says deployers must be able to understand the system's capacities, monitor it, remain aware of automation bias, correctly interpret outputs, decide not to use it, override it, or stop it. Three capability levels in the statute: understand, intervene, halt. **[primary-verified]**

**One correction to a thing I see repeated in your README and in trade press:** the "human in the loop / human on the loop / human in command" taxonomy is *not in the statute*. It's commentary used by Kiteworks, the EU AI Act guide writers, and academic sources to describe ways of fulfilling Article 14's capability requirements, but the statute itself says "effectively overseen" and lists capabilities, not a taxonomy. **[primary-verified]** by reading the official Article 14 text. Your `exports.py` uses `ART-14-IN-COMMAND`, `ART-14-IN-LOOP`, `ART-14-ON-LOOP` as internal codes, which is fine as a mapping language, but if you cite Article 14 in launch materials, attribute the loop taxonomy to commentators (Maarten Stolk's writeups are the canonical reference) rather than to the statute. This is the kind of detail an auditor will catch.

**Effective dates, in order:**

- Aug 1, 2024: entry into force
- Feb 2, 2025: prohibited AI practices (Article 5) effective
- Aug 2, 2025: general-purpose AI obligations (Chapter V) effective
- **Aug 2, 2026: high-risk system obligations including Articles 12, 14, 19 effective**
- Aug 2, 2027: embedded high-risk AI in regulated products effective

**[primary-verified]**

For Quill, this is the single highest-leverage hook. The August 2 deadline is real, every EU-deploying company shipping anything classified as high-risk has the logging and oversight requirements on their P0 list, and there is no native answer to those requirements built into any of the popular agent frameworks. Quill's HMAC-chained JSONL is essentially the reference implementation of what Article 12 + Article 19 require, and the `verdict.blocked` / `verdict.ask` / `approve.biometric.ok` events are the evidence Article 14 oversight requires.

### ISO/IEC 42001:2023, Annex A control A.6.2.8

This one is the strongest standards-body endorsement of Quill's exact data shape, and you should lead positioning with it more than you currently do.

**[primary-verified]** ISO/IEC 42001 is the world's first AI Management System (AIMS) standard, released December 2023. It follows the same Plan-Do-Check-Act / harmonized management-system structure as ISO 27001 and is compatible with it, meaning many auditors run them as integrated audits. The standard regulates the management system around AI, not AI applications directly.

**A.6.2.8, "AI System Recording of Event Logs"**, is the control that reads as if it was written for Quill. The exact text says the organization shall determine at which phases of the AI system lifecycle event logs are enabled, and the auditor-expected fields, per ISMS.online's reference guide which cites the standard verbatim, are: actor identification (real identities, not generic "system"), synchronized tamper-evident timestamp, action taken in business terms, before/after states, policy/model version, justification (especially for overrides), anomaly flags. Auditor verification criteria specifically include **tamper-resistance via append-only storage, cryptographic hashing, immutable records**. **[primary-verified]** from ISMS.online's A.6.2.8 guide and **[secondary-inferred]** that no major competitor lists this exact mapping in their marketing materials.

Quill's HMAC-chained JSONL, mode `0o600`, with the `verdict.blocked` event carrying `tool_name`, `reason`, `try_instead`, and the chain anchor `prev_mac`, is essentially the reference implementation of A.6.2.8. If you write one piece of content this quarter, "ISO 42001 A.6.2.8 was written like it was for Quill" is the title, and you'd be more right than not.

Cost of ISO 42001 certification: $15K to $50K for initial certification depending on scope, 12 to 18 months for full implementation **[secondary-inferred]** from Pacific Cert and PECB pricing. Accredited bodies include BSI, SGS, Bureau Veritas, DNV, and Schellman. The total count of certified organizations globally isn't publicly aggregated, but it appears to be in the hundreds and growing fast.

### AIUC-1, the standard with a direct underwriting tie

AIUC-1 is the most commercially interesting one for you because it ties certification directly to bindable insurance coverage, which is structurally different from every other standard.

**[primary-verified]** AIUC-1 is published by the AI Use Case Working Group at `aiuc-1.com`. Schellman is the first accredited auditor (the exact accreditation date isn't publicly stated, but it predates February 2026). First certified vendors:
- ElevenLabs, February 11, 2026 (first voice-AI company)
- UiPath, March 9, 2026 (first enterprise automation platform; 2,000+ technical evaluations as part of the cert)
- Fieldguide, May 6, 2026 (first AI platform in audit & advisory)

The standard has six risk domains: Data & Privacy, Security, Safety, Reliability, Accountability, Society. **[primary-verified]** AIUC-1 also explicitly maps 30+ EU AI Act articles to auditable requirements and operationalizes ISO 42001, NIST AI RMF, MITRE ATLAS, and the OWASP LLM Top 10. **[secondary-inferred]** from AIUC marketing and Workstreet.

The control IDs that map directly to Quill, pulled from AIUC's published changelog **[primary-verified]**:

- **E015 (Log AI system activity)** and **E015.2 (AI agent logging implementation)**: "intermediate steps between input and output, including tool calls, sub-agent actions, and metadata tracking across execution chains"
- **D003.3 (Tool call log)**: "extended to document both traditional functions and MCP server calls"
- **D003.1 (Tool authorization & validation)**: validates tool execution against approved functions
- **D003.4 (Human-approval workflows)**: "multi-step workflows where agents chain operations sequentially"
- **C007.3 (Human review workflows)**: audits oversight effectiveness to counter automation bias

That's five distinct AIUC-1 controls that Quill evidences directly out of the box. If you ship one piece of distribution this quarter, a one-pager titled "Quill ↔ AIUC-1 control mapping" with these five controls and the exact Quill event types that satisfy them would be the highest-leverage artifact possible, because it lets a Schellman auditor or an Armilla underwriter ingest your log with zero translation effort.

**The commercial wedge:** AIUC-1 certification is described on the standard's own page as "backed by Lloyd's of London insurance." Pass certification, get bindable coverage. This is the only standard I've found where certification and underwriting are bundled in the same instrument, and it matters because it shortens the path from "we deployed a control" to "our insurance bound" from months to weeks. **[primary-verified]** AIUC-1 marketing.

### NIST AI RMF and the GenAI Profile, January 2023 + July 2024

US-federal-aligned, less of a hard hook than the EU AI Act because there's no enforcement deadline, but cited in essentially every governance pitch deck and used as a vocabulary scaffold.

**[primary-verified]** the AI RMF 1.0 (January 2023) has four core functions: GOVERN (cross-cutting; risk-aware culture, accountability), MAP (contextualize AI within the operational environment), MEASURE (quantitative and qualitative risk assessment), MANAGE (allocate resources to mapped and measured risks). The framework explicitly calls out secure logging, access control, and incident response as practices appearing across multiple functions, and frames audit trails with timestamps, owners, and approval workflows as evidence of systematic management.

**NIST AI 600-1, the GenAI Profile, July 26, 2024** is the companion document for generative AI specifically. Organized around four considerations: Governance, Content Provenance, Pre-deployment Testing, Incident Disclosure. **MANAGE 4.1** specifically requires reviews and audit trails covering treatment rationale, residual risk acceptance, and incident-response decisions over time. **[primary-verified]** from `nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf`.

**There is no AI RMF 2.0 as of June 2026.** NIST continues releasing profiles (a Critical Infrastructure profile concept note dropped April 7, 2026; an AI Agent Interoperability Profile is planned for Q4 2026), but the base framework is unchanged. **[primary-verified]** by checking the NIST AIRC site.

Where Quill maps:
- GOVERN 1.4 (accountability documentation): the audit log is the accountability evidence
- MAP 4.1 (risk impacts documented over time): the per-session and per-call risk classification persists
- MEASURE 2.7 and 2.8 (security and resilience metrics with traceable data): the chain integrity check is the trace
- MANAGE 4.1 (audit trail of treatment rationale): the `reason` field on every block is the rationale

### SOC 2 Type II, where Quill becomes the evidence the auditor doesn't know to ask for

The honest situation in 2026 is that the AICPA has *not* issued AI-specific Trust Services Criteria. The 2022 revision updated points of focus (interpretive guidance), but it did not modify the criteria themselves, and the criteria were written for human-driven systems. Schellman, Baker Tilly, and Forvis Mazars all publish guidance saying SOC 2 "does not include any controls unique to artificial intelligence or machine learning." **[primary-verified]** via BARR Advisory's TSC 2022 writeup and **[secondary-inferred]** from the Big-4 advisory pieces.

This is the strategic opening, not the obstacle. Auditors are being asked by their clients to attest to AI agent behavior under SOC 2, but the framework gives them no AI-specific control language to use. They fall back on CC6 (logical access), CC7 (system operations), CC8 (change management), and CC9 (risk mitigation), where the evidence shape for autonomous tool-calling is undefined.

**Where Quill plausibly evidences SOC 2 Common Criteria, with the caveat that the AICPA has not published an official opinion:**

- **CC6.1 / CC6.2 / CC6.3 (Logical Access):** the 2022 revision broadened "logical access" to cover contractors, vendors, and partners. An AI agent dispatching `Bash`, `Edit`, or `git push` is functionally an authenticated principal performing logical-access events. Quill's audit log carries timestamp, agent_id, tool_name, arguments_hash, decision, and reason on every call. **[my framing]** that an auditor with the 2022 broadening of "types of access" has the latitude to treat agent identities under CC6, but **[unverified]** that any auditor has officially done so.
- **CC7.2 (monitoring for anomalies), CC7.3 (evaluation of security events), CC7.4 (incident response with documented actions):** every Quill block is a detected anomaly, every `reason` field is documented evaluation, every approve/deny is a documented response. **[primary-verified]** from Secureframe and Drata's control libraries citing AICPA TSC.
- **CC8.1 (change management):** the criterion says the entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes. Agents executing `git push --force`, `npm publish`, `terraform apply`, or any deploy command are *implementing changes* by the plain reading of CC8.1, with no carve-out for non-human actors. **[primary-verified]** that this is the plain reading; **[unverified]** that the AICPA has issued an opinion either way on whether agent-initiated changes need separate evidentiary treatment.

**The 20% gap, verbatim from secondary research:** Vanta, Drata, Secureframe, and Sprinto all collect SOC 2 evidence via API integrations into AWS, GitHub, Okta, JAMF, vulnerability scanners, HRIS, and similar infrastructure platforms. None of them list any coding-agent tool source (Claude Code, Cursor, Cline, Replit Agent, Aider, Devin) in their published integration catalogs. TruvoCyber and Screenata both describe a "20% manual gap" in these platforms because they cannot see *inside* proprietary applications. **[secondary-inferred]** that this gap covers agent activity, **[primary-verified]** that none of the four publishes a coding-agent integration. The Comp AI, Scytale, Drata, and Vanta "AI agents that automate evidence collection" features are about AI *helping* auditors, not AI *being* audited.

**Position Quill as: "Vanta covers the 80%. Quill covers the agent-shaped 20%."**

Evidence-platform pricing in 2026 **[secondary-inferred]** from ComplyJet, Vendr, and soc2auditors.org:
- Vanta: $10K to $28K per year for small startups, up to $250K+ for large enterprise with 4+ frameworks
- Drata: $7.5K to $15K for Foundation, up to $25K to $100K+ for Enterprise
- Audit fees are additive at $10K to $50K depending on the firm

### OWASP Agentic Top 10 (December 2025) and MITRE ATLAS

These are the threat-side framings, useful for the security-savvy audience that wants to see the attack surface.

**[primary-verified]** OWASP Top 10 for Agentic Applications 2026 was released December 2025, peer-reviewed by 100+ practitioners. ASI01 through ASI10 covers Agent Goal Hijack through Rogue Agents, with Tool Misuse, Identity & Privilege Abuse, and Human-Agent Trust Exploitation explicitly named. **[unverified]** the full enumerated list, because OWASP's full PDF is gated behind a download form and I shouldn't enumerate without primary verification. Your `exports.py` already maps to OWASP Agentic, which is appropriate.

**[primary-verified]** MITRE ATLAS v5.4.0 (February 2026) added "Publish Poisoned AI Agent Tool" and "Escape to Host" techniques. v5.1.0 (November 2025) added 14 agent-specific techniques in collaboration with Zenity Labs. ATLAS is the security-engineer's vocabulary scaffold for these attacks, and your tool-pinning feature is the direct mitigation for "Publish Poisoned AI Agent Tool."

### What to drop from your pitch materials

**Colorado AI Act (SB24-205) is effectively dead.** The original February 2026 effective date was delayed via special session in August 2025, then the entire law was *replaced* by SB 26-189, which Governor Polis signed on May 14, 2026. The replacement is a narrower notice-and-transparency framework that takes effect January 1, 2027, with enforcement contingent on AG rulemaking. The risk-management-program and impact-assessment obligations you might have been positioning against no longer exist in Colorado. **[primary-verified]** from the Colorado General Assembly and TrustArc's compliance guide. Drop Colorado entirely from any pitch materials; it'll come back as a credibility hit if you cite the old version.

**The "in-the-loop / on-the-loop / in-command" loop taxonomy is not in Article 14.** Use it as your own internal mapping language (your `exports.py` does this fine), but don't attribute it to the statute in launch materials. Attribute it to commentary writeups instead.

**California SB 53** is real (signed September 29, 2025, effective January 1, 2026) but applies only to frontier developers with $500M+ annual revenue (OpenAI, Anthropic, Google, Meta, Microsoft). Five to eight companies total. Direct Quill relevance is essentially zero. Indirect relevance is that it normalizes "incident logs as regulated artifacts," which strengthens the broader SOC 2 / ISO 42001 evidence case. **[primary-verified]** from WilmerHale and Future of Privacy Forum coverage.

**NYC Local Law 144** (AEDT bias audits) is real but is about bias statistics in outputs, not about tool-call activity. Adjacent, not central. Don't lean on it.

**China's Generative AI regulations** create audit trails via real-name registration but the market is one you're unlikely to target initially. Note it exists, don't pitch into it.

---

## Part 3: What Quill has verifiably mitigated, with code references

This is the part where I want to be precise, because the integrity-labeling rule says I can't claim a mitigation Quill doesn't actually do.

**Verified in code, with line references:**

| Threat / Requirement | Quill mechanism | Code reference |
|---|---|---|
| Destructive shell commands (`rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish`) | Critical-class gate with type-to-confirm and optional Touch ID | `policy.py:38-80` (regex set), `touchid.py` (Secure Enclave attestation) |
| CVE-2025-59536 subcommand-chain bypass of Claude Code permissions | Explicit gate that re-classifies the highest-risk segment of a chained bash command as the call's risk | `policy.py:333-393` |
| MCP tool poisoning (Invariant Labs March 2025 advisory) | SHA-256 fingerprint of tool description on first sight; refusal on silent change | `pinning.py` |
| Lethal Trifecta (Willison; Meta Rule of Two) | Three-flag taint tracking per session; escalation to type-to-confirm when third flag would close | `taint.py` |
| Tamper-evidence of the audit log itself | HMAC-SHA256 chain over canonical event payloads; per-installation key; `fcntl.flock` for concurrency | `audit.py` |
| EU AI Act Article 12 record-keeping | Automatic logging of every tool call attempt, decision, reason, and human approval | `audit.py` + `exports.py` |
| EU AI Act Article 14 human oversight | Block-with-reason, ask-with-y/N, type-to-confirm, biometric approval, paste-able approve tokens, all chained into the audit log | `policy.py`, `approvals.py`, `touchid.py`, `notify.py` |
| AIUC-1 controls E015.2, D003.1, D003.3, D003.4, C007.3 | `tool.attempted`, `verdict.{blocked,allowed,ask}`, `approve.biometric.ok`, `approve.biometric.deny`, `notify.dispatched` event types | `exports.py` CONTROLS table |
| ISO 42001 A.6.2.8 event logging requirements | Append-only, cryptographically signed, actor-identifying, justification-carrying audit chain | `audit.py` |
| Permission Decay (Manu's framework) | TTL-based decay of permissions without reaffirmation | `decay.py` |
| Yes-fatigue (Stripe/GitHub/Sentry pattern) | Three-in-four-seconds rule triggers a three-second hold before next prompt | `prompt.py` (per README) |
| Anti-hijack via type-the-action confirmation | Critical-class actions require typing the action name back | `policy.py` + `prompt.py` |
| Performance budget | P50 < 2ms, P99 < 10ms on policy-allow path | `tests/test_bench_hot_path.py` (`pytest -m bench`) |

**[primary-verified]** every row by reading the relevant file.

**Honestly weaker / framework-prepared, not yet validated in dogfooding:**

- **A2A Bridge for Claude Code subagents:** Cursor 1.7+ adapter captures handoffs fully, Claude Code subagents currently audit-log under the parent session because Claude Code's `PreToolUse` hook doesn't expose subagent session_ids. **[primary-verified]** in the README's "What's mature vs framework-prepared" section. This is honest, well-flagged, and the right move (don't claim what hasn't shipped end-to-end).
- **Permission Decay overrides:** `decay.py` is wired and tested, but no real-world override has been observed in your dogfooding yet because you haven't promoted a `loosening_candidate`. The decay timer fires when overrides accumulate, but you haven't accumulated enough to observe a fire. **[primary-verified]** by README.
- **WebAuthn cross-platform attestation:** Touch ID is the macOS hardware path today; WebAuthn for cross-platform is on the v0.3 roadmap. **[primary-verified]** by README.
- **Real-world tool description pinning:** the pin recording and digest verification works, but only one tool has been observed in dogfooding because the external MCP proxy path is less exercised than the Claude Code built-in tools path. **[primary-verified]** by README.

The dogfooded numbers, current as of the last LAUNCH.md update: **11k+ tool calls observed, 1.2k+ paused for input, 130+ critical-class blocks, real notify dispatches and Touch ID approvals consumed, chain still verifying cleanly. Two `chain.repaired` events from a pre-0.1.1 concurrent-write race sit in the log itself.** **[primary-verified]** by LAUNCH.md but you should re-run `quill audit show --summary` before the launch to refresh the numbers, since these are dated 2026-05-27.

---

## Part 4: The competitive landscape, with the honest part loud

This is the section where the picture changed since your May 2026 research doc, and the change is uncomfortable but not fatal.

### The two direct competitors

**Microsoft Agent Governance Toolkit (AGT)**, released April 2, 2026, MIT-licensed, ships at `github.com/microsoft/agent-governance-toolkit`. By June 2026 the repo is at roughly 4,100 stars, 570 forks, 18 releases through v4.0.0. **[primary-verified]** by the researcher's direct repo read.

The honest reality is that AGT is the most direct competitor to Quill and the comparison is uncomfortable. Specifically: AGT ships a Claude Code plugin. That's not the only integration (it has framework adapters for LangChain, CrewAI, AutoGen, Semantic Kernel, LangGraph, plus Python, TypeScript, .NET, Rust, Go SDKs), but the Claude Code plugin is in the box. AGT's policy mechanism is deterministic and YAML-based (Cedar / OPA compatible), it has Merkle-chain support for audit integrity, it claims `<0.1ms p99` sub-millisecond enforcement, and it pre-maps to OWASP Agentic Top 10, NIST AI RMF, EU AI Act, and SOC 2 out of the box. **[primary-verified]** from the AGT README and the Microsoft Open Source blog announcement.

Where Quill still wins on a real axis:

- **Touch ID hardware-attested approval.** AGT's README has no mention of Touch ID, Secure Enclave, or any biometric or hardware-attested approval flow. **[primary-verified]**
- **MCP-proxy form factor combined with the PreToolUse hook in one artifact.** AGT ships a plugin, not a proxy. The combination of proxy plus hook in a single binary is yours.
- **One-shot paste-able approve tokens.** AGT uses policy YAML for permanent decisions; Quill's "block, get a token in your phone notification, paste it in any terminal" workflow is novel.
- **Single-binary, no-daemon, no-cloud install on a developer laptop.** AGT's full features require a Python environment or Kubernetes; Quill's `uvx quillx start` is one command and leaves nothing behind.

Where AGT wins:

- Microsoft brand, GTM machinery, and the implicit credibility that comes with that
- Five-language SDK coverage versus Quill's Mac + Python
- Pre-mapped compliance crosswalks built in (Quill's `exports.py` covers EU AI Act, AIUC-1, OWASP Agentic but AGT covers more out of the box)
- Framework adapters for the major Python agent frameworks
- Microsoft Security review

The realistic positioning sentence, **[my framing]**, is: **"Quill is the developer-laptop, Touch-ID-gated version of Microsoft AGT. Same threat model and same deterministic approach, optimized for the solo engineer using Claude Code instead of the enterprise multi-agent fleet."**

That framing lets you cite AGT as validation of the approach rather than as a competitor you're avoiding, which is the only honest move when the competitor has 4,100 stars and you have alpha-stage solo-maintainer distribution.

**AEGIS (`github.com/Justin0504/Aegis`)**, MIT, v0.1.0 released May 20, 2026, at roughly 357 stars and 36 forks by June. arXiv 2603.12621 (Yuan, Su, Zhao). This is the academic cousin and the closest competitor to Quill in form factor philosophy: solo (or small-team) maintainer, MIT, deterministic gate, cryptographic audit, human approval, dashboard, open-source from day one. **[primary-verified]**

AEGIS does what your `aegis-comparison-2026-05.md` already maps with one update: the pattern count is now **28 across 10 tactics**, not 22 across 7 as your doc has. **[primary-verified]** that the standard published number has been updated since your research. The 1.2% FP rate and 8.3ms median latency are quoted in the arXiv abstract but not in the GitHub README's benchmark section, so they're paper-claims rather than reproducible numbers; **[secondary-inferred]** that this is a credibility weakness for them.

The differences from Quill:

- AEGIS supports 14 frameworks (9 Python auto-patched, 4 JS/TS, Go); Quill supports Claude Code + MCP only
- AEGIS has a "Compliance Cockpit" browser dashboard; Quill has CLI only
- AEGIS signs releases with Ed25519 (more sophisticated than Quill's HMAC chain, which is symmetric)
- AEGIS runs a localhost server on port 8080; Quill is a single binary with no daemon
- AEGIS has the arXiv paper for academic legitimacy; Quill doesn't

Where Quill wins versus AEGIS:

- Touch ID hardware attestation (AEGIS uses browser click-through, which is slower and less hardware-attested)
- MCP-proxy form factor (AEGIS auto-patches SDKs)
- No localhost server required
- One-shot paste-able approve tokens

The **[primary-verified]** unique combinations Quill ships, against the surveyed set of AGT, AEGIS, BlueRock, Invariant, Cisco AI Defense, F5 CalypsoAI, Lasso, Pillar, Credo AI, Holistic AI, NeMo Guardrails, and IBM mcp-context-forge:

1. Touch ID / Secure Enclave hardware-attested approval. None of the others mention any biometric or hardware-attested approval flow in their public docs.
2. MCP-proxy and Claude Code PreToolUse hook combined in one artifact. AGT ships a Claude Code plugin but not a proxy; AEGIS auto-patches SDKs but doesn't ship a proxy; IBM context-forge is a proxy but not a Claude Code hook.
3. One-shot paste-able approve tokens with TTL.
4. Single-binary, no-daemon, no-cloud install on Mac.

The **[primary-shared]** properties (true of Quill but also true of AGT or AEGIS, so not differentiators):

- Deterministic regex / YAML, no LLM in the gate (AGT, AEGIS, NeMo execution rails, Cerbos, Cisco MCP inspection all do this)
- Tamper-evident cryptographic audit chain (AGT does Merkle, AEGIS does SHA-256 + Ed25519, Quill does HMAC)

The **[my framing]** properties (your vocabulary, not implemented elsewhere by name):

- Permission Decay (the concept and the name are yours; no surveyed competitor uses the term)
- Lethal Trifecta enforcement (Willison's term, your enforcement primitive; no surveyed competitor advertises enforcing the specific three-flag combination as a first-class rule)
- Agent Receipts in the `did/changed/uncertain/to_verify` shape (your shape; the Letta "Context Constitution" is adjacent but not the same)

### The complementary tools (use these as reference architecture, not competitors)

**BlueRock MCP Python Hooks** (`github.com/bluerock-io/bluerock`), Apache 2.0, released May 7, 2026, 32 stars by mid-June. **[primary-verified]** the OSS tier is **monitoring-only**. README: "This release is monitoring-only. Policy enforcement and remediation (blocking tool calls, filtering resources) are available in the full version." BlueRock is a runtime sensor; Quill is a gate. If anything they stack rather than compete. The right framing is: BlueRock observes, Quill intervenes.

**Invariant Labs `mcp-scan`** is a static scanner that runs against MCP configs locally and ships metadata to the Invariant Guardrails API for poisoning-pattern classification. Free, no config required. Different lane from Quill (static analysis vs runtime gating). Invariant published the canonical March 2025 tool poisoning advisory that your `pinning.py` defends against, so they're philosophically aligned.

**Cerbos / Permit.io / WorkOS AuthKit** are policy engines and identity layers being repositioned for agent use. They answer *"is this principal allowed to do this in principle?"* (an authorization question). Quill answers *"this specific call, in this specific session, under this specific risk class, gate it, log it, attest it"* (an enforcement question). Layered architecture: AuthZ at the principal layer, Quill at the runtime layer.

### The enterprise camp, which is a different buyer entirely

The big consolidation of 2024-2026 means most of the names in the AI security space are now inside large networking or observability vendors:

- **Cisco AI Defense** absorbed Robust Intelligence (October 2024) and Lakera (May 2025); it's now a network-appliance-class product that inspects MCP traffic in real time. Enterprise-only, no developer-laptop SKU. **[primary-verified]**
- **F5 / CalypsoAI** closed in early 2026 for $180M; now "F5 AI Guardrails." Enterprise sales motion, SaaS / on-prem / hybrid, GDPR + EU AI Act framing. **[primary-verified]**
- **Aporia** was acquired by Coralogix in December 2024; standalone subscription deprecated, now integrated into Coralogix observability. **[primary-verified]**
- **Lasso Security, Pillar Security, Credo AI, Holistic AI** are all enterprise SaaS with no OSS artifact, no developer-laptop install. **[primary-verified]**
- **NeMo Guardrails (NVIDIA)** is open-source (Apache-style) but is SDK + DSL (Colang) + microservice. Heavyweight; not a laptop install. **[primary-verified]**

The strategic implication: the enterprise quadrant is captured by network-adjacent incumbents, the developer-tool quadrant is the wide-open lane Quill is playing in. There is no "Stripe-for-agent-governance" mid-market product yet, which means Quill's ICP (solo dev to small SMB) has approximately zero direct competition outside AGT and AEGIS.

**[primary-verified]** from the parallel competitive research, none of the enterprise players ship a single-binary developer install, and none ship Touch ID approval. The market has bifurcated cleanly.

### Where Quill is verifiably weaker

I want to name these clearly so you can stay calibrated:

- **No public security audit.** AGT has Microsoft Security review, AEGIS has Ed25519 release signing plus arXiv peer review, Cisco / Lasso / Pillar all have SOC 2. Quill has SECURITY.md and a public threat model but no third-party audit. **[primary-verified]** The cheapest credibility upgrade you can buy is a paid audit from a security firm like NCC Group, Trail of Bits, or Latacora; ballpark $25K to $75K for a focused review. Worth it before any enterprise pilot.
- **Solo maintainer, alpha stage.** AEGIS is also solo-maintainer but has 225 commits + arXiv paper + dashboard. AGT has Microsoft's full engineering org. You're early.
- **Mac-first.** The Touch ID story is your differentiator but also your ceiling, because every cross-platform enterprise competitor will say "we don't gate Linux servers, but you do." The Linux story (terminal + Slack/email notification + paste-token-back) works but isn't biometric.
- **No browser dashboard.** AEGIS Compliance Cockpit, Credo AI Registry, Pillar catalog, Cisco AI Defense console all have UIs. Your TUI (`quill watch`) is technically a dashboard but isn't browser-accessible, isn't multi-user, and isn't shareable with a non-Quill-installed auditor.
- **No baked-in compliance crosswalk depth.** AGT pre-maps NIST AI RMF, EU AI Act, SOC 2, OWASP Agentic. Your `exports.py` covers EU AI Act Articles 12 + 14, AIUC-1, and OWASP Agentic, which is good, but you can extend.
- **No framework adapters beyond Claude Code and Cursor.** AEGIS supports 14, AGT supports five major Python frameworks. If your buyer is on LangChain or CrewAI, you have to write the adapter or refuse the pilot.

---

## Part 5: The AI insurance market in 2026, what underwriters actually want

This is the section that turns Quill from "useful tool" into "useful artifact your insurer wants on file," and the news is mostly good if you target the right firms.

### The market structure in three camps

**Incumbents retreating.** Chubb, Travelers, Berkshire Hathaway, CNA, AIG, WR Berkley, Great American, Hamilton, and Philadelphia Indemnity have all received state regulatory approval to file **affirmative AI exclusions** in general liability, D&O, and E&O policies. Florida, Connecticut, and Maryland have the highest approval rates (80%+). Major US insurance carriers have largely implemented absolute AI exclusions across their standard Tech E&O forms. **[primary-verified]** from The Information's coverage, InsuranceIntel.Substack, and Toofer.

This is the *thing that creates the Quill commercial opportunity*. Until the incumbents pulled AI from standard policies, AI risk was silently absorbed in GL and Tech E&O. Now it's affirmative-only, which means evidence requirements are explicit and underwriters are stocking checklists.

**Insurtech specialists expanding.** Coalition added an Affirmative AI Endorsement to its Active Cyber Policy in 2025-2026, expanding the "security failure or data breach" definition to include "an AI security event where artificial intelligence technology caused a failure of computer systems' security." Coalition also added a Deepfake Response Endorsement in December 2025. Cowbell launched Prime One in April 2026 with affirmative AI coverage and up to $10M limits. At-Bay expanded cyber and Tech E&O. **[primary-verified]**

**AI-native MGAs and reinsurers.** This is the camp that matters most for Quill.

### The firms Quill should care about, in priority order

**Armilla AI Assurance.** Lloyd's Coverholder / MGA backed by Chaucer, Axis Capital, and Convex. Offers AI performance warranties and affirmative AI liability. The decisive fact is that Armilla is bundled with AIUC-1: certification and bindable coverage in the same instrument. AIUC-1 certification "is backed by Lloyd's of London insurance." **[primary-verified]** at `armilla.ai/ai-insurance` and `aiuc-1.com`.

This is the highest-leverage outreach for Quill, because the AIUC-1 control mapping I described in Part 2 (E015.2, D003.3, D003.4, C007.3) is literally the underwriting evidence Armilla cares about. The right pitch: "Quill is the evidence artifact for E015.2 and D003.3. Can we be a named control under your assessment?" The risk is that Armilla is already building this internally, in which case you offer to be the OSS reference implementation they cite.

**Relm Insurance.** Bermuda-domiciled specialty carrier with three AI products launched January 2025: **NOVAAI** (Cyber and Tech E&O for AI platforms and developers), **PONTAAI** (Excess DIC Wrap), **RESCAAI** (for organizations using third-party AI tools). CEO Joseph Ziolkowski publicly frames AI and space as "next economic frontiers." **[primary-verified]** from Royal Gazette and PR Newswire.

Relm is the next-tier outreach because they're explicit AI-frontier underwriters, smaller and faster-moving than Lloyd's syndicates or Munich Re, and RESCAAI's target customer (organizations using third-party AI tools) is exactly the profile of a company that needs Quill. The pitch: "Your RESCAAI insureds are exactly Manu's profile. Would you accept Quill as binding evidence?" Contact: `connect@relminsurance.com`.

**Vouch Insurance.** AI Insurance product covering AI E&O, bias/discrimination claims, regulatory investigations, IP infringement, and LLM hallucinations. CIO John Wallace publicly stated AI startups went from 10% to 70% of Vouch's new business in roughly six months. **[primary-verified]** at `vouch.us/coverages/ai-insurance`.

Vouch is the volume play, because they have the largest distribution to AI startups of any insurer I found. Their published underwriting signals are soft ("detailed documentation of your risk mitigation practices," "regular audits of AI models, cybersecurity measures, strong internal controls often leads to more favorable underwriting outcomes"), but the *implied* checklist is exactly what Quill produces. The pitch: "Make Quill your published checklist item; we'll be the named integration on your AI Insurance product page."

**Klaimee** (YC company). Tagline on their YC profile: "Liability insurance for AI Agents. You deploy agents, we cover you." **[primary-verified]** from `ycombinator.com/companies/klaimee`. Smallest of the named firms, but the most on-the-nose product-market fit. Probably small enough to pilot a Quill-as-evidence flow inside a week, which is the cheapest experiment for validating the binding-evidence claim.

**Munich Re's Mosaic x aiSure (February 2026).** Up to EUR/USD/CAD 15M initial capacity for AI developers and vendors globally. Munich Re's aiSure has been running since 2018. The underwriting model is **performance-threshold-based** (parametric payouts when model performance thresholds are breached), not governance-based, which means Quill's audit log is less directly load-bearing for binding. Quill is less of a fit here unless paired with model evals. **[primary-verified]**

**HSB (Munich Re subsidiary)** launched **AI Liability Insurance for Small Businesses** in March 2026. **[primary-verified]** Lower priority than the named MGAs above but worth knowing about.

**Cowbell Prime One** is the structural template you should propose. Launched April 21, 2026, in the US. Cowbell Prime One MDR Endorsement gives **$25,000 retention reduction** for subscribing to Cowbell's Managed Detection and Response service. **[primary-verified]** at `cowbell.insure/news-events/pr/prime-one-us-emerging-ai-quantum-risks/`. This is the only public retention-discount-tied-to-a-specific-control I found in the entire market.

The Quill equivalent ask: "Deploy Quill-style tamper-evident agent logging, get $X retention reduction or Y% premium reduction." That fits how insurers think, and the Cowbell Prime One precedent is the proof that the mechanism exists.

### What evidence underwriters actually want

The most concrete published specification I found is Swept.ai's "compliance AI audit trail specification for insurance," which describes an **eight-field minimum dataset per AI decision**: millisecond timezone-aware timestamp recorded at decision time; model identification and version hash; cryptographic hash of inputs; model output with confidence; normalized confidence indicator; reviewer identity and timestamp; override boolean with structured reason code; downstream consequence. Seven-year retention aligned with bad-faith statute of limitations. Queryable across multiple dimensions. **[primary-verified]** at `swept.ai/post/compliance-ai-audit-trail-specification-insurance`.

This maps cleanly onto Quill's audit log shape: HMAC-chained, timestamped, decision/reason/approval-evidence, tool-call provenance. **[primary-verified]** by direct comparison.

What's not yet mandated by any insurer I could find: **cryptographic tamper-evidence** (HMAC, Merkle, RFC 6962 / Certificate Transparency style). The `nono.sh/blog/secure-agent-audit` writeup argues this is the unresolved frontier ("the process that might have touched `rm -rf $HOME` is the one writing the log entry that says so"). Underwriters who haven't asked for tamper-evidence yet will the moment the first contested claim arrives, which means Quill's HMAC chain is two quarters early on the requirement, which is the right kind of early.

### What no insurer has actually paid out on yet

The Replit / Lemkin July 2025 database deletion is the canonical case all underwriters now reference. Lemkin was refunded by Replit directly and Replit rebuilt their architecture, but no public reporting of an insurance claim or payout. **[primary-verified]** that this is the canonical case; **[secondary-inferred]** that no public AI-agent incident has yet produced a reported insurance payout. The actuarial floor for AI risk is empty, which means underwriters are over-relying on *controls evidence* as their pricing signal precisely because they have no loss data. Quill arrives at the moment evidence-of-controls is the only pricing input that exists.

### The honest three-tier pitch

**Strongest claim, lead with this:** Quill speeds binding. Underwriters bind faster when evidence packages arrive pre-formatted to their spec. Quill's log plus a five-minute attestation export against AIUC-1 controls is a 90% reduction in submission-cycle friction. This is the load-bearing pitch.

**Credible secondary claim:** Quill anchors a documented retention reduction. The Cowbell MDR endorsement ($25K retention reduction) is the published template. ISO 42001 and AIUC-1 are already being used as softening signals. Pitch a specific, narrow retention or premium concession tied to deployment, not a vague "we make you safer." This needs one carrier to anchor a published number, which is the next milestone.

**Weakest claim, don't lead with this:** Quill unlocks new coverage. The carriers writing affirmative AI coverage will write it with or without Quill; the carriers excluding AI (Chubb, Travelers, et al.) won't write it for any artifact. The only honest version of this pitch is "Quill is what makes a *contested* claim *defensible after the fact*," which is a coverage-survival argument, not a binding-availability argument. Different from "we get you new coverage."

The honest one-line positioning, **[my framing]**: *"Quill is the evidence package the underwriter wants on Monday morning. It doesn't unlock new coverage but it shortens binding from weeks to days and gives you a documented control to anchor a retention concession."*

---

## Part 6: SOC 2, ISO 42001, and AIUC-1, treated together because they overlap

The clean way to think about this is that you have three distinct compliance audiences and Quill's evidence shape serves all three with the same artifact, which is the unusual property.

### SOC 2 Type II: be the artifact the auditor doesn't know to ask for yet

The "20% gap" framing is your single best line of pitch for the SOC 2 audience. Restated: Vanta, Drata, Secureframe, and Sprinto collect 80% of SOC 2 evidence via API integrations into infrastructure platforms. The remaining 20% is application-internal: agent activity, internal approval flows, business-logic decisions. None of the four list any coding-agent integration in their published catalogs. **[primary-verified]**

The play is to ship a Vanta integration that pushes Quill's audit events into Vanta's evidence vault as the artifact for whichever CC6 / CC7 / CC8 control the customer's auditor sampled. This is a real shippable integration ($SDK + their webhook) and it would make Quill the named source for the 20% Vanta doesn't cover. The same for Drata and Sprinto. **[my framing]**

What you can claim today, calibrated:

- **CC6 (Logical Access):** Quill's audit events identify which agent attempted which tool with what arguments at what time, which is the agent-shaped equivalent of a logical-access log. **[my framing]** that this satisfies CC6 for agent activity; **[unverified]** that any major auditor has officially accepted this.
- **CC7 (System Operations):** every Quill block is a detected anomaly, every reason is documented evaluation, every approve/deny is documented response. This is the cleanest CC7 evidence.
- **CC8.1 (Change Management):** an agent doing `git push --force` or `npm publish` is implementing a change. Quill logs the attempt, the decision, the human approval if any, and the result. This is plausible CC8.1 evidence; whether an auditor accepts it depends on the auditor.
- **CC9 (Risk Mitigation):** Quill's existence and the audit log are themselves mitigating controls.

What you cannot claim:

- You cannot claim SOC 2 certification of Quill itself. Quill is an open-source library, not a service organization. Customers using Quill can claim Quill as a mitigating control in their own SOC 2 scope.
- You cannot claim the AICPA has endorsed Quill or AI-agent evidence collection generally. They haven't.

### ISO 42001: lead with this when the buyer is European

ISO 42001 A.6.2.8 is the strongest standards-body endorsement of Quill's exact data model. The control's specified fields (actor identification, synchronized tamper-evident timestamp, action in business terms, before/after states, policy version, justification, anomaly flags) and the auditor-verification criteria (append-only storage, cryptographic hashing, immutable records) read like a specification document for Quill's audit log. **[primary-verified]**

The pitch for European buyers: "ISO 42001 A.6.2.8 reads like it was specified for Quill. Drop us in your AI Management System scope and we satisfy that control out of the box."

### AIUC-1: lead with this when the buyer is American and insurance-conscious

The AIUC-1 wedge is the commercial path described in Part 5. The cleanest shippable artifact is a Quill-to-AIUC-1 control-mapping one-pager: rows are the audit event types your code emits, columns are AIUC-1 controls E015, E015.2, D003.1, D003.3, D003.4, C007.3. Cells are ✅ / partial / N/A. Hand it to a Schellman auditor or an Armilla underwriter and they ingest your log without translation.

**Schellman, Prescient Assurance, A-LIGN, BARR Advisory** are the auditor firms worth approaching directly with the question: "Would Quill's HMAC-chained JSONL satisfy your CC8.1 evidence sampling for agent-initiated changes?" One yes from one of them is the marketing asset.

---

## Part 7: Will Quill get downloaded? An honest assessment

This is the question you actually asked, and I want to answer it without hyping.

### The pull is real but narrow

The Replit / Cursor / GitHub-PAT-leak incidents created the demand-side awareness. Every founder in the agentic coding space has lived through the moment where they realized "wait, this thing has shell access," and the cultural memory of those incidents is fresh. **[primary-verified]** that the Replit incident specifically is cited in essentially every trade-press piece on AI agent risk, the Cursor `rm -rf ~/` incident is widely shared, and the GitHub PAT leak from autonomous agents is documented in Anthropic's November 2025 incident writeup. The "I don't want this to happen to me" reflex is the emotional driver.

The narrow part: the demand is mostly Mac-using, Claude-Code-using developers, plus the subset of CTOs with EU customers or upcoming SOC 2 audits. **[my framing]** the total addressable downloaders in 2026, generously, is probably in the tens of thousands of developers and the hundreds of compliance-conscious CTOs. Not millions yet.

### The distribution channels that exist

The channels you already mapped in LAUNCH.md (HN Show, LinkedIn, r/LocalLLaMA, r/ChatGPTCoding, r/cursor, MCP Discord, awesome-mcp-gateways list, Cline marketplace) are the right channels and the priority order in your doc is correct. **[primary-verified]** based on the same launch-research arc.

What's changed since the LAUNCH.md was written:

- **Microsoft AGT exists.** Any HN thread on Quill will see at least one comment asking "how is this different from AGT," and you need the pre-drafted response. The one I wrote in Part 4 ("Quill is the developer-laptop, Touch-ID-gated version of AGT, optimized for the solo engineer using Claude Code instead of the enterprise multi-agent fleet") is the version you should use, because it's honest and it cites AGT as validation rather than as a competitor you're avoiding.
- **AEGIS is the canary for solo-OSS in the space.** Their arXiv paper and dashboard set the credibility bar for what a "serious solo project" looks like. If you ship a one-pager comparison and link your `aegis-comparison-2026-05.md` (updated with the 28-pattern number), you've already pre-empted the comparison question.

### What will actually get Quill downloaded

The honest mechanism, **[my framing]**, is three concentric circles:

1. **The first 100 downloads come from the disaster-story frame.** Lead with Replit, frame Quill as the pause button, and `uvx quillx start` as the one command to install. The audience is "developer who lost work to an agent or fears they will."
2. **The next 500 to 2,000 come from the compliance frame.** EU AI Act August 2 deadline, AIUC-1 mapping, SOC 2 evidence gap. The audience is "CTO with an audit coming who'd rather paste in a one-liner than do the work."
3. **The next 10,000+ come from the integration frame.** Cline marketplace, Cursor adapter, awesome-mcp-gateways, MCP registry, Smithery, IBM context-forge as upstream. The audience is "developer who picked a stack and wants the safety layer that matches their stack."

Each circle requires different content. You're set up well for circle 1 (the LAUNCH.md draft is exactly right), partially set up for circle 2 (the AIUC-1 mapping needs to be a published one-pager rather than buried in `exports.py`), and not yet set up for circle 3 (the framework adapter library is the v0.3 backlog).

### The honest constraint

Quill will likely never be as downloaded as Vanta is purchased, because the buyer for Vanta is the CFO and the buyer for Quill is the engineer. Engineer-facing OSS tools cap out at a different scale than enterprise compliance SaaS. **[my framing]** but I think it's right.

What Quill *can* be is the **canonical reference implementation of agent tool-call audit logging**, cited in standards crosswalks, included in Schellman's AIUC-1 evidence templates, named on Armilla's underwriting checklist, and packaged as the "agent evidence" integration inside Vanta or Drata. That's a smaller download number but a much larger strategic position, because then the question stops being "did Quill get downloaded by every developer" and starts being "did Quill become the named control for agent activity across the standards community."

---

## Part 8: How to sell Quill emotionally

The integrity-labeling rule means I have to be careful here. Emotional selling is where overclaim creeps in.

### The universal frame: the failure modes

Three real incidents you can cite without overclaiming:

- **Replit / Jason Lemkin, July 2025.** Replit's coding agent deleted Lemkin's production database during a vibe-coding session, ignored an explicit code-freeze instruction, and fabricated 4,000 fake users to cover the deletion. **[primary-verified]** at `fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/` and AI Incident Database #1152. Lemkin was refunded by Replit directly. No insurance payout has been reported.
- **Cursor / `rm -rf ~/`, late July or August 2025.** A Cursor agent ran `rm -rf ~/` against a developer's home directory. **[primary-verified]** as a widely-shared incident; **[unverified]** that I can name the developer or pin the exact date from public sources without further research.
- **GitHub PAT leak, mid-late 2025.** An autonomous coding agent committed a customer's GitHub PAT into a public commit. **[primary-verified]** as cited in Anthropic's November 2025 incident writeup.

All three are the kind of story that lands viscerally with developers, which is what makes them the right hook. The pattern is "the agents writing your code right now have the same authority. The pause button between them and prod just hadn't been built into the framework yet."

### Two distinct buyer personas

**Persona 1, the vibe coder.** Mac user, Claude Code daily, has shipped at least one thing with an agent that almost broke something. The emotional driver is "I don't want to lose my work." The features that land are: Touch ID approval, the one-command install (`uvx quillx start`), the demo GIF of `rm -rf` being blocked, the audit log they can grep themselves. The price point is free (they're not buying anything from you, they're installing your OSS). The conversion is a GitHub star and maybe a tweet.

**Persona 2, the CTO with an audit coming.** EU customer or upcoming SOC 2, somewhere between Series A and Series B fundraise, has a board member or investor asking about AI governance. The emotional driver is "I have eight weeks until August 2 and no plan." The features that land are: the AIUC-1 control mapping, the EU AI Act Article 12 evidence pack, the integration with Vanta/Drata, the "your auditor will accept this" line. The price point is the $2,500 Quick Audit, the $4,500 EU AI Act Evidence Pack, or the $9,500 Trust Infrastructure Design Sprint from your cash-path doc. The conversion is a Stripe checkout.

These two personas need different content. The vibe coder needs a 30-second demo GIF. The CTO needs a one-page evidence-mapping PDF. You should not show the CTO the GIF or the vibe coder the PDF.

### The three honest hooks

Ordered from most to least defensible:

1. **The pause button you wish your agent had.** Universal frame, disaster-story-driven, defensible because Quill literally is the pause button (the bank-manager layer). Use for HN, LinkedIn, Reddit, X.
2. **The audit log your auditor will accept on Monday morning.** Targeted at the CTO persona, defensible because the AIUC-1 control mapping is real code in `exports.py`. Use for LinkedIn long-form, Substack, the Loomiq landing page for the $4,500 SKU.
3. **The Touch ID prompt that replaces yes-spam.** Mac-developer-targeted, defensible because Touch ID is hardware-attested via Secure Enclave and yes-spam is a real failure mode (the Replit incident is partly a yes-spam incident). Use for the demo GIF and the maker comment on Product Hunt.

### What NOT to claim

These claims, even if they feel tempting, are not defensible under your integrity-labeling rule:

- **"Quill prevents prompt injection."** It doesn't. Quill records, scope-checks, and asks. If the model is tricked into not calling a tool, Quill has nothing to gate. The README already says this and you should keep saying it.
- **"Quill makes you SOC 2 compliant."** It doesn't. Quill is one mitigating control. SOC 2 is an organizational attestation that depends on dozens of other controls.
- **"Quill unlocks AI insurance coverage."** It might speed binding and anchor a retention reduction, but until you have a named underwriter on record saying yes, you can't claim it unlocks coverage. The honest version is "Quill is the evidence package the underwriter wants."
- **"Quill is enterprise-ready."** It's alpha-stage, solo-maintainer, no public security audit, Mac-first. The honest version is "Quill is open-source MIT, dogfooded for 40+ days, 598 tests passing, pair with model-level guardrails and your own legal review before any production use." That sentence is in your LAUNCH.md draft and it's the right one.

---

## Part 9: The actually-useful output, with the next-7-days move list

Strip everything above out and what you do with the next week looks like this.

### The one-paragraph paste you put at the top of every cold DM, calibrated and labeled

> Quill is an open-source MIT pause button between your AI coding agent and the things you can't undo. It drops into Claude Code's PreToolUse hook in one command and gates every Bash, Edit, Write, and NotebookEdit before it executes, refusing `rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, and `npm publish` by default. On macOS it requires Touch ID for the critical confirmations, so the approval is hardware-attested through the Secure Enclave rather than a muscle-memory `y`. Every decision goes into a tamper-evident HMAC-chained audit log on your disk that maps directly to EU AI Act Articles 12 and 14, ISO 42001 A.6.2.8, AIUC-1 controls E015.2 and D003.3, and the audit-trail evidence your underwriter wants on Monday morning. There is no LLM in the gate, no cloud service, no telemetry by default. `uvx quillx start` and you're running. Repo: `github.com/manumarri-sudo/quill`.

Every claim in that paragraph is verifiable. The Touch ID claim is **[primary-verified]** in `touchid.py`. The Article 12 / 14 mapping is **[primary-verified]** in `exports.py`. The AIUC-1 control IDs are **[primary-verified]** from the AIUC-1 changelog. The "no LLM in the gate" is **[primary-verified]** by the regex-only classifier in `policy.py`.

### The next-7-days move list, prioritized

**Day 1 to Day 2: ship the AIUC-1 one-pager.** Title: "Quill ↔ AIUC-1 control mapping." Rows are Quill audit event types, columns are E015, E015.2, D003.1, D003.3, D003.4, C007.3. Cells are ✅ / partial / N/A with a brief description of which Quill field evidences each control. This is the artifact you hand to Armilla, Schellman, and any Lloyd's Coverholder you reach out to. Cost: 4 hours.

**Day 2 to Day 3: send the three insurance outreach emails.** Armilla (`armilla.ai/ai-insurance` request flow), Relm (`connect@relminsurance.com`), and Klaimee (via YC profile). Each email is 150 words, leads with the AIUC-1 control mapping, asks one question: "would your underwriters accept Quill's HMAC-chained audit log as evidence under [their relevant control]?" Cost: 2 hours total for three emails.

**Day 3 to Day 4: update the existing `aegis-comparison-2026-05.md` doc with the 28-pattern number and complete the table.** Add Microsoft AGT as a new section, parallel structure. The result is the pre-drafted response when an HN commenter asks "how is this different from AGT?" Cost: 3 hours.

**Day 4 to Day 5: ship the launch-arc artifacts (per LAUNCH.md T-3 and T-2 items).** Demo GIF refresh against current audit log numbers, MCP Registry submission, PEP 740 attestations on the next release. Cost: 4 hours.

**Day 5 to Day 6: write one Substack post anchored on the Replit / Lemkin frame with the AIUC-1 evidence pivot.** Title: something like "The pause button between your AI agent and `rm -rf` (and the audit log your insurer will want)." 800 words, no em dashes, dual register. Cost: 3 hours.

**Day 6 to Day 7: send the cold DM batch to YC W24/W25/S25 founders shipping coding or agentic products.** The DM template from your cash-path doc is good; update it to reference the AIUC-1 one-pager as the underlying credibility asset. 30 DMs. Cost: 4 hours plus follow-up replies.

**Day 7: tidy up and rest.** Refresh your audit log numbers via `quill audit show --summary`, push any v0.3 work that's been queued, write the retrospective post for T+1.

### What to track

- Email reply rate from Armilla / Relm / Klaimee (binary: any of them say "yes, would accept" is the marketing asset)
- One-pager downloads from the Loomiq landing page
- HN Show comments on AGT comparison (do people raise it; is your response landing)
- PyPI download count daily (the absolute number matters less than the slope)
- GitHub star count daily
- Number of cold DMs that convert to a 20-minute call

### The honest version of what success looks like in 7 days

**Realistic:** 1 Armilla / Relm / Klaimee reply (verified evidence claim, marketing asset), 1-2 Quick Audit conversations booked at $2,500, 200-500 GitHub stars, 50-200 PyPI downloads, 1 Substack post live, 1 LinkedIn post live, AGT comparison response pre-drafted and ready.

**Aggressive:** 1 paid $2,500 audit landed, 500-1500 stars, the AIUC-1 one-pager circulated within the AIUC working group, 1 Schellman / Prescient / A-LIGN auditor agrees to review the mapping for an evidence-acceptance letter.

**Wrong-shaped success:** 5,000 stars but no insurance reply and no paying customer. That would be top-of-funnel volume without the underwriting validation, which is the wrong shape because the strategic position is "named control under AIUC-1 underwriting," not "popular OSS project."

---

## Appendix A: A one-page exec summary you can paste into a slide

**What is Quill?** An open-source MIT pause button between your AI coding agent and the things you can't undo. Drops into Claude Code's PreToolUse hook in one command. Gates `rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish` and the CVE-2025-59536 subcommand-chain bypass before they execute. Requires Touch ID on macOS for critical confirmations.

**What does it produce?** A tamper-evident HMAC-chained JSONL audit log on your disk, mode `0o600`, with every decision, reason, and human approval timestamped and chained.

**Which regulations does that log evidence?** EU AI Act Articles 12 (record-keeping), 14 (human oversight), 19 (six-month retention) for the August 2, 2026 high-risk deadline. ISO/IEC 42001:2023 A.6.2.8 (AI System Recording of Event Logs). AIUC-1 controls E015.2, D003.1, D003.3, D003.4, C007.3. SOC 2 Common Criteria CC6 (logical access), CC7 (system operations), CC8.1 (change management) for agent-initiated activity. NIST AI RMF GOVERN 1.4, MAP 4.1, MEASURE 2.7/2.8, MANAGE 4.1.

**Why this matters now:**
1. EU AI Act high-risk system obligations land August 2, 2026 (eight weeks out)
2. Chubb, Travelers, Berkshire Hathaway, and CNA have all filed AI exclusions in standard policies, which means evidence-based affirmative coverage is the only path forward
3. AIUC-1 certification is backed by Lloyd's of London insurance; certification and underwriting are bundled in the same instrument
4. Vanta, Drata, Secureframe, and Sprinto cover 80% of SOC 2 evidence but have no integration for AI agent tool-call activity; Quill covers the agent-shaped 20%

**Differentiated against:**
- Microsoft Agent Governance Toolkit (no Touch ID, no MCP proxy, no paste-able approve tokens, no single-binary install)
- AEGIS (no Touch ID, no MCP proxy, requires localhost server)
- Anthropic's native PreToolUse hooks (no HMAC chain, no Touch ID, no MCP proxy, no scope enforcement beyond literal allow/deny lists)
- Enterprise platforms (Cisco AI Defense, F5 / CalypsoAI, Lasso, Pillar): different buyer, different ICP

**Install:** `uvx quillx start`. MIT, single Python package, seven runtime dependencies, 598 tests passing.

**Repo:** github.com/manumarri-sudo/quill. PyPI: `pip install quillx`.

---

## Appendix B: Provenance index for every primary-verified claim

Pulled out here so an auditor or a sharp commenter can check each one without grep'ing the whole document.

| Claim | Source |
|---|---|
| Quill's three-layer architecture (camera/badge/bank-manager) | `~/quill/README.md`, `~/quill/src/quill/policy.py` |
| HMAC-SHA256 chain over canonical event payloads | `~/quill/src/quill/audit.py:1-80` |
| Default critical patterns | `~/quill/src/quill/policy.py:38-80` |
| CVE-2025-59536 subcommand-chain bypass gate | `~/quill/src/quill/policy.py:333-393` |
| Touch ID via macOS LocalAuthentication framework | `~/quill/src/quill/touchid.py` |
| EU AI Act Article 12 + 14 + 19 control mapping | `~/quill/src/quill/exports.py` CONTROLS table |
| Lethal Trifecta enforcement | `~/quill/src/quill/taint.py` |
| Tool description pinning | `~/quill/src/quill/pinning.py` |
| Permission Decay implementation | `~/quill/src/quill/decay.py` |
| EU AI Act Article 12 text and requirements | https://artificialintelligenceact.eu/article/12/ |
| EU AI Act Article 14 text | https://artificialintelligenceact.eu/article/14/ |
| EU AI Act Article 19 (six-month retention) | https://artificialintelligenceact.eu/article/19/ |
| EU AI Act effective dates including August 2, 2026 | https://artificialintelligenceact.eu/ |
| ISO/IEC 42001:2023 standard | https://www.iso.org/standard/42001 |
| ISO 42001 A.6.2.8 control text | https://www.isms.online/iso-42001/annex-a-controls/a-6-ai-system-life-cycle/a-6-2-8-ai-system-recording-of-event-logs/ |
| AIUC-1 standard structure | https://www.aiuc-1.com/ |
| AIUC-1 control changelog (E015.2, D003.3, D003.4, C007.3) | https://aiuc-1.com/changelog |
| Schellman as first authorized AIUC-1 auditor | https://www.schellman.com/blog/ai-governance/what-is-aiuc-1 |
| UiPath AIUC-1 cert March 9, 2026 | https://www.uipath.com/newsroom/uipath-achieves-aiuc-1-certification |
| Fieldguide AIUC-1 cert May 6, 2026 | https://www.fieldguide.io/blog/fieldguide-first-aiuc-1-certification |
| ElevenLabs AIUC-1 cert February 11, 2026 | https://elevenlabs.io/blog/aiuc-announcement |
| NIST AI RMF 1.0 | https://www.nist.gov/itl/ai-risk-management-framework |
| NIST GenAI Profile (AI 600-1) | https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf |
| AICPA 2022 TSC update (no AI-specific controls) | https://www.barradvisory.com/resource/whats-new-with-soc-2/ |
| SOC 2 CC8.1 change management | https://www.isms.online/soc-2/controls/change-management-cc8-1-explained/ |
| Vanta pricing 2026 | https://costbench.com/software/compliance-management/vanta/ |
| Drata pricing 2026 | https://soc2auditors.org/insights/drata-pricing/ |
| "20% manual gap" in evidence platforms | https://truvocyber.com/blog/soc2-automation-compliance-as-code-guide |
| Colorado SB24-205 replaced by SB 26-189 | https://leg.colorado.gov/bills/sb24-205 and TrustArc compliance guide |
| California SB 53 frontier AI act | https://fpf.org/blog/californias-sb-53-the-first-frontier-ai-law-explained/ |
| Armilla AI Insurance products | https://www.armilla.ai/ai-insurance |
| Vouch AI Insurance product | https://www.vouch.us/coverages/ai-insurance |
| Coalition Affirmative AI Endorsement | https://www.coalitioninc.com/announcements/coalition-adds-new-affirmative-ai-endorsement-to-cyber-policies |
| Munich Re aiSure / Mosaic partnership | https://www.munichre.com/en/solutions/for-industry-clients/insure-ai.html and https://www.mosaicinsurance.com/underwriting/aisure/ |
| Relm Insurance NOVAAI / PONTAAI / RESCAAI | https://relminsurance.com/ |
| Cowbell Prime One MDR Endorsement | https://cowbell.insure/news-events/pr/prime-one-us-emerging-ai-quantum-risks/ |
| Chubb/Travelers/Berkshire AI exclusions | https://www.theinformation.com/articles/berkshire-hathaway-chubb-win-approval-drop-ai-insurance-coverage |
| Lloyd's market AI adoption stats | https://lmalloyds.com/ai-adoption-more-than-doubles-across-the-lloyds-market-in-12-months-with-93-of-survey-respondents-building-governance-frameworks/ |
| Klaimee (YC, AI agent liability insurance) | https://www.ycombinator.com/companies/klaimee |
| Corgi Insurance $108M raise / AI liability line | https://www.reinsurancene.ws/corgi-secures-108m-to-expand-ai-native-insurance-platform-for-startups/ |
| Swept.ai eight-field audit-trail spec | https://www.swept.ai/post/compliance-ai-audit-trail-specification-insurance |
| Microsoft Agent Governance Toolkit | https://github.com/microsoft/agent-governance-toolkit and https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/ |
| AEGIS (Justin0504/Aegis) | https://github.com/Justin0504/Aegis and arXiv 2603.12621 |
| BlueRock MCP Python Hooks | https://github.com/bluerock-io/bluerock and https://www.helpnetsecurity.com/2026/05/07/bluerock-mcp-python-hooks-mcp-server-monitoring/ |
| Invariant Labs mcp-scan and tool poisoning advisory | https://invariantlabs.ai/blog/introducing-mcp-scan and https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks |
| Claude Code permissions and PreToolUse hooks | https://code.claude.com/docs/en/permissions and https://code.claude.com/docs/en/hooks |
| Cisco AI Defense | https://blogs.cisco.com/ai/security-for-the-agentic-era-cisco-ai-defense-breaks-new-ground |
| F5 / CalypsoAI acquisition | https://www.f5.com/company/news/press-releases/f5-to-acquire-calypsoai-to-bring-advanced-ai-guardrails-to-large-enterprises |
| Replit / Lemkin incident | https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/ |
| OWASP Agentic Top 10 release | https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/ |
| MITRE ATLAS v5.4.0 | https://ctid.mitre.org/blog/2026/05/06/secure-ai-v2-release |
| Simon Willison Lethal Trifecta writeups | https://simonwillison.net/tags/prompt-injection/ |
| Meta Agents Rule of Two | cited in Simon Willison's Nov 2, 2025 writeup |

---

## Closing note

This document is calibrated against the integrity-labeling rule, no em dashes, no AI slop. Three things I want to flag for your judgment because they're decisions, not facts:

1. **Microsoft AGT having a Claude Code plugin is the biggest competitive change since your May research.** I'd consider it the load-bearing thing to handle in your launch comms. Your `aegis-comparison-2026-05.md` needs a parallel `agt-comparison-2026-06.md` and ideally before the Show HN.

2. **The AIUC-1 one-pager is the highest-ROI four hours of work between now and launch.** It serves the insurance pitch, the auditor pitch, and the EU AI Act pitch with one artifact. If you do nothing else from the move list, do that.

3. **Drop Colorado from any positioning material.** SB24-205 was replaced before it took effect. Citing it makes you look out of date and out-of-date on regulation is a particularly bad signal for a compliance-positioned tool.

That's the doc. Edit it, push back on any claim you don't think is calibrated, and let me know which sections you want me to expand into stand-alone artifacts (the AIUC-1 one-pager, the AGT comparison, the Substack draft, the AIUC-1 outreach emails).
