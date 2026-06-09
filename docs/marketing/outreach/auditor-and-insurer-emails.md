# Cold outreach drafts: three auditors, three insurers

**Purpose:** open conversations that produce one of two assets:
- An accredited auditor's written acceptance that Quill's audit log is sampling-grade evidence under specific controls
- An AI-native insurance underwriter's confirmation that Quill's log shape matches their binding evidence requirement

**One yes from any of these six closes the biggest credibility gap before the August 2 deadline.**

Each email is ~180 words, leads with the recipient's published work, names the specific control or product it maps to, and asks one closed question. Each one attaches the [AIUC-1 control mapping one-pager](../aiuc-1-mapping.md).

---

## 1. Schellman (auditor) — the highest-priority send

**Send to:** `info@schellman.com` (general inquiry) plus check LinkedIn for the Director of AI Assurance or Avani Desai (CEO) for a warm-route attempt
**Subject:** AIUC-1 evidence sampling: open-source MIT tool that produces it

> Hi Schellman team,
>
> I'm Manu Marri, solo founder at Loomiq. Saw the UiPath AIUC-1
> certification announcement and the Fieldguide cert announcement in May.
> The Accountability domain controls you sampled there (E015, E015.2,
> D003.1, D003.3, D003.4, C007.3) are the exact shape of evidence my
> open-source tool produces.
>
> Quill is an MIT-licensed Python package that sits between an AI coding
> agent (Claude Code, Cursor, others) and the agent's tool dispatch path.
> Every tool call attempt, every gate decision, every human approval
> lands in an HMAC-chained JSONL audit log on the deployer's disk,
> verifiable in 60 seconds with `quill audit verify`. Repo at
> github.com/manumarri-sudo/quill, 700+ tests, dogfooded for 6 months.
>
> One question: would your auditors accept Quill's log shape as
> sampling-grade evidence under E015.2 and D003.3? Attached is the full
> per-control crosswalk. Not asking for a formal opinion, just whether
> the shape works.
>
> Happy to do a 30-minute walkthrough or to send the dogfood log itself.
>
> Manu Marri
> manu.marri@gmail.com
> Booth MBA 2025 · ex-Accenture Strategy · Loomiq LLC

---

## 2. BARR Advisory (auditor)

**Send to:** `info@barradvisory.com` plus look for Brad Hibbert (CEO) on LinkedIn for warm-route
**Subject:** SOC 2 CC8.1 evidence for AI agent activity — open-source artifact

> Hi BARR team,
>
> I'm Manu Marri, ex-Accenture Strategy, Booth MBA 2025. Read your AICPA
> 2022 TSC update writeup last month, specifically the points-of-focus
> broadening for "logical access" to cover contractors and vendors. The
> framing applies cleanly to AI agent activity, but the AICPA hasn't
> issued AI-specific TSC, so auditors are being asked to attest to
> agent behavior without a framework opinion to anchor on.
>
> I've built Quill, an open-source MIT artifact that records every AI
> agent tool dispatch into an HMAC-chained tamper-evident audit log on
> the deployer's disk. The format maps directly onto CC6.1 / CC7.2 /
> CC7.3 / CC7.4 / CC8.1 evidence shapes. github.com/manumarri-sudo/quill.
>
> One question: in an active SOC 2 engagement where the customer deploys
> an AI coding agent in their dev pipeline, would Quill's log be a
> credible CC8.1 evidence source for the agent-initiated changes? I'm
> not asking for endorsement, I'm asking whether the shape matches your
> sampling discipline.
>
> 20-minute call this week works for me if useful. Otherwise the AIUC-1
> mapping one-pager is attached for asynchronous review.
>
> Manu

---

## 3. A-LIGN (auditor)

**Send to:** `info@a-lign.com` plus Scott Price (CEO) on LinkedIn
**Subject:** AI agent activity under SOC 2 CC8.1 — sampling-grade evidence?

> Hi A-LIGN team,
>
> I'm Manu Marri, solo founder of Loomiq LLC. Booth MBA, ex-Accenture
> strategy. I built Quill, an open-source MIT artifact that produces
> tamper-evident, HMAC-chained audit logs of every AI coding agent's
> tool dispatch. Repo at github.com/manumarri-sudo/quill.
>
> The reason I'm writing: the AICPA hasn't issued AI-specific TSC, but
> your audit teams are being asked by customers to attest to AI agent
> activity under the existing CC6 / CC7 / CC8 controls. Quill's log
> format covers timestamp, agent_id, tool_name, args_digest, decision,
> reason, and human approval evidence with a verifiable HMAC chain.
>
> Three questions, any of which is useful:
> 1. Would your auditors sample Quill's log as CC8.1 change-management
>    evidence for agent-initiated `git push` / `terraform apply` /
>    `kubectl apply` events?
> 2. Are you seeing customer demand for AI-agent activity attestation
>    in current SOC 2 engagements?
> 3. Is there a sample evidence requirement document A-LIGN publishes
>    that I could align Quill's output format to?
>
> 30-minute call works, or async via the attached AIUC-1 mapping doc.
>
> Manu Marri · manu.marri@gmail.com

---

## 4. Armilla AI (insurance) — the highest-asymmetric-upside send

**Send to:** `info@armilla.ai` via the Request Coverage form at https://www.armilla.ai/ai-insurance, OR LinkedIn-route to Karthik Ramakrishnan (CEO) or Dan Adamson (President)
**Subject:** AIUC-1 E015.2 evidence: open-source artifact that matches the standard's published shape

> Hi Armilla team,
>
> I'm Manu Marri, solo founder of Loomiq LLC. Watched the
> AIUC-1-backed-by-Lloyd's-of-London bundling closely; the certification-
> and-underwriting-in-one-instrument is structurally different from how
> ISO 42001 or NIST AI RMF have been treated by other carriers, and the
> precedent is interesting.
>
> The reason I'm writing: I've built Quill, an open-source MIT Python
> tool that produces HMAC-chained, tamper-evident audit logs of every
> AI agent tool dispatch. The output maps directly onto the AIUC-1
> Accountability domain controls Armilla underwrites against:
> E015 (log AI system activity), E015.2 (intermediate steps + tool calls
> + sub-agents), D003.1 / D003.3 / D003.4 (tool authorization, MCP call
> log, chained-operation approval), and C007.3 (human review workflow
> auditing). Repo at github.com/manumarri-sudo/quill.
>
> One question: would your underwriters accept Quill's log as binding
> evidence under E015.2 and D003.3 for an AI-platform insured? I'm
> attaching the full per-control crosswalk for asynchronous review;
> happy to walk it live if useful.
>
> If the answer is yes, the cleanest next step would be naming Quill as
> an evidence source in your underwriting workflow. Open to whatever
> structure fits Armilla's process.
>
> Manu Marri
> Booth MBA · ex-Accenture · manu.marri@gmail.com

---

## 5. Relm Insurance (insurance)

**Send to:** `connect@relminsurance.com` plus Joseph Ziolkowski (CEO) on LinkedIn for warm route
**Subject:** RESCAAI insureds and a binding-evidence question

> Hi Relm team,
>
> I'm Manu Marri, solo founder of Loomiq LLC, ex-Accenture strategy
> consultant, Booth MBA 2025. Followed Relm's January 2025 launch of
> NOVAAI / PONTAAI / RESCAAI closely; the RESCAAI product (organizations
> using third-party AI tools) covers exactly the buyer profile I work
> with most: YC-stage and Series-A startups shipping AI coding agents
> into production.
>
> I've built Quill, an open-source MIT Python tool that produces
> tamper-evident, HMAC-chained audit logs of every AI coding agent's
> tool dispatch. Output covers per-call timestamp, agent identification,
> tool name, args hash, gate decision, reason, and human approval. Repo
> at github.com/manumarri-sudo/quill.
>
> The reason for the email: RESCAAI's underwriting workflow needs
> evidence that the insured's AI tools are bounded and monitored. Quill
> produces that evidence at the developer-laptop layer in a format
> that's already auditor-shaped (maps to AIUC-1 E015.2 + D003.3 +
> D003.4; attached). Would your underwriters accept this as binding
> evidence for a RESCAAI submission?
>
> If yes, I'd love to talk about naming Quill as an evidence source in
> your underwriting checklist. If no, I'd love feedback on what's
> missing so I can ship it.
>
> Manu · manu.marri@gmail.com

---

## 6. Klaimee (insurance) — the smallest, most pilot-able

**Send to:** YC profile page at https://www.ycombinator.com/companies/klaimee — they list a contact channel there
**Subject:** Liability insurance for AI agents + tamper-evident agent activity logs

> Hi Klaimee team,
>
> Saw your YC profile: "Liability insurance for AI Agents. You deploy
> agents, we cover you." The framing is exactly the product-market shape
> I've been hoping someone would build, and the YC stamp suggests you're
> at the stage where shipping a pilot is faster than at a Lloyd's
> syndicate.
>
> Quick context: I'm Manu Marri, solo founder of Loomiq LLC, Booth MBA
> 2025, ex-Accenture strategy. I built Quill, an open-source MIT Python
> tool that produces HMAC-chained, tamper-evident audit logs of every
> AI coding agent's tool dispatch. Output covers tool attempts, gate
> decisions, blocked reasons, human approvals, and a chain integrity
> proof. Repo at github.com/manumarri-sudo/quill.
>
> The reason I'm writing: if you're looking for the binding-evidence
> shape that demonstrates an insured's AI agent was bounded and
> monitored, Quill is open-source and produces it today. I'd love to
> pilot the integration with one of your insureds, either by you
> referring a candidate or by walking through a synthetic underwriting
> scenario together.
>
> Free to talk this week. Or async via the attached AIUC-1 mapping doc.
>
> Manu Marri
> manu.marri@gmail.com

---

## Send order and timing

Per the cash-path doc, send all six within a single 3-day window so
the responses cluster. Tuesday morning (Eastern) is the highest open
rate for cold B2B outreach per published case studies. If any of the
six replies, that becomes the marketing asset on the Loomiq landing
page within a week.

If none reply within two weeks, follow up with a short
"checking in" message that references one new thing (case study,
podcast appearance, conference talk submission). Don't push twice; if
the second message goes silent, move on.

## What success looks like

- **Best**: one of the auditors says "yes, would sample." Their name
  goes on the Loomiq landing page (with permission) as social proof.
  Every subsequent sale converts faster because the credibility transfer
  is done.
- **Good**: one of the insurers says "we'd accept this in a submission."
  Same outcome.
- **Workable**: a warm referral, a 30-minute call that doesn't close
  but produces a named contact for re-engagement after the first paid
  customer.
- **Honest baseline**: cold-outreach reply rate for warm-credentialed
  senders to B2B audit and insurance firms runs roughly 1 in 5 to 1 in
  10 per published case studies. Six emails should produce 1-2 replies.
  Treat that as the model, not the forecast.
