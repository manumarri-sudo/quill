# Quill messaging guide

**For:** anyone (Manu, future contributors, contracted copywriters) writing public-facing content about Quill.
**Status:** these are the canonical hooks, frames, and don't-claim guardrails. Pull from this doc before drafting a Substack post, a LinkedIn post, a tweet, a conference abstract, a press response, or a sales email. If you find yourself reaching for a claim that isn't here, run it past the [integrity-labeling discipline](../../CLAUDE.md) first.

---

## The three concentric circles of who installs Quill

Different audiences need different framing. Don't try to write one post that converts all three; you'll convert none of them.

### Circle 1 (first ~100 stars): the vibe coder
**Who:** Mac developer, Claude Code daily, shipped at least one agentic thing that almost broke something. Has the muscle memory of "wait, the agent has shell access?"
**Driver:** *"I don't want to lose my work."*
**The right framing:** the disaster story (Replit / Lemkin database deletion, Cursor `rm -rf ~/`, GitHub PAT leak, Anthropic November 2025 hijack). Lead with someone else's lost weekend.
**The right hook:** "the pause button you wish your agent had."
**The right artifact:** the 30-second demo GIF showing `rm -rf` being blocked + Touch ID approval.
**The right CTA:** `uvx quillx start`.
**Channels:** Show HN, X / Twitter, r/LocalLLaMA, r/cursor, r/ChatGPTCoding, MCP Discord.
**Conversion target:** GitHub star, install, optional tweet.

### Circle 2 (next ~500 to 2,000 stars): the CTO with an audit coming
**Who:** Series A to B founder or CTO. Has an EU customer, an upcoming SOC 2, or a board member asking about AI governance. Booth / Wharton / non-technical MBA grad on the comp/risk side of the org.
**Driver:** *"I have eight weeks until August 2 and no plan."*
**The right framing:** the EU AI Act August 2 deadline, the AIUC-1 + Lloyd's bundling, the Vanta-20%-gap. Lead with the regulatory calendar.
**The right hook:** "the audit log your auditor will accept on Monday morning."
**The right artifact:** the one-page AIUC-1 control mapping ([`aiuc-1-mapping.md`](aiuc-1-mapping.md)) printed to PDF.
**The right CTA:** "deploy Quill against your stack, run it for 30 days, hand your auditor the evidence pack."
**Channels:** LinkedIn long-form, Substack, founder cold DMs, AIUC-1 / Schellman / Armilla outreach.
**Conversion target:** Quick Audit conversation (when Loomiq paid surface goes live; until then, just a GitHub star + intro).

### Circle 3 (10K+ stars): the integration buyer
**Who:** Developer who has already picked a stack (LangChain / CrewAI / Cline / Aider / Continue / Windsurf) and wants the safety layer that fits.
**Driver:** *"I'm shipping an agent product and need governance plumbing that works with what I already use."*
**The right framing:** integration depth, framework adapters, MCP-proxy compatibility, Cline marketplace, awesome-mcp-gateways list.
**The right hook:** "the integration that gives you the audit log your customers will ask about."
**The right artifact:** the docs page for their specific client ([`docs/clients.md`](../clients.md)).
**The right CTA:** "wire `quill serve` into your `mcpServers` config; rest of your stack unchanged."
**Channels:** ecosystem listings (Smithery, mcp.so, awesome-mcp-servers PR), client-specific subreddits and Discords.
**Conversion target:** integration install + PR upstream to add Quill as a recommended adapter.

**The point of separating them:** the vibe coder doesn't care about EU AI Act; the CTO doesn't care about Touch ID UX; the integration buyer cares about whichever framework adapter they're on. Write to one circle per post.

---

## The three honest hooks, ranked by defensibility

In order from most-to-least defensible. Higher in the list = safer to use in front of hostile / sharp readers (HN, security Twitter, auditor calls).

### Hook 1 (most defensible): "The pause button you wish your agent had."
**Why it works:** universal frame, disaster-story-driven, defensible because Quill literally *is* the pause button (the bank-manager layer enforces it deterministically). Use this anywhere the audience may be skeptical or hostile.
**Use for:** Show HN title, repo "About" string, GitHub repo tagline, generic LinkedIn / Substack hero, conference abstracts.

### Hook 2 (very defensible): "The audit log your auditor will accept on Monday morning."
**Why it works:** targeted at CTO Circle 2 persona; defensible because the AIUC-1 control mapping is real code in [`src/quill/exports.py`](../../src/quill/exports.py) and the evidence-pack PDF is verifiable. Don't use this in front of an actual AIUC-1 auditor without the explicit caveat that Quill is *one evidence source*, not certification; the auditor must still sample, opine, and sign.
**Use for:** LinkedIn long-form, Substack, future Loomiq landing page once paid surface goes live, CTO cold emails.

### Hook 3 (defensible with one caveat): "The Touch ID prompt that replaces yes-spam."
**Why it works:** Mac-developer-targeted, defensible because Touch ID is hardware-attested via the Secure Enclave and yes-spam is a real failure mode (the Replit incident is partly a yes-spam incident).
**Caveat:** Touch ID is macOS-only. On Linux / Windows the hook becomes "the type-the-action-name prompt that replaces yes-spam," which is still defensible but slightly weaker because typing isn't hardware-attested.
**Use for:** the demo GIF, Product Hunt maker comment, Mac-specific developer Discords / channels.

---

## What NOT to claim, ever

These claims, even if they feel tempting, are not defensible under the integrity-labeling rule.

| Tempting claim | Why it fails | The honest version |
|---|---|---|
| "Quill prevents prompt injection." | Untrue. Quill refuses the *consequence* (the exfil call) when the trifecta closes; it does not prevent the model from being injected. Pair with model-level guardrails. | "Quill defends against the worst case of prompt injection by enforcing the Lethal Trifecta deterministically." |
| "Quill makes you SOC 2 compliant." | Untrue. Quill is one mitigating control. SOC 2 is an organizational attestation requiring dozens of other controls. | "Quill produces SOC 2 CC6 / CC7 / CC8.1 evidence for AI agent activity that Vanta-class platforms can't reach." |
| "Quill unlocks AI insurance coverage." | Untrue. Carriers writing affirmative AI coverage will write it with or without Quill. | "Quill is the evidence package the underwriter wants on Monday morning. It shortens binding from weeks to days and gives you a control to anchor a retention concession." |
| "Quill is enterprise-ready." | Quill is alpha-stage, solo-maintainer, no public security audit, Mac-first. | "Quill is open-source MIT, dogfooded for 6+ months, 700+ tests. Pair with model-level guardrails and your own legal review before production use." |
| "Quill is the only tool that does X." | Almost always provable false. | Use the calibrated comparison table in [`why-quill-vs-others.md`](why-quill-vs-others.md) and the verifiable wedge list at the bottom. |

---

## The strategic position, in one sentence (memorize this)

> **"Quill is the canonical reference implementation of agent tool-call audit logging."**

Not the most downloaded. Not the most enterprise-deployed. **The named control that standards crosswalks cite, that AIUC-1 evidence templates include, that Armilla underwriting checklists name, that Vanta/Drata catalog as the agent-activity integration.** That's a smaller download number than "consumer SaaS scale" but a much larger strategic position. Optimize content for that outcome, not for raw star count.

---

## The provenance label discipline (load-bearing)

Every public-facing factual claim from Quill must be classifiable into one of four labels. The labels live in the writer's drafting notes, not necessarily in the published prose. If a claim cannot be labeled `[primary-verified]` or `[secondary-inferred]`, it must be hedged or removed.

- **`[primary-verified]`**: read directly in the codebase or on the official site of a regulator, standards body, or vendor.
- **`[secondary-inferred]`**: from trade press, analyst coverage, or a vendor's marketing.
- **`[my framing]`**: the writer's own description, opinion, or generalization. Not a factual claim per se; the reader can decide.
- **`[unverified]`**: included because the asker asked, or because it sounds true, but the writer has not verified. Must be flagged before publishing.

When the writer drafts a "punchier" or "hooky" version of any claim, re-run the labels on the new version. Hooks do not get a verification pass. The hook is not allowed to launder the underlying claim.

---

## Sentence-rhythm rules (Manu's published voice)

These apply to every Quill output that goes out under Manu's name or Loomiq's name. Adopted from `CLAUDE.md` and the established voice across the existing Substack and LinkedIn posts.

- **No em dashes.** Use commas, parentheses, or full stops. Em dashes look AI-shaped and Manu has flagged them as a calibration signal.
- **Flowing sentences over choppy ones.** A run-on sentence that holds together logically is better than three short declarative sentences stacked. Connect with "because," "which," "and so," "although," "while," "until."
- **Punchy single-sentence beats for emphasis, not as default rhythm.** Save them for closers.
- **Dual register: vibe coder + CTO in the same paragraph.** Manu's voice translates between technical depth and buyer-side language without losing either.

---

## Pre-publish checklist

Before any public artifact ships:

- [ ] Hook chosen from the three honest hooks (not invented on the fly)
- [ ] Audience identified as Circle 1, 2, or 3 (not "everyone")
- [ ] Every factual claim labeled per the provenance discipline
- [ ] None of the "what NOT to claim" appears anywhere
- [ ] Sentence-rhythm rules followed (no em dashes, flowing prose, dual register where appropriate)
- [ ] Calibrated comparison: if a competitor is named, their strengths come first, then Quill's wedge
- [ ] CTA matches the audience's circle (`uvx quillx start` for Circle 1, AIUC-1 mapping PDF for Circle 2, integration docs for Circle 3)
- [ ] Source URLs included for every primary-verified claim

The single best heuristic: would Simon Willison, a Schellman auditor, and a CTO with an upcoming Series B all walk away from the artifact with their assumptions about Quill *roughly aligned*? If yes, ship. If not, the artifact is overclaiming somewhere.
