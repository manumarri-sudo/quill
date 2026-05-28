# AEGIS vs Quill — pattern-library and architectural comparison

**Date:** 2026-05-27
**Status:** Headline architecture verified against the arxiv HTML on 2026-05-27. Per-category pattern map (Quill's regexes vs AEGIS's 22 patterns) still TODO and is the next pass.
**Author:** Manu Marri (Loomiq)
**Why this doc exists:** AEGIS is the closest direct competitor to Quill found after the May 7 field survey was written. Architecturally near-identical (signed/chained audit log, three-stage policy pipeline, human approval primitive), with a published pattern library and FP rate Quill does not yet match in published form. This doc maps Quill's `policy.py` regex set against AEGIS's published pattern categories so we can answer "how does Quill compare to AEGIS" with real numbers in launch comments and follow-on conversations.

## Primary sources

- **Paper:** *AEGIS: No Tool Call Left Unchecked — A Pre-Execution Firewall and Audit Layer for AI Agents*, https://arxiv.org/html/2603.12621v1
- **Authors:** Aojie Yuan (USC, aojieyua@usc.edu), Zhiyuan Su (UC Davis, azysu@ucdavis.edu), Yue Zhao (USC, yue.z@usc.edu) — verified against arxiv HTML 2026-05-27
- **Repo:** https://github.com/Justin0504/Aegis (MIT, owner GitHub username `Justin0504`)
- **License:** MIT
- **Verbatim quotes from the paper (verified 2026-05-27):**
  - Pattern library: *"Extracted strings are matched against 22 detection patterns in 7 categories"*. Table 1 of the paper breaks down: SQL Injection (7), Path Traversal (4), Shell Injection (4), Prompt Injection (3), Sensitive Files (2), Data Exfiltration (1), PII Leakage (1).
  - Framework support: *"The current implementation supports 9 Python frameworks (Anthropic, OpenAI, LangChain, CrewAI, Gemini, Bedrock, Mistral, LlamaIndex, and smolagents), 4 JS/TS frameworks, and Go."*
  - Approval tooling: *"The Compliance Cockpit (Figure 6) is a web-based operational dashboard for real-time activity monitoring, approval queues for high-risk actions, anomaly summaries, session-level trace inspection, and compliance-oriented export and reporting tools."*
  - Headline numbers: 48 attack instances blocked, 1.2% FP rate on benign calls, 8.3 ms median latency, three-stage pipeline (deep string extraction → content-first risk scanning → composable policy validation).

## Architectural deltas (no paper reading required)

| Dimension | AEGIS | Quill |
|---|---|---|
| Interception point | SDK wrappers across 14 frameworks | MCP proxy + Claude Code `PreToolUse` hook + Cursor 1.7+ pre-tool-call hook |
| Audit log signature | Ed25519 | HMAC-SHA256 (per-installation key) |
| Audit log structure | SHA-256 hash-chained | HMAC-chained JSONL |
| Audit log on-disk mode | unspecified in researcher summary | `0o600` enforced at creation |
| Cross-process concurrency | unspecified | POSIX `fcntl.flock(LOCK_EX)` + atomic `O_APPEND` |
| fsync discipline | unspecified | batched (16 entries / 250 ms) with force-fsync on `HIGH+` risk |
| Human approval primitive | Web "Compliance Cockpit" dashboard | Terminal y/N + type-to-confirm + macOS banner + Touch ID on Secure Enclave + paste-able one-shot approve tokens |
| Approval attestation | web auth (assumed) | Touch ID hardware-attested via macOS LocalAuthentication framework |
| Detection patterns | 22 across 7 categories | TO COUNT after reading paper |
| Published FP rate | 1.2% | not published |
| Validation corpus | 48 attack instances | 586 unit + integration tests; no separate attack-instance corpus |
| Median latency | 8.3 ms | benchmark via `tests/test_bench_hot_path.py` |
| License | MIT | MIT |
| Audience | enterprise compliance | individual developer / solo founder |
| Form factor | SDK + web cockpit | single Python package, no daemon, no web service |
| Standards alignment | unspecified | EU AI Act Art. 12 + Art. 14, AIUC-1, OWASP Agentic Top 10 (mapped in `src/quill/exports.py`) |
| Permission decay | not mentioned in researcher summary | shipped (`src/quill/decay.py`); per Manu's field survey, unique vs Cerbos / Permit.io / OPA / WorkOS |
| Lethal-trifecta enforcement | not mentioned in researcher summary | shipped in v0.2.0a2 (`src/quill/taint.py`) |
| CVE-2025-59536 subcommand-chain bypass | unknown | explicit gate in `policy.py:384` |

## Pattern category mapping (TO FILL IN after reading paper)

After reading AEGIS sections [TBD], populate each AEGIS category with the Quill regex patterns from `src/quill/policy.py` that overlap. The 7 AEGIS categories per researcher summary are: [TBD — read paper, list here].

| AEGIS category | AEGIS pattern count | Quill regex(es) in `policy.py` | Coverage delta |
|---|---|---|---|
| [Cat 1] | n | | |
| [Cat 2] | n | | |
| [Cat 3] | n | | |
| [Cat 4] | n | | |
| [Cat 5] | n | | |
| [Cat 6] | n | | |
| [Cat 7] | n | | |
| **Total** | 22 | | |

## Strategic questions to answer once filled

1. **Where does Quill have a real coverage gap vs AEGIS?** Patterns AEGIS catches that Quill doesn't. Add them to `policy.py` or to the v0.3 roadmap.
2. **Where does Quill catch things AEGIS doesn't?** CVE-2025-59536 subcommand-chain bypass is one. List others. These become the honest "Quill ALSO catches X" lines for launch comments.
3. **What's the honest one-line comparison for launch comments?** Working draft: *"Quill is the developer-laptop, MCP-proxy / Touch-ID-native version of what AEGIS does at the SDK + web-cockpit layer for enterprise compliance buyers."* Validate after pattern mapping; tighten if the coverage delta is meaningful in either direction.
4. **Is there a collaboration path?** Joint pattern library? Shared attack-instance benchmark? AEGIS-pattern compatibility mode in Quill? Worth raising in the outreach email (draft lives in `LAUNCH.md` under "AEGIS author outreach").

## What to do after reading the paper

- Fill in the pattern-category table.
- Re-run `tests/test_bench_hot_path.py` and record Quill's median latency in the architectural table so the 8.3 ms vs Quill comparison is grounded.
- If meaningful coverage gaps surface in either direction, file issues in `manumarri-sudo/quill`.
- Update the LAUNCH.md "How this compares" sentence in the Show HN draft with verified, post-reading numbers.
- Send the AEGIS outreach email from `LAUNCH.md` once the paper read confirms the comparison framing.
