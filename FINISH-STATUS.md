# Quill — Finish Status (launch-readiness triage)

Worklist for getting Quill to a launch-ready, honest state. Tracks every
AUDIT-FIX-PLAN.md finding (58 total) against the **current** tree, since many
were closed by recent waves and the Change-Control pivot (commit 98bf17b) made
several obsolete. Ground truth re-established this session — do not trust prior
notes.

## Ground truth (verified 2026-06-23, branch `change-control-pivot`)

| Signal | Notes claimed | Actual |
| --- | --- | --- |
| pytest | "598 passing" | **1030 passed, 4 xfailed** |
| ruff check / format | "5 lint errors" (#9) | **clean** |
| mypy src/quill | "227 errors" (#8/#10) | **6 errors in 3 files** |
| audit chain | "11k / 24k" | **`chain intact: 32332 entries`** |
| secret patterns | "18 vs 26" | **26 vendor `_PATTERNS` + inline-cred patterns** |

## Identity decision (#11/#13/#24) — DECIDED: headline = Quill Change Control

**Decision:** Lead with **Quill Change Control** — a CI/CD pull-request gate that
verifies an AI-written diff against the human-approved task and issues a
tamper-evident **Change Passport**. The local runtime gate (PreToolUse hook +
Touch ID approvals + off-switch) becomes a clearly-scoped *supporting* surface
framed as **local defense-in-depth**, never as a hard boundary.

**Why this is the honest headline (prime directive):**
- The owner already made this call: commit 98bf17b ("pivot Quill to Change
  Control") **deleted** the MCP proxy, OS sandbox (Seatbelt/ESF), TUI, and
  notification surfaces, `pyproject.toml`'s `description` leads with Change
  Control, and `quill --help`'s top lines are `begin` / `verify`. The README and
  LAUNCH.md simply lagged the pivot. Finishing this is completing a decision, not
  inventing one.
- Change Control is an **evidence-and-verification** claim (provable): the CI
  gate runs in CI — *outside the agent's reach, where it cannot be self-disabled*
  — parses the unified diff, scopes it against the contract, scans added lines
  for secrets, and signs a verdict into the HMAC chain. Every word maps to code
  (`policy.evaluate_diff`, `contract.py`, `verify.py`, `passport.py`, `action.yml`).
- The runtime laptop gate is an **app-layer regex gate** = real but bounded
  defense-in-depth, with documented bypasses (write-then-run, flag reorder,
  inherited-env, tool switch). Leading with it invites the "fake security layer"
  critique. It stays, scoped honestly, as the supporting surface.
- Per the prime directive's tiebreak — "pick the headline that is true" — the
  provable verification artifact wins the headline; the bounded control supports.

This reshapes the public face, so it is flagged for owner sign-off in the session
summary. Proceeding with the most-honest option per the working agreement
(don't silently choose; proceed with the most-honest one and document).

## Pivot obsoletes several pre-pivot findings (now MOOT)

The audit was written against the *runtime-gate* product. The pivot removed those
surfaces, so these findings no longer describe shipping code:

- **#14, #15** (Seatbelt CI / macOS runner for the kernel floor) — `sandbox.py`
  and `native/quill-esf` were **deleted**. There is no kernel boundary to
  CI-test anymore. Action: document in SECURITY-MODEL.md that the runtime gate is
  now defense-in-depth only (no kernel floor); the *provable* boundary is the CI
  gate + tamper-evident passport. MOOT-as-written; rolled into the security-model update.
- **#22, #39** (hook-vs-MCP-proxy divergence; proxy empty-scope footgun) — the
  MCP proxy (`proxy.py`) was **deleted**. `docs/HOOK-VS-PROXY.md` documents a dead
  architecture → delete it. MOOT.

## Triage table

Legend: **FIXED** (closed, test-backed where security-relevant) · **PARTIAL**
(started, needs finishing) · **OPEN** (not started) · **MOOT** (obsoleted by
pivot) · **WONTFIX-NOW** (out of launch scope, next run).

### Phase 1 — real security holes (all closed by recent waves; verified this session)

| # | Sev | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | Critical | **FIXED** | `_require_disable_auth` (cli.py:1174) refuses by default when no Touch ID + no tty; `--no-biometric` opt-in logged loudly. Tests: `test_no_biometry_no_tty_refuses_by_default`, dangerous twin `test_touchid_cancel_does_not_fall_through`. Old fall-open test removed. |
| 3 | High | **FIXED** | `approvals_list` (cli.py:3433) prints sha256 hashed id only; approval via `--latest` + Touch ID; `--no-biometric` use logged. |
| 4/16 | High | **FIXED** | `verify_chain(expected_count=)` + `seal_head`/`read_head` `.head` sidecar (audit.py:252+); truncation reported at line 0. Tests in test_audit.py. |
| 17/18 | Med→High | **FIXED** | `_summarize_call`/`_redacted_input` run `secrets.redact()`; `_redact_for_export` redacts `_FREETEXT_EXPORT_FIELDS` incl. `what`, normalizes home paths. `_INLINE_CRED_PATTERNS` covers `-p`, bearer, aws key, DSN. Tests: test_secrets.py, test_exports.py. |

### Phase 2 — make every claim true

| # | Verdict | Action |
| --- | --- | --- |
| 5 | **PARTIAL** | README "24,478" now stale (actual 32,332); LAUNCH "11k"/"598 tests" stale. Reconcile to SSOT + add pattern-count assertion test. |
| 6 | **PARTIAL** | marketing docs have disclaimers; README still has a standards-acronym wall. Demote in rewrite. |
| 7 | **WONTFIX-NOW** | Demo GIF re-record is a launch-channel task (Show HN), not a repo-correctness blocker; the headline pivots away from the GIF's runtime-block story anyway. |
| 11/13/26 | **PARTIAL** | version labels mostly reconciled to 0.2.0a5; finish Roadmap separation + pivot framing in README rewrite. |
| 12 | **FIXED** | CITATION.cff = 0.2.0a5. |
| 19 | **PARTIAL** | calibration table exists in SECURITY-MODEL.md; ensure README/LAUNCH obey it (no unqualified "prevents prompt injection"/"enterprise-grade"/"production-safe"/"secure by default"). |
| 23/56 | **OPEN** | "cannot be jailbroken"/"$50k"/LAUNCH "nothing is jailbreakable" — calibrate in rewrite. |
| 31/44 | **FIXED** | pattern count consistent (26); path ref → secrets.py. |
| 51 | **FIXED** | "472 entries" gone. |
| 55/57/58 | **FIXED** | determinism scoped to the verdict; no replay claim. |

### Phase 3 — front door + CI honestly green

| # | Verdict | Action |
| --- | --- | --- |
| 2 | **PARTIAL** | `pyproject [project.scripts]` declares both `quill` and `quillx`; published-wheel fix needs a release (human-gated). Headline pivots away from `uvx quillx start` as the hero; point README at the verified-working install + `quill begin`/`verify` flow. |
| 8/10 | **PARTIAL** | mypy down to 6 errors. Fix them, drop `|| true`, keep py.typed + badge honest. `disallow_any_explicit` already OFF (#47 done). |
| 9 | **FIXED** | ruff clean, hard-gated in CI. |
| 14/15 | **MOOT** | kernel floor removed; document. |

### Phase 4 — land in-flight work

HEAD is **broken on fresh checkout**: committed `claude_code.py` imports untracked
`code_scan` (:242) and calls `learning.record_decision_learning` (:1202/1207) which
lives only in uncommitted `learning.py`. The 8 modified files are a coherent
mypy-greening + #46 de-dup pass. **Commit them** (split sensibly); the cli.py
`reaped` block is dead code (orphan-reaping removed in pivot) → delete it. Delete
`docs/HOOK-VS-PROXY.md` (dead architecture).

### Phase 2/4 architecture + low-priority (mostly done or next-run)

| # | Verdict | Note |
| --- | --- | --- |
| 20/21 | **FIXED** | `HookDecision.classified_by` structured field; downshifts no longer key on reason substring. |
| 25/34/52 | **PARTIAL** | pip-audit already blocking (no `|| true`); only mypy `|| true` remains → removed with #8/#10. |
| 40 | **FIXED** | inherited-env bypass documented in SECURITY-MODEL.md. |
| 46 | **FIXED** (pending commit) | `record_decision_learning` helper extracted. |
| 47 | **FIXED** | `disallow_any_explicit` off. |
| 27/35/36 | **WONTFIX-NOW** | dedicated taint/trifecta module + hypothesis fuzz + config-determinism test — valuable, next run (no new holes). |
| 28/29/30/41/48/49/53 | **WONTFIX-NOW** | cli.py split, README CLI map, demo DX, ARCHITECTURE.md, API-stability section — polish, next run. |
| 32/37 | **PARTIAL** | SECURITY.md: contrib/ link + 0.1.x version + supply-chain tense — quick fixes folded into the security-model pass. |
| 33/54 | **WONTFIX-NOW** | macOS Touch ID framework-bind test; perf-budget hard asserts — next run. |
| 38/43 | **FIXED** | SECURITY-MODEL.md honest framing intact. |
| 42 | **FIXED** | quillx/quill callout present. |
| 45 | **FIXED** | no caches/.DS_Store tracked. |
| 50 | **WONTFIX-NOW** | CODE_OF_CONDUCT.md — trivial, next run. |

## Out of scope (explicit — next run, per directive)

No new product surface: compliance docs, retention, SOC2 pack, EU AI Act export,
connectors, cli.py split, demo re-record, fuzz tests, ARCHITECTURE.md. Scope here
is launch-ready + honest only.
