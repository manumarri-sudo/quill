# Quill security model and threat model

This document states plainly what Quill is, what it defends against well, and
where its limits are. It exists because a security tool that overstates its
guarantees is worse than one that is honest about them: an operator who
believes the walls are thicker than they are takes risks they would not
otherwise take.

The short version: **Quill is a deterministic, application-layer gate and
evidence recorder. It is a strong defense-in-depth layer and an excellent
audit trail. It is not a hard security boundary against a determined,
adversarial agent that is actively trying to escape it.** Both of those
sentences are true at the same time, and the rest of this document explains
why.

## Where Quill sits (the trust boundary)

Quill runs in two places on the developer's machine:

1. A **PreToolUse hook** in the coding agent (Claude Code, Cursor) that fires
   before each built-in tool call (Bash, Edit, Write, NotebookEdit).
2. An **MCP proxy** between the agent and the MCP servers it calls.

Both are at the **application layer**. Quill sees the *tool calls the agent
chooses to make through the framework*. It classifies them with a compiled
regex/policy set (no LLM in the decision path) and returns allow / ask / deny,
writing every decision to an HMAC-chained audit log.

What Quill does **not** see, by construction:

- System calls (the actual `unlink`, `connect`, `execve` the kernel runs).
- Actions taken in-process by an interpreter it already allowed to start
  (what `python3 script.py` does once it is running).
- Writes that do not flow through a gated tool (a sandbox escape, or a
  framework bug that skips the hook).
- Network bytes leaving the machine.

Everything in the "what it does well" list below is *within* that boundary;
everything in the "known limits" list is a consequence of *where the boundary
is drawn*.

## What Quill defends against well

For the common case (a capable but non-adversarial agent, or a careless one,
or a single-shot prompt injection that is not specifically tuned to evade
Quill), the gate is genuinely effective:

- **Irreversible destructive commands** in their direct and common-obfuscated
  forms: `rm -rf`, `DROP TABLE`, `git push --force`, `vercel --prod`,
  `mkfs`, `dd`, fork bombs, and the documented bypass shapes
  (`bash -c "$(curl | sh)"`, base64-decode-to-shell, interpreter heredocs,
  `python -c "...rmtree..."`, `$(which rm) -rf`, variable-assembled
  `$a$b -rf`). See `src/quill/policy.py` and `tests/test_kill_test_2026_06.py`.
- **Credential reads and the exfiltration shape**: `cat ~/.aws/credentials |
  curl ...`, `env`/`printenv` dumps, reads of `~/.ssh`, `~/.npmrc`, and
  friends, and the lethal-trifecta third edge (untrusted input + private
  data + exfil path in one session).
- **Gate self-tamper through a gated tool**: an Edit/Write or shell
  redirection aimed at `~/.claude/settings.json`, `~/.cursor/hooks.json`, or
  `~/.quill/config.toml` is classified CRITICAL, so an agent cannot quietly
  rewrite the gate's own config to disable it *through the tools Quill gates*.
- **Tool-description poisoning / rug-pulls** at the MCP layer (invisible
  Unicode, injection-shaped phrases, schema drift after first trust).
- **A complete, tamper-evident record** of everything attempted, allowed, and
  refused, including everything allowed while the gate was paused
  (`gate_paused` markers) so even an off-window is on the record.

The gate's classifier has no LLM in it, so the gate itself **cannot be
prompt-injected or jailbroken**. That is true and worth stating. It is *not*
the same claim as "cannot be bypassed" (see below).

## Known limits (read this before you trust it with your life)

These are the second-review critique's points, restated honestly. They are
real. We do not close them with more regex.

1. **Semantic shell obfuscation is unbounded.** Regex enumerates the common
   evasions; it cannot enumerate all of them. The Tier-1 and Tier-2 audits
   (2026-06-12) closed the cheapest named shapes - single-variable
   reconstruction (`x=rm; $x -rf`), `printf`-assembled strings piped to a
   shell, `${IFS}` whitespace games, ANSI-C escape reconstruction
   (`$'\x72\x6d'`, decoded before matching), command-substitution binary
   resolution (`$(echo rm) -rf`), and `eval` of a destructive literal are now
   caught (see `tests/test_audit_fixes_tier1.py` and `_tier2.py`) - but the
   *class* remains open: glob-expanded binary paths (`/bin/[r]m -rf`), deeper
   string-splitting, novel encodings, and importance-unknown truncation
   (`: > important.db`) still evade, and are kept on the record as xfail-marked
   residual tests. Catching "what a command *does*" rather than "what it
   *looks like*" needs a shell AST parser or a syscall-level view, not a
   pattern list.

2. **Application-layer hooks can be bypassed by the layer below them.** Quill
   relies on the agent framework to call the hook. If the framework has a bug
   (for example, a subagent dispatched with bypass-permissions that skips
   PreToolUse hooks), or if an attacker writes to the hook config *without
   going through a gated tool*, Quill never fires. The gate self-tamper
   detection above only covers tampering that flows through a gated tool.
   Relatedly, `QUILL_BYPASS_MODE` / `CLAUDE_DANGEROUSLY_SKIP_PERMISSIONS` in the
   *inherited* environment downshift HIGH verdicts to a silent allow (the
   operator opted out of HIGH prompts); the CRITICAL class never softens. An
   agent that *sets* those vars through a gated tool is classified self-tamper
   and denied, but one that inherits them already-exported (from the operator's
   shell or a parent process) is not caught, because there is no gated tool call
   to intercept. Treat a pre-exported bypass var as equivalent to running
   without the gate for the HIGH class.

3. **The write-then-run loophole.** An agent can use the (allowed) Write tool
   to create `deploy.py`, put `DROP TABLE` or a `requests.post` exfiltration
   inside it, and then run `python3 deploy.py`, which looks like a MEDIUM
   command. The destructive action happens inside the interpreter, invisible
   to a command classifier. Scanning file *writes* for destructive payloads
   is a partial mitigation (Quill already scans writes for secrets); it does
   not close the loophole.

4. **Network egress is not gated.** Blocking `curl` does nothing against a
   Python `requests.post`. The Tier-2 audit (2026-06-12) added classification
   for the common *credential-exfil shapes* - `scp`/`curl -F @cred`/
   `nc < cred`/`openssl < cred`, wget request-body posts, and interpreter
   one-liners that read a file/env and POST it - so the cheap exfil patterns
   are now caught at the command layer. This is a partial mitigation, not
   egress gating: a novel script, an already-running interpreter, or any
   channel the classifier does not enumerate still exfiltrates freely. Quill
   tracks the lethal trifecta heuristically but does not inspect or block the
   outbound connection itself; only a network-egress proxy (roadmap) closes
   this.

5. **Local key + local log.** The audit log is tamper-*evident*, not
   tamper-*proof*. A fully compromised machine can rewrite both the log and
   the HMAC key. The right framing is "locally tamper-evident, optionally
   externally anchored," not "immutable."

6. **Trailing truncation is not detected by the chain alone.** Deleting the
   last N lines of the log leaves a shorter but *valid* chain - each remaining
   entry still links to its predecessor - so `quill audit verify` passes on a
   truncated log. This is a weaker prerequisite than the limit-5 case: it needs
   only write access to the log file, not the HMAC key. Mitigation: `seal_head`
   records a high-water-mark (entry count + last mac) to a `<log>.head` sidecar,
   and a later verify against it (`expected_count`) flags a shortfall; but
   truncation *before* any seal, or deletion of the sidecar on a compromised
   host, stays undetected. Per-write detection (a head pointer updated under the
   emit flock) would close it but is deferred rather than risk the audited
   tamper-evidence write path.

## What the limits mean for the claims

- The audit log is **auditor-reviewable evidence**, not a guarantee of
  prevention and not "the artifact your auditor will accept" on its own.
  Auditor acceptance depends on scope, sampling, key custody, and retention,
  none of which a tool can decide for you. A cryptographically signed log of
  the gate failing to stop an attack is a high-quality *record of a breach*,
  not a mitigating control. Quill maps to evidence requests (SOC 2 CC6/CC7/CC8,
  EU AI Act Article 12-shaped logging, ISO/IEC 42001 A.6.2.8); it does not
  certify compliance by itself.
- "The gate cannot be jailbroken" (true: no LLM in it) is **not** "the gate
  cannot be bypassed" (false: see limits 1-4). Keep the two separate in any
  copy.

### Claims we do and do not make

A launch-gate for any README or marketing copy. If a claim is not at least
"partial" below, it does not ship.

| Claim | Status | Honest form |
|---|---|---|
| Deterministic gate | **Supported** | Same tool call -> same allow/ask/deny; no model in the decision path. Scope it to the *verdict*, never to record-and-replay. |
| Tamper-evident audit log | **Supported** | HMAC-chained, locally tamper-evident (limits 5-6), optionally externally anchored. Not "immutable". |
| Blocks the irreversible class | **Supported** | rm -rf / DROP TABLE / force-push / npm publish / .env reads etc. are default-critical via inspectable regex. |
| Prevents prompt injection | **Partial / reframe** | It cannot be prompt-injected (no LLM) and refuses some injection *consequences* (lethal-trifecta deny); it does not *prevent* injection. Say "refuses the consequence, not detects the cause." |
| Secure by default | **Partial** | The local hook fails closed, but `off`/`--no-biometric` exist and the app layer is bypassable (limits 1-4). Say "defense-in-depth by default." The provable boundary is the CI gate (next row), not the local hook. |
| CI gate runs outside the agent | **Supported, deployment-gated** | `quill verify` runs in CI where the agent can't disable it, enforces a **human-signed perimeter** (Ed25519: forging needs the approver's private key, which lives off the box), BLOCKs any edit to its own trust surfaces (perimeter, approver keys, workflow), and emits a **gate-signed passport** anyone re-verifies with `quill verify-passport`. The agent cannot forge approval (no private key), bootstrap trust (editing `.quill/approvers/**` is a gate-tamper BLOCK), or forge the verdict (asymmetric). This is a real boundary **iff** the trust root is deployed off the PR's reach — see the deployment checklist below. Absent that (no signed perimeter, keys committed in-repo, action run from the PR's own checkout), it degrades to honest review automation for a cooperative agent, and `--strict` BLOCKs rather than pretending. |

### Deployment checklist (what makes the CI gate a real boundary)

All three are required; any one missing drops it back to cooperative-only:

1. **Keys off the build machine.** The approver/gate **private** keys never live
   in the repo. Publish the approver **public** key as `QUILL_APPROVER_PUBKEYS`
   and the gate signing key as `QUILL_GATE_KEY` — repo/org **secrets** a PR
   cannot read or edit. (A committed `.quill/approvers/*.pub` set is a
   convenience layer only; it's editable in a PR, so gate-tamper BLOCKs such
   edits, but the authoritative pin is the secret.)
2. **Pin the Action to a published tag** (`uses: manumarri-sudo/quill@v0`), not
   the PR's own checkout (`uses: ./` + `install-from-source`), so a PR can't ship
   a modified gate that judges itself.
3. **Make the Status Check required** in branch protection, with admin-bypass and
   force-push disabled — otherwise a `BLOCK` is merely advisory.
4. **Sign the contract** with the approver key (`quill begin --key`). The contract
   supplies the base commit and allowed scope, so an unsigned one is forgeable by
   the agent (it could move the base to hide commits, or widen scope). In strict
   mode an unsigned/forged contract is a BLOCK.

### CI gate: known limits and the external-review status

An independent skeptical security review (2026-06-23) found, and we fixed, two
complete bypasses: an unsigned per-PR contract whose base commit could be moved
to hide malicious commits (P0-1, now requires a signed contract in strict mode),
and an unsigned wildcard exceptions file that could waive whole finding classes
(P0-2, strict mode no longer honors branch-authored exceptions). Both are covered
by adversarial tests in `tests/test_trust_spine.py`.

A second review pass (same date) drove three more to closure, each with a
regression test:

- **Composite rogue-key-in-base attack (closed).** An attacker who plants a
  public key in the base commit (where the gate-tamper scan can't see it, since
  the diff starts *after* it) and signs their own perimeter + contract with it.
  Strict mode now trusts **only** externally-pinned `QUILL_APPROVER_PUBKEYS`, so
  a committed key is never a trust root (`test_p0_1_composite_rogue_key_plus_base_move_blocks`).
- **Action-wrapper fail-open (closed).** `scripts/quill-passport.sh` now runs the
  verifier into a fresh `mktemp` dir and reads the verdict only from there (a
  committed/stale passport can't be read), fails closed on any non-`0/1` exit or
  unrecognised verdict, and re-verifies the passport's gate signature when a gate
  pubkey is configured (`tests/test_action_wrapper.py`).
- **Binary / rename diff coverage (closed).** The unified-diff parser now seeds
  each file from the `diff --git` header and parses `Binary files … differ`
  stanzas, so a binary blob is inventoried against scope and the gate-tamper
  surfaces; `evaluate_diff` checks both ends of a rename
  (`tests/test_diff_binary_rename.py`).

Genuinely still open — do not rely on the CI gate against a determined adversary
until these land:

- **Off-box evidence anchoring.** The Merkle transparency tree head is built but
  not yet anchored off the runner, so a CI passport's MAC is not independently
  resolvable. There has been **no external security audit** of the full
  end-to-end construction; treat the CI gate as alpha.
- **Perimeter allow-list as outer bound.** The signed perimeter's `allowed_paths`
  now caps a contract's scope (a contract can narrow but not widen past it), but
  `contract_id` still does not cryptographically bind the *specific* scope a
  human saw at approval time; a re-signed contract with a different scope under
  the same id is not detected beyond the signature itself.
| Auditor evidence pack | **Partial** | Maps to evidence requests (SOC 2, EU AI Act Art 12-shaped, ISO 42001 A.6.2.8); does not certify compliance by itself. |
| Enterprise-grade / production-safe | **Not yet** | Alpha, squatted dist name, no external audit. Do not claim. |
| Cannot be bypassed / agent-proof | **Dangerous** | False - see limits 1-4. Never claim. |

## Roadmap to close the gaps (in honesty order)

The fixes for the limits above are architectural, not pattern additions:

- **Shell AST / intent classification** for limit 1 (keep it local and fast;
  a lightweight intent classifier or a real bash parser, not an LLM in the
  hot path).
- **Move the enforced boundary into CI, not the kernel.** An earlier preview
  shipped an opt-in macOS Seatbelt floor (`quill shell`); it was **removed** in
  the Change Control pivot because a local kernel floor still runs on the
  machine the agent controls. The chosen direction is the opposite: enforce in
  CI, where `quill verify` gates the diff in a process the agent cannot reach.
  A kernel-layer local control (eBPF / Landlock / Endpoint Security) remains a
  possible future addition for the local-gate surface, but it is not what makes
  Quill a boundary today — the CI gate is.
- **Network-egress proxy** for limits 3 and 4: catch unauthorized outbound
  connections regardless of the language or script that opened them.
- **Config-file integrity monitoring** for limit 2: detect changes to the
  hook config even when they do not flow through a gated tool.

Until those land, position Quill honestly: the gate that refuses the
irreversible thing and records what was attempted, on the developer-laptop
tool-dispatch layer, as one layer of defense-in-depth. Pair it with
model-level guardrails and (for real adversaries) a kernel-layer control.
Never substitute it for either.
