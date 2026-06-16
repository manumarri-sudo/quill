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

## Roadmap to close the gaps (in honesty order)

The fixes for the limits above are architectural, not pattern additions:

- **Shell AST / intent classification** for limit 1 (keep it local and fast;
  a lightweight intent classifier or a real bash parser, not an LLM in the
  hot path).
- **Kernel-layer enforcement** for limit 2: eBPF / Linux Landlock / macOS
  Endpoint Security, gating the actual syscalls so a framework bug cannot
  route around the gate. This is the single highest-leverage change and the
  one that would let Quill claim "boundary" rather than "speed bump."
- **Network-egress proxy** for limits 3 and 4: catch unauthorized outbound
  connections regardless of the language or script that opened them.
- **Config-file integrity monitoring** for limit 2: detect changes to the
  hook config even when they do not flow through a gated tool.

Until those land, position Quill honestly: the gate that refuses the
irreversible thing and records what was attempted, on the developer-laptop
tool-dispatch layer, as one layer of defense-in-depth. Pair it with
model-level guardrails and (for real adversaries) a kernel-layer control.
Never substitute it for either.
