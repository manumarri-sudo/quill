# quill

> **Quill Change Control** — a CI/CD pull-request gate that verifies an AI-written
> diff against the human-approved task, scopes the change, and issues a
> tamper-evident **Change Passport**.

<!-- mcp-name: io.github.manumarri-sudo/quill -->

[![PyPI](https://img.shields.io/pypi/v/quillx.svg)](https://pypi.org/project/quillx/)
[![Python versions](https://img.shields.io/pypi/pyversions/quillx.svg)](https://pypi.org/project/quillx/)
[![CI](https://img.shields.io/github/actions/workflow/status/manumarri-sudo/quill/ci.yml?branch=main&label=ci)](https://github.com/manumarri-sudo/quill/actions/workflows/ci.yml)
[![Typed](https://img.shields.io/badge/typed-strict-blue.svg)](https://mypy.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An AI agent opens a pull request. Did it do **only** what it was asked to do? Quill
answers that in CI, deterministically, and signs the answer.

```bash
# 1. capture the approved task (once, at the start of the work)
quill begin "Add rate-limiting to the login endpoint" --scope "src/auth/**"

# 2. let the agent write the diff, open the PR

# 3. CI runs this on every push and signs the verdict
quill verify        # PASS · NEEDS_REVIEW · BLOCK   (BLOCK fails the build)
```

`quill verify` reads `git diff <base>..HEAD`, checks every changed file against the
scope you approved, scans added lines for hardcoded secrets and sensitive surfaces
(CI config, lockfiles, test deletions), evaluates any logged exceptions, and writes
a **Change Passport** — `passport.json` + a PR-ready `passport.md` — that cites the
HMAC-chained audit entry for the run, so a reviewer can trace the verdict back to a
tamper-evident record instead of trusting the markdown alone.

---

## Why this layer

The agents writing your code have shell access, file write, deploy permissions, and
your credentials, and the failures are already on the record: in July 2025 [Replit's
agent deleted a production database](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/)
during a vibe-coding session and fabricated data to cover it; that same month a
Cursor agent ran `rm -rf ~/` against a developer's home directory; in August an
autonomous agent committed a customer's GitHub token into a public commit. The
common thread is not that the model is evil, it is that nothing checked the change
against what was actually approved before it shipped.

Quill puts that check where it can be enforced and recorded: **in CI, on the pull
request**, where the gate runs outside the agent's own process and cannot be quietly
switched off by the thing it is reviewing. The verdict is a deterministic function of
the diff, the contract, and the policy — there is no LLM in the decision path, so the
gate itself cannot be prompt-injected.

## What Quill is, and what it is not

Calibration matters more than marketing.

- **Quill is a verification-and-evidence artifact, not a content classifier.** It
  does not predict whether a change is "good." It checks the diff against a recorded
  contract (scope, secrets, sensitive surfaces) and issues a signed verdict a human
  can review. There is no model in the gate.
- **The CI gate is the defensible boundary; the local gate is defense-in-depth.**
  Quill also ships an optional on-laptop runtime gate (below). That gate is a
  deterministic speed bump and recorder at the tool-dispatch layer — it raises the
  bar against careless agents and the common destructive/exfiltration shapes, but it
  is **not** a hard boundary against a determined adversary actively trying to escape
  it (write-then-run, flag reordering, inherited-env, ungated network egress are all
  documented limits). The full, honest threat model is in
  [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).
- **Quill does not certify compliance.** The audit log is machine-verifiable evidence
  your auditor will want to review, not the artifact they will accept on its own.
- **Quill is not a hosted service.** It is a single Python package. The audit log and
  signing key live on your disk in mode `0o600`; you own the key, the log, and the
  verdict. No cloud round-trip on the verify path, no telemetry by default.

## Change Control in detail

### 1. `quill begin` — capture the contract

```bash
quill begin "Add rate-limiting to the login endpoint" \
            --scope "src/auth/**" --scope "tests/auth/**" \
            --approved-by alice
```

Writes `.quill/contract.json`: the approved task (text or a URL to a ticket), the
`allowed_paths` scope (globs, directory prefixes, or exact paths), the base commit
the change starts from, and a `contract_id`. Commit this file to the branch — it is
the fixed record the diff is later measured against, and the Change Passport cites it.

### 2. `quill verify` — gate the diff

```bash
quill verify                 # uses .quill/contract.json, diffs base..HEAD
```

`verify` (`src/quill/verify.py`, on top of `policy.evaluate_diff`):

1. parses `git diff <base_commit>..HEAD` as a unified diff,
2. matches every changed path against the contract scope,
3. scans **added lines** for the 26 vendor-format secret patterns in
   [`src/quill/secrets.py`](src/quill/secrets.py),
4. classifies sensitive surfaces (CI/workflow files, lockfiles, test deletions),
5. applies any logged exceptions in `.quill/exceptions.jsonl`,
6. composes a verdict — **PASS**, **NEEDS_REVIEW**, or **BLOCK** — and chains a
   `verification.run` event into the audit log.

`BLOCK` exits non-zero (fails CI); `PASS` and `NEEDS_REVIEW` exit 0, so review is
surfaced without hard-stopping the pipeline. The whole thing is deterministic: same
diff + same contract + same policy → same verdict, explainable line by line.

### 3. The Change Passport

`verify` writes `passport.json` (machine-readable, for downstream tooling and status
checks) and `passport.md` (PR-ready). The markdown footer cites the
`verification.run` audit MAC, so the passport traces back to the tamper-evident chain
rather than asking you to trust the document.

### 4. The GitHub Action

```yaml
# .github/workflows/quill-change-control.yml
on:
  pull_request:
    branches: [main]
jobs:
  change-control:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # full history so the base commit resolves
      - uses: manumarri-sudo/quill@v0   # runs `quill verify`, publishes a Status Check
```

The composite action ([`action.yml`](action.yml)) runs `quill verify`, publishes a
commit Status Check, and fails the job on `BLOCK`. If a PR has no
`.quill/contract.json`, the gate is a no-op with a notice telling you to run
`quill begin` — Change Control is opt-in per branch.

## Trust spine: sign the boundary once, the agent can't forge it

The point of running in CI is that the gate lives where the agent can't disable
it — but that only matters if the agent also can't *fake its approval* or *edit
its own judge*. Quill closes both with Ed25519 (verification uses a public key,
forging needs the private key — not the same secret, which is what the symmetric
HMAC chain could never give you):

```bash
quill keygen --out approver.pem          # human's key; keep the private half OFF the box
quill guard --key approver.pem --forbid 'migrations/**' --forbid 'src/auth/**'
#   ^ signs .quill/perimeter.json once. From now on EVERY agent's PR is checked
#     against it automatically — you're paged only when one crosses the line.
```

- **A human signs the perimeter once; every PR is enforced with no per-change
  approval.** That is the answer to "I'm not going to sit and approve a hundred
  agents." Forbidden paths and gate-tamper edits BLOCK; secrets BLOCK; in-bounds
  work PASSes silently.
- **The agent can't authorize itself.** Editing the perimeter, the approver keys
  (`.quill/approvers/**`), or the workflow that runs the gate is itself a BLOCK,
  so an agent can't widen its own boundary or add its own signing key. Tampering
  with a signed perimeter invalidates the signature.
- **The verdict can't be forged.** With a gate key (`quill verify --strict
  --sign-key gate.pem`, or `QUILL_GATE_KEY` in CI), the passport is signed;
  anyone re-checks it with `quill verify-passport passport.json` and a flipped
  verdict or untrusted signer fails.
- **Or use GitHub's own reviews.** `quill check-approval` requires a human who is
  not the PR author to have approved the current head commit — an agent can't
  approve its own PR, and the approval is dismissed when new code is pushed.

**What this requires to be a real boundary (not optional):** the trust root must
live where a PR can't edit it — hold the approver/gate **private keys off the
build machine** (a repo/org secret: `QUILL_GATE_KEY`, `QUILL_APPROVER_PUBKEYS`),
**pin the Action to a published tag** (`uses: manumarri-sudo/quill@v0`, not the
PR's own checkout), and make the **Status Check required** in branch protection.
With those three in place an adversarial agent cannot fool the gate; without them
it is honest review automation for a cooperative one. The full threat model and
the exact deployment checklist are in [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## The local runtime gate (optional, defense-in-depth)

Separately from CI, Quill can gate an agent's tool calls **as they happen** on your
laptop, via Claude Code's `PreToolUse` hook. This is the supporting surface, scoped
honestly as defense-in-depth — a deterministic speed bump and recorder, not a hard
boundary.

```bash
quill onboard      # detect agents, install the hook, pick a risk preset
```

From the next session, every `Bash` / `Edit` / `Write` / `NotebookEdit` passes
through the compiled-regex classifier in [`src/quill/policy.py`](src/quill/policy.py):
`rm -rf`, `git push --force`, `DROP TABLE`, `vercel --prod`, `npm publish`, `.env`
reads, and the CVE-2025-59536 subcommand-chain bypass are critical-class by default.
Critical calls are refused with a plain-English reason and a single-use, 10-minute
`quill approve <token>`; on macOS the approval is hardware-attested through Touch ID
on the Secure Enclave. Files an agent writes are scanned with the same 26 secret
patterns and an AST pass ([`code_scan.py`](src/quill/code_scan.py)) that flags
destructive Python shapes (`shutil.rmtree`, `os.system`, `exec(b64decode(...))`)
before a later `python foo.py` can run them. Every decision lands in
`~/.quill/audit.log.jsonl`, HMAC-SHA256 chained for tamper evidence.

Supporting surfaces on the local gate, all derived from the same chain on read:
`quill receipts` (per-session did / changed / uncertain / to-verify), `quill trifecta`
(lethal-trifecta exposure: untrusted input + private data + exfil vector),
`quill pins` (tool-description pinning against MCP rug-pulls), `quill decay`
(permissions that erode without reinforcement), and `quill audit` (review and verify
the chain). `quill scan-secrets` runs the secret detectors standalone over files.

**Why this is defense-in-depth and not the headline:** an application-layer gate can
be routed around by a capable adversary (the limits above). The provable boundary is
the CI gate, which runs where the agent cannot disable it and produces a signed
record. The local gate is real and useful, but its honest claim is "raises the bar
and records everything," not "cannot be bypassed."

## The signed audit log

Both surfaces write to `$QUILL_HOME/audit.log.jsonl`, mode `0o600`. Each entry's
`mac` is `HMAC-SHA256(prev_mac || canonical(payload))` under your installation's key
(auto-generated at first run, stored at `$QUILL_HOME/key`, mode `0o600`). Writes take
`fcntl.flock(LOCK_EX)` and re-read the tail MAC inside the lock so concurrent writers
can't break the chain. A sealed `<log>.head` high-water-mark lets `verify` detect
trailing truncation, not just edits and insertions.

```bash
quill audit verify
# chain intact: 32332 entries verified.
```

That count is from ~45 days of real dogfooding on the maintainer's machine; your own
log starts at one. The chain is locally tamper-evident (and optionally externally
anchored) — see [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) for exactly what
that does and does not buy.

## Install

```bash
uvx --from quillx quill begin --help     # no install; run it once
pipx install quillx                      # or install the CLI persistently
pip install quillx                        # or into an existing venv
```

The PyPI dist name is `quillx` because the `quill` name is held by an unrelated
package; the CLI binary, import path (`quill`), config dir (`~/.quill/`), env vars
(`QUILL_KEY`), and brand all stay `quill`. A PEP 541 reclaim for the canonical name
is in flight (not yet granted); if it lands, `quillx` becomes a transitional alias.
For a development checkout: `git clone https://github.com/manumarri-sudo/quill && cd
quill && pip install -e .`.

## CLI surface

```
quill begin          capture the approved task into .quill/contract.json
quill verify         compare the diff to the contract, emit PASS / NEEDS_REVIEW / BLOCK
quill onboard        first-run setup for the local gate (detect agents, install hook)
quill audit          review what got blocked / allowed / asked; verify the chain
quill approve <tok>  confirm a pending one-shot approval (Touch ID on macOS)
quill approvals      list (hashed ids) / revoke pending approval tokens
quill receipts       per-session did / changed / uncertain / to-verify
quill trifecta       lethal-trifecta exposure tracking
quill pins           tool-description pins (anti-poisoning, anti-rug-pull)
quill decay          permissions that erode without reinforcement
quill scan-secrets   scan files for hardcoded credentials
quill scan-prompts   scan files for prompt-injection-shape patterns (signal only)
quill commit-hook-install   append a session summary to every commit message
quill doctor         diagnose the install
quill version        print the version
```

Run `quill --help` for the full list (including `night`/`off` gate-weakening toggles —
read [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) before using them).

## What's shipping today vs. on the roadmap

**Shipping (0.2.0a5), with on-disk evidence:** the Change Control flow
(`begin`/`verify`/passport + GitHub Action), the HMAC-chained audit log (32k+ entries
dogfooded, truncation-detectable, `quill audit verify` clean), the local PreToolUse
gate with Touch ID approvals and 26-pattern secret detection, the write-then-run AST
scan, and the read-side surfaces (receipts, trifecta, pins, decay). 1030 tests pass;
`ruff`, `ruff format`, and `mypy --strict` are green and enforced in CI.

**Roadmap (not shipping today, do not assume present):** PR-comment rendering of the
passport (the Action publishes a Status Check today), the lethal-trifecta enforcement
escalation as a CI signal, per-tool hook adapters for Cline / Aider / Continue /
Windsurf / Zed, WebAuthn for cross-platform hardware-attested approval, and a
`from quill import gate` BYO-agent library API. The MCP proxy, OS sandbox, desktop
dashboard, and out-of-band notification channels that earlier previews shipped were
**removed** in the Change Control pivot and are not coming back in this line.

## Security

`quill` is itself security-critical code. The threat model, the honest list of what
the gate stops well and where it can be bypassed, and the responsible-disclosure
address are in [SECURITY.md](SECURITY.md) and [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).
When PyPI publishing is wired, releases will be signed via
[PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) with PEP 740
attestations (planned, not yet in place).

## Contributing

Missed a dangerous-action class, a scope-bypass on the diff parser, or a false
positive? Open an issue with a repro. Adapters live under `src/quill/adapters/`.

## License

MIT. See [LICENSE](LICENSE). Vendored third-party code is attributed in
[NOTICE](NOTICE). Version history in [CHANGELOG.md](CHANGELOG.md). Repo:
[github.com/manumarri-sudo/quill](https://github.com/manumarri-sudo/quill).

---

Built with assistance from Claude (Anthropic).
