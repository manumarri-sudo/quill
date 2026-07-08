# Quill Quickstart

Get from zero to a blocked bad PR in about ten minutes. Everything here is free
and open source, runs locally, and needs no account.

## What Quill does in one sentence

Quill checks every AI-authored change against a **human-signed boundary** (the
paths agents may and may never touch) and issues a **Change Passport** — a
deterministic PASS / NEEDS_REVIEW / BLOCK verdict with the evidence behind it — so
an autonomous coding agent cannot quietly edit your workflows, your migrations, or
leak a secret without a human seeing it.

## Install

```bash
pipx install quillx      # installs the `quill` command
quill --version
```

## 1. Set up the boundary (about 2 minutes)

```bash
cd your-repo
quill init
```

`quill init` generates an approver keypair and a gate keypair, signs a
secure-by-default perimeter, writes the **secure** GitHub workflow
(`pull_request_target`, SHA-pinned, PR checked out into a data-only directory),
and gitignores your private keys. It finishes by printing your posture and the
exact steps left to make the boundary real.

## 2. Declare what agents may never touch

```bash
quill guard \
  --key .quill/keys/approver.pem \
  --forbid ".github/workflows/**" \
  --forbid "migrations/**" \
  --forbid ".quill/keys/**"
```

Forbidden paths **BLOCK** unconditionally — even a signed contract cannot widen
past them. This is your outer perimeter. (`--key` is the approver private key
`quill init` generated; it re-signs the perimeter so the change is trusted.)

## 3. Sign a scoped task (about 1 minute)

```bash
quill begin "add rate limiting to the API" \
  --scope "src/api/**" \
  --key .quill/keys/approver.pem \
  --expires-in 7
```

Pass `--key` so the contract is **signed** — an unsigned contract cannot establish
provenance under `quill verify --strict` (the CI default), so the boundary wouldn't
actually enforce. `--expires-in` takes a number of days; after it lapses,
`quill verify --strict` BLOCKs so a stale approval can't authorize work forever. In
CI the repo is bound automatically from `$GITHUB_REPOSITORY`; locally pass `--repo
owner/name`.

This writes a signed contract binding the work to a scope, an expiry, and — when
`$GITHUB_REPOSITORY` or `--repo` is present — this repository, so the approval
cannot be replayed elsewhere.

Now commit the boundary you just set up, as its own commit, **before** any agent
work. `quill begin` recorded this commit as the contract's *base*; `quill verify`
later diffs everything after it, so the setup must land first:

```bash
git add .quill && git commit -m "quill: sign boundary + open contract"
```

## 4. Watch a bad change get blocked

```bash
# An agent edits a workflow it was never scoped to touch, in a NEW commit
# on top of the base the contract recorded:
echo "# tampered" >> .github/workflows/ci.yml
git add -A && git commit -m "sneaky workflow edit"

quill verify
```

You get a **BLOCK** with a Change Passport that names the exact forbidden surface.
(If instead you see a PASS with a warning that "the diff is empty," the bad change
landed in the same commit as the contract base — make it a separate commit on top,
as above, so there is a diff to check.)
Try the same with an out-of-scope file, or a line like `AWS_SECRET_ACCESS_KEY=...`,
and you will see the scope and secret findings respectively.

## 5. Explain the failure and fix it with your agent

```bash
quill explain
quill explain --fix-prompt
```

`quill explain` turns the passport into plain English: per finding, what's wrong,
the exact `git` command to undo it, and what Quill does *not* prove (it checks the
boundary, not whether the code is correct). `--fix-prompt` emits a compact prompt
you paste into Claude Code, Codex, Cursor, or another coding agent — it tells the
agent exactly what to revert, split, or ask approval for, without dumping the full
passport into context. (`--format html` writes a click-to-copy page for a
non-technical reviewer.)

## 6. Turn repeated failures into repo lessons

```bash
quill lessons
quill lessons promote <lesson-id>
quill teach --agents claude,codex,cursor
quill agent-brief
```

`quill lessons` aggregates the mistakes recorded locally in `.quill/mistakes.jsonl`
and suggests a short, reusable lesson for each repeated pattern. Promote the ones you
agree with, then `quill teach` writes them into `CLAUDE.md`, `AGENTS.md`, or Cursor
rules inside a managed block (your own content is preserved). Future agents read them
before they start. **This is local by default — no code, diffs, prompts, or secret
values ever leave your machine, and no lesson is applied without your promotion.**

## 7. Ask what is still missing for a *real* boundary

```bash
quill status
```

Quill is honest here. A key sitting on the same laptop the agent runs on is **not**
a boundary — the agent runs as you and can read it. `quill status` reports:

- 🔴 **unconfigured** — no signed perimeter yet
- 🟡 **cooperative** — honest review automation, but the trust root is still
  reachable by the agent (a local/committed key)
- 🟢 **enforced** — the approver trust root is off-box (a CI secret or hardware
  key), the gate runs pinned trusted code, and a required status check gates merge

To reach 🟢 you move three things off the machine (Quill prints the commands):

```bash
gh secret set QUILL_GATE_KEY < .quill/keys/gate.pem
gh secret set QUILL_APPROVER_PUBKEYS < .quill/keys/approver.pub
# then delete the local private keys, and make the `quill/change-control`
# status check REQUIRED in branch protection on main.
```

## 8. Confirm your environment

```bash
quill doctor
```

Checks Python, the installed Quill version, keys, the workflow, dependencies, the
Action wiring, and the audit chain, and tells you what to fix.

---

**Next:** read [`SECURITY-MODEL.md`](SECURITY-MODEL.md) for the threat model and the
control/data separation, and [`PRODUCT.md`](PRODUCT.md) for what stays free forever
versus what the paid team tiers add.
