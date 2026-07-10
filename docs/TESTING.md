# Notari manual testing guide

This is a step-by-step script for testing Notari from scratch. It assumes you
have never seen this tool before. Every step tells you exactly what to type,
what you should see, and what it means if you don't see it. Total time:
about 25 minutes for Parts 1 to 4; Part 5 is optional and needs a GitHub repo.

**What Notari is, in one sentence:** it checks that a change to a code repo
stayed inside a boundary a human signed off on, and gives a PASS /
NEEDS_REVIEW / BLOCK verdict with evidence.

**What you need:**

- macOS or Linux, a terminal, and `git`
- Python 3.11+ with [`uv`](https://docs.astral.sh/uv/) or `pipx`
  (any one of them; the steps below use `uvx`, which needs no install step)
- 25 minutes

**How to report what you find:** open an issue at
<https://github.com/manumarri-sudo/notari/issues>. A "this step didn't match
the doc" report is exactly as valuable as a bug. Include the step number, what
you typed, and what you saw.

---

## Part 1: install and first look (2 minutes)

### 1.1 Run it without installing anything

```bash
uvx notari --version
```

**You should see:** `notari 0.3.3` (or newer).
**If not:** `pipx install notari && notari --version` is the fallback. If both
fail, your report is "install broken on <OS> with <Python version>", and that
is a great report.

> All later steps write `uvx notari ...`. If you installed with pipx, just
> type `notari ...` instead.

### 1.2 Look at the help

```bash
uvx notari --help
```

**You should see:** three groups of commands, not a wall:
**Core** (`begin`, `verify`, `explain`, `init`, `status`),
**Safety** (`off`, `on`, `approve`), and
**Health & evidence** (`doctor`, `version`, `audit`).

**Check:** does the help alone tell you what to do first? If you cannot answer
"what would I type next" within 30 seconds, note that in your report.

---

## Part 2: the happy path (8 minutes)

You will make a throwaway repo, sign a boundary, and watch a good change PASS.
Nothing here touches your real projects.

### 2.1 Make a sandbox repo

```bash
mkdir -p /tmp/notari-test && cd /tmp/notari-test
git init demo && cd demo
git config user.email you@test.local && git config user.name tester
mkdir -p src migrations
echo "x = 1" > src/app.py
git add -A && git commit -m "first commit"
```

### 2.2 Create the approver key

```bash
uvx notari keygen --out approver.pem
export NOTARI_APPROVER_PUBKEYS="$(cat approver.pem.pub)"
```

**You should see:** four green check lines, including one that says it
**gitignored** `/approver.pem` and `/approver.pem.pub`.
**Why that matters:** the private key must never be committed; Notari protects
you from your own `git add -A`.

**Check:** `cat .gitignore` shows both entries.

### 2.3 Sign the boundary

```bash
uvx notari guard --key approver.pem --allow "src/**" --forbid "migrations/**"
git add -A && git commit -m "notari: signed boundary"
```

This says: agents may work in `src/`, may never touch `migrations/`. The
commit step matters and the ORDER matters: the boundary must be committed
BEFORE the next step.

### 2.4 Open a task contract

```bash
uvx notari begin "add a feature" --scope "src/**" --key approver.pem
git add -A && git commit -m "notari: open task contract"
```

**You should see:** a green line saying the contract was written and
`(signed)`, plus the task, scope, and base commit.
**You should NOT see:** a yellow "heads-up: uncommitted setup file(s)" warning.
If you do, you skipped the commit in 2.3; run it and redo 2.4.

### 2.5 Make a good change and verify it

```bash
echo "y = 2" >> src/app.py
git add -A && git commit -m "in-scope change"
uvx notari verify
```

**You should see:** a verdict of **PASS** with the reason "diff is within the
approved boundary: in scope, no secrets, nothing forbidden", and a note that
it is signed by your approver key. Also a yellow "cooperative mode" warning;
that is honest, not an error (it means the trust root is still on this
machine; Part 5 is what removes it).

**Check the exit code:**

```bash
echo $?
```

**You should see:** `0`.

---

## Part 3: watch bad changes get caught (8 minutes)

### 3.1 A forbidden-path change

```bash
echo "-- sneaky" >> migrations/evil.sql 2>/dev/null || { mkdir -p migrations && echo "-- sneaky" > migrations/evil.sql; }
git add -A && git commit -m "touch a forbidden path"
uvx notari verify
```

**You should see:** **BLOCK**, with a reason naming a forbidden perimeter
surface. If you are in a normal terminal (not a script), a **fix-it page
should open in your browser** automatically; it lists each problem in plain
English with a copy-paste fix. (Set `NOTARI_OPEN=never` to suppress that.)

**Check the exit code:** `echo $?` shows `1`. A BLOCK fails a build.

### 3.2 A hardcoded secret

```bash
printf 'KEY = "AKIA%s"\n' "IOSFODNN7EXAMPLE" >> src/config.py
git add -A && git commit -m "add a fake AWS key"
uvx notari verify
```

**You should see:** **BLOCK** with "secret(s) detected on added lines"
(the fake key above is Amazon's official documentation example, safe to use).

### 3.3 Read the explanation

```bash
uvx notari explain
```

**You should see:** a plain-English list: what is wrong, where, how to fix it
yourself, and a paste-ready instruction for a coding agent. It should be
readable by someone who has never used Notari.

**Check:** it also states what Notari does NOT prove (it does not judge
whether code is correct). If any sentence oversells, report it.

### 3.4 Clean up the bad changes and confirm PASS again

```bash
git revert --no-edit HEAD HEAD~1
uvx notari verify
```

**You should see:** PASS again. (Reverts of the bad commits count as in-scope
changes to `src/` plus the forbidden file returning to its original state.)
If you see NEEDS_REVIEW instead, read the reason it prints and include it in
your report; reverts that touch a forbidden path are a known review-worthy
shape.

---

## Part 4: try to cheat (5 minutes, the fun part)

Notari's docs claim specific things. Try to break them.

### 4.1 Commit the private key on purpose

```bash
sed -i.bak '/approver.pem/d' .gitignore && rm .gitignore.bak
git add -A -f && git commit -m "smuggle the key"
uvx notari verify
```

**You should see:** **BLOCK** with a secret finding (a PEM private key on
added lines). Restore afterwards:

```bash
git revert --no-edit HEAD && uvx notari verify >/dev/null; git checkout -- . 
```

### 4.2 Edit the boundary itself from "inside" the work

```bash
echo " " >> .notari/perimeter.json
git add -A && git commit -m "tamper with the perimeter"
uvx notari verify
```

**You should see:** **BLOCK**. The perimeter file no longer matches its
signature, so provenance fails. An agent cannot rewrite the rules it is
judged by. Restore:

```bash
git revert --no-edit HEAD
```

### 4.3 Point a symlink at a forbidden file

```bash
ln -s ../migrations/evil.sql src/alias.sql 2>/dev/null || ln -s ../migrations src/alias
git add -A && git commit -m "symlink into forbidden territory"
uvx notari verify
```

**You should see:** **NEEDS_REVIEW** (not PASS), with the symlink and its
target named. Notari refuses to silently pass links whose content its
scanners cannot see.

### 4.4 Your own ideas

Anything that gets an out-of-scope, forbidden, or secret-bearing change to
**PASS** is a security finding. Please report it with the exact commands; the
project explicitly asks for bypass attempts.

---

## Part 5 (optional, advanced): the real boundary in CI

Everything above ran in "cooperative" mode: honest checking, but the keys
live on the same machine, so a malicious agent could theoretically re-sign
things. The enforced mode moves trust off the machine. This needs a GitHub
repo you own.

```bash
uvx notari init          # writes the hardened workflow + keys, guided
uvx notari status        # tells you the exact remaining steps
```

**You should see:** `status` honestly reports the posture (unconfigured /
cooperative / enforced) and lists precisely what is missing (usually: set two
repo secrets, delete the local private keys, make the check required in
branch protection). Follow what it prints; when done, open a PR that touches
a forbidden path and confirm the check fails the PR.

**Check:** at no point should `status` claim you are enforced while a private
key still exists on your machine. If it does, that is a high-priority report.

---

## Part 6: cleanup

```bash
cd / && rm -rf /tmp/notari-test
```

If you used `pipx`: `pipx uninstall notari`.

---

## Results checklist

Copy this into your issue or message and mark each line:

```text
[ ] 1.1 install works, version prints
[ ] 1.2 help is three panels; next step was obvious within 30s
[ ] 2.2 keygen auto-gitignored both key files
[ ] 2.4 begin: contract written signed, no ordering warning
[ ] 2.5 good change: PASS, exit 0
[ ] 3.1 forbidden path: BLOCK, exit 1, fix-it page opened
[ ] 3.2 secret: BLOCK
[ ] 3.3 explain was readable by a stranger
[ ] 3.4 reverts: PASS again (or noted the printed reason)
[ ] 4.1 committed key: BLOCK
[ ] 4.2 tampered perimeter: BLOCK
[ ] 4.3 symlink: NEEDS_REVIEW
[ ] 4.4 my own bypass attempts: (describe)
[ ] 5   (optional) status was honest about posture
Notes / surprises / anything that felt confusing:
```

Thank you. A confusing sentence in our docs is a bug just like a wrong
verdict is; report both.
