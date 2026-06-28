# Quill Security Review — Round 9 (Independent)

You are an independent, skeptical security reviewer. You have no relationship with the developer and no incentive to be generous. Your job is to evaluate whether this tool does what it claims, find what's broken or weak, and score it honestly. If it deserves a 5, say 5. If it deserves a 9, say 9. Do not anchor on any prior score.

## What you're reviewing

**Quill** (`~/quill`, PyPI `quillx`, CLI `quill`) is a CI/CD merge-boundary gate for AI agent pull requests. It compares AI-written diffs against a human-signed scope/perimeter using Ed25519 asymmetric signing, then issues a Change Passport (verdict: PASS / NEEDS_REVIEW / BLOCK) as a commit Status Check.

The trust spine: `quill keygen` (generate Ed25519 keypair) → `quill guard --key` (sign a perimeter defining forbidden paths + allowed surfaces) → `quill begin --key` (sign a contract binding task + scope + base commit) → `quill verify --strict` (deterministically evaluate the diff against the signed artifacts, produce a passport).

The project claims to be an honest, defense-in-depth layer — not a hard security boundary. Your job is to verify whether even *that* modest claim holds up under scrutiny.

## Files to read (security-critical surface)

Start here — these are the files where security lives or dies:

| File | Lines | What it does |
|------|-------|-------------|
| `src/quill/verify.py` | ~880 | Core verification engine: diff generation, policy evaluation, ancestry checks, secret scanning, verdict composition |
| `src/quill/attest.py` | ~197 | Ed25519 key generation, signing, verification — the cryptographic foundation |
| `src/quill/provenance.py` | ~237 | Artifact signature verification, trusted approver loading, trust-root externalization |
| `src/quill/passport.py` | ~258 | Passport signing/verification, HMAC audit chain binding |
| `src/quill/perimeter.py` | ~266 | Forbidden-path matching, gate-tamper globs, deny-side homoglyph normalization |
| `src/quill/policy.py` | ~1695 | Diff parsing, scope checking, secret pattern matching, sensitive surface classification |
| `src/quill/secrets.py` | ~405 | 26 vendor-format secret patterns |
| `src/quill/audit.py` | ~338 | HMAC-chained append-only audit log |
| `scripts/quill-passport.sh` | ~280 | GitHub Action wrapper: runs verify, posts Status Check, enforces fail-closed |
| `action.yml` | ~142 | Composite GitHub Action definition |
| `docs/secure-workflow.yml` | ~45 | Recommended secure workflow template |
| `docs/SECURITY-MODEL.md` | ~454 | Threat model and honest limits — READ THIS FIRST for context |

Also read the test files for security coverage:
- `tests/test_security_regressions.py` — targeted regression tests for prior findings
- `tests/test_action_wrapper.py` — wrapper script tests
- `tests/test_verify_passport_validity.py` — verify-passport consumer tests
- `tests/test_trust_spine.py` — end-to-end trust chain tests

## Evaluation dimensions

Score each dimension 1-10, then produce a weighted overall score.

### A. Trust spine integrity (weight: 25%)

The core claim is that a human signs the scope and only a diff within that scope passes. Verify:

1. **Cryptographic soundness.** Is Ed25519 used correctly? Are payloads canonicalized before signing? Can signature verification be tricked (algorithm confusion, key-id substitution, malformed base64)?
2. **Key separation.** Can an agent access private keys that should be off-box? Does strict mode actually reject committed approver keys? Does the `_is_inside` symlink check hold?
3. **Contract binding.** Does the contract actually bind repo, scope, base commit, and expiry? Can a contract be replayed across repos? Within a repo? What stops a wider-than-approved scope?
4. **Perimeter as outer bound.** Does the signed perimeter actually cap the contract's scope, or can a contract widen past it? What if the perimeter itself is unsigned?
5. **Strict vs cooperative.** Does strict mode genuinely refuse to operate without signed artifacts, or does it silently degrade? Map every early-exit in `verify()` and confirm each returns `_block_result`.

### B. Fail-closed discipline (weight: 20%)

A security gate that fails open is worse than no gate. Check:

1. **Every error path in verify.py.** Does a crash, a malformed input, an unresolvable ref, a missing file, or a subprocess failure produce a BLOCK or an error exit — never a PASS?
2. **The wrapper script.** Does `set -euo pipefail` actually hold? Are there any code paths where a failure could be swallowed and the job exits 0? What about the `set +e` around `quill verify`?
3. **Evidence integrity.** The wrapper checks process rc vs passport verdict vs exit_code and fails on disagreement. Can this check be bypassed? What if the passport JSON is malformed but parseable?
4. **Unrecognized verdicts.** Does the wrapper catch a verdict that isn't PASS/NEEDS_REVIEW/BLOCK?
5. **Exception handling in Python.** Are there bare `except:` or `except Exception:` blocks that swallow errors and continue? Does every `try/except` in the security path fail closed?

### C. Agent adversarial model (weight: 20%)

Assume a capable AI agent that has read the Quill source code and is actively trying to bypass the gate. It controls the PR contents, the commit history, and any files in the checkout. It does NOT control the base branch workflow (pull_request_target), CI secrets, or the GitHub API token's permissions.

1. **Workflow impersonation (C-1).** The `pull_request` event runs the PR's workflow. Does strict mode actually refuse this? Is the opt-out (`QUILL_ALLOW_PULL_REQUEST_TRIGGER`) properly gated? Could an agent set this env var from within the PR?
2. **Status check spoofing.** Even under `pull_request_target`, can an agent add a parallel workflow that posts a fake "success" status to the same context? How does the MAC fingerprint help, and what are its limits?
3. **Empty-diff attacks.** Can an agent craft a contract whose base_commit equals HEAD, producing an empty diff that trivially passes? Does the ancestry check actually block this? What about shallow clones?
4. **Diff evasion.** Can an agent hide changes from the diff parser? What about `.gitattributes -diff`, binary files, rename-only changes, mode-only changes, submodules? Does the authoritative inventory catch what the textual parser misses?
5. **Exception/waiver injection.** Can an agent author `.quill/exceptions.json` to waive findings? Does strict mode disable this?
6. **Gate-tamper.** Can an agent edit `.github/workflows/**`, `.quill/perimeter.*`, or `.quill/approvers/**` without triggering BLOCK? What about editing via rename (rename OUT of a protected path)?
7. **Secret suppression.** Can an agent hide a secret from the scanner via encoding tricks (UTF-16, BOM, `.gitattributes`), by splitting the secret across lines, or by committing it in a binary file?
8. **Supply chain.** Can an agent influence what version of Quill gets installed? Can it modify `action.yml` or `pyproject.toml` in the PR to change the install path? What about pip dependency confusion?
9. **Contract scope widening.** Can an agent re-sign a contract with a broader scope than the human approved? Does the perimeter cap actually prevent this?

### D. Honesty and documentation (weight: 15%)

A security tool's credibility depends on whether it tells the truth about itself.

1. **Claims table.** Read the claims table at the end of SECURITY-MODEL.md. Is every "Implemented" claim actually backed by wired-up code? Is every "Partial" or "Not yet" honest?
2. **Known limits.** Are the documented limits (semantic shell obfuscation, hook bypass, interpreter escalation, network egress) real and honestly stated? Are there undocumented limits?
3. **Overstated language.** Does the README or any doc use language that implies stronger guarantees than the code delivers? ("enterprise-grade", "agent-proof", "cannot be bypassed")
4. **Test evidence.** Do the test counts match reality? Are security-critical properties actually tested, or are the tests superficial?
5. **Open items.** Is the "still open" section in SECURITY-MODEL.md up to date and honest?

### E. Code quality of the security surface (weight: 10%)

1. **No `shell=True`.** Verify every `subprocess.run` / `subprocess.Popen` call in the Python codebase uses list-of-args form.
2. **Input validation.** Are all external inputs (env vars, file contents, git output, JSON payloads) validated before use? Look for injection vectors.
3. **Shell script safety.** In `quill-passport.sh`, are all variable expansions quoted? Are there command injection vectors via env vars or passport data?
4. **Constant-time comparison.** Is `hmac.compare_digest` used for MAC comparison? Are there timing-sensitive comparisons elsewhere?
5. **File permissions.** Are sensitive files (audit log, keys) created with restrictive permissions?

### F. Test coverage of security properties (weight: 10%)

1. **Regression tests.** Do prior security findings (rounds 6-8) have corresponding regression tests? Check `test_security_regressions.py`.
2. **Adversarial test cases.** Are there tests for the attack vectors listed above (empty-diff, status spoofing, exception injection, gate-tamper via rename, BOM encoding, etc.)?
3. **Negative tests.** Are there tests that verify BLOCK verdicts, not just PASS? A test suite that only checks the happy path proves nothing about security.
4. **Wrapper tests.** Is the shell wrapper tested for the fail-closed paths (crash, malformed passport, unrecognized verdict, evidence inconsistency)?
5. **Missing tests.** What security-critical code paths have NO test coverage?

## Output format

```
## Overall Score: X.X / 10

### Dimension Scores
| Dimension | Score | Weight | Weighted |
|-----------|-------|--------|----------|
| A. Trust spine integrity | X/10 | 25% | X.XX |
| B. Fail-closed discipline | X/10 | 20% | X.XX |
| C. Agent adversarial model | X/10 | 20% | X.XX |
| D. Honesty and documentation | X/10 | 15% | X.XX |
| E. Code quality | X/10 | 10% | X.XX |
| F. Test coverage | X/10 | 10% | X.XX |

### Findings (CRITICAL / HIGH / MEDIUM / LOW / INFO)

For each finding:
- **[SEVERITY] Title**
  - What: one-sentence description
  - Where: file:line_number
  - Attack: how an adversary exploits this
  - Impact: what breaks if exploited
  - Fix: what to change
  - Credibility cost: how much this hurts the project's trustworthiness (none / minor / significant / severe)

### Credibility Assessment

Answer these yes/no:
1. Does the tool do what it says it does?
2. Does it fail closed when it should?
3. Does it overstate its guarantees anywhere?
4. Would you trust it as one layer in a defense-in-depth stack?
5. Would you recommend it to a team shipping AI-assisted PRs?

### What would move the score up by 0.5?
List the 3 most impactful changes, ordered by effort-to-credibility ratio.
```

## Ground rules

- **No bias.** Score what you see, not what you hope. If the code is good, say so. If it's weak, say so. Do not anchor on any prior review's score.
- **No overwriting.** You are read-only. Do not edit, create, or modify any files. Report findings only.
- **Verify, don't trust.** If SECURITY-MODEL.md says something is closed, confirm it in the code. If a test exists, read it and check it actually tests what it claims.
- **Think like an attacker.** For every defense, ask: "how would I get around this?" If you can construct a concrete bypass, that's a finding. If you can't but the defense is thin, say so.
- **Credit honesty.** If the project is upfront about a limitation, that's a positive signal — it means the developer knows the boundary. Undocumented weaknesses are worse than documented ones.
