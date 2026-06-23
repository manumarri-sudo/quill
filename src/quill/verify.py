"""`quill verify`: compare the diff to the contract and render a verdict.

This is the heart of Change Control. Given a contract (the human-approved task
+ scope + base commit), verify:

  1. generates ``git diff <base_commit> HEAD``,
  2. runs the deterministic policy evaluation over it
     (out-of-scope paths, secret hits on added lines, sensitive surfaces),
  3. subtracts any human exceptions logged in ``.quill/exceptions.json``,
  4. composes a verdict: PASS, NEEDS_REVIEW, or BLOCK,
  5. audit-chains a ``verification.run`` event.

No AI anywhere on this path - every step is a string, glob, or regex operation,
so the verdict is reproducible and explainable line by line.
"""

from __future__ import annotations

import enum
import json
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from quill import events as ev
from quill import perimeter as perimeter_mod
from quill import policy
from quill import provenance as provenance_mod
from quill.contract import Contract, head_sha, repo_root
from quill.errors import QuillError
from quill.perimeter import GATE_TAMPER_GLOBS, Perimeter, _glob_hit
from quill.provenance import ProvenanceResult

if TYPE_CHECKING:
    from quill.audit import AuditLog
    from quill.policy import DiffEvaluation


class VerifyError(QuillError):
    """Raised when the diff cannot be generated."""


class Verdict(str, enum.Enum):
    PASS = "PASS"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    BLOCK = "BLOCK"

    @property
    def exit_code(self) -> int:
        """BLOCK fails CI (1); PASS / NEEDS_REVIEW succeed (0). NEEDS_REVIEW is
        a soft signal: it surfaces evidence for a human without failing the
        build, matching the architecture's exit-code contract."""
        return 1 if self is Verdict.BLOCK else 0


def exceptions_path(root: Path) -> Path:
    return root / ".quill" / "exceptions.json"


def load_exceptions(root: Path) -> list[dict[str, Any]]:
    """Read logged human exceptions. Tolerant: a missing or malformed file
    yields no exceptions (fail safe - an unreadable waiver file must never
    silently waive findings)."""
    p = exceptions_path(root)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = data.get("exceptions", [])
    if not isinstance(data, list):
        return []
    return [e for e in data if isinstance(e, dict)]


def git_diff(base_commit: str | None, root: Path, *, head: str = "HEAD") -> str:
    """Return ``git diff <base_commit> <head>`` for the repo at `root`.

    When no base commit is recorded (a contract created before the first
    commit), diff the empty tree against HEAD so the whole history shows up as
    additions rather than silently producing an empty - and falsely passing -
    diff.
    """
    if base_commit:
        args = ["git", "diff", base_commit, head]
    else:
        # 4b825dc... is git's well-known empty-tree object; diffing against it
        # surfaces every line as an addition.
        args = ["git", "diff", "4b825dc642cb6eb9a060e54bf8d69288fbee4904", head]
    try:
        # errors="replace": real repos contain binary blobs (images, compiled
        # fixtures) whose diff stanzas are not valid UTF-8. Strict decoding
        # would crash the gate on an innocuous binary change; replacement keeps
        # the text hunks intact and turns undecodable bytes into U+FFFD, which
        # the line-oriented parser simply ignores.
        out = subprocess.run(
            args,
            cwd=root,
            capture_output=True,
            text=True,
            errors="replace",
            check=True,
        )
    except FileNotFoundError as e:
        msg = "git not found on PATH"
        raise VerifyError(msg) from e
    except subprocess.CalledProcessError as e:
        msg = f"git diff failed: {e.stderr.strip() or e}"
        raise VerifyError(msg) from e
    return out.stdout


def _glob_match(value: str, pattern: str | None) -> bool:
    """A None/empty pattern matches anything; otherwise reuse the policy path
    matcher so exception globs behave exactly like scope globs."""
    if not pattern:
        return True
    return policy._path_matches(value, pattern)


def _waived_scope(path: str, exceptions: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    for e in exceptions:
        if e.get("type") == "scope" and _glob_match(path, e.get("path")):
            return e
    return None


def _waived_secret(
    finding: policy.SecretFinding, exceptions: Sequence[dict[str, Any]]
) -> dict[str, Any] | None:
    for e in exceptions:
        if e.get("type") != "secret":
            continue
        if not _glob_match(finding.path, e.get("path")):
            continue
        line = e.get("line")
        if line is not None and int(line) != finding.line:
            continue
        return e
    return None


def _waived_surface(
    category: str, path: str, exceptions: Sequence[dict[str, Any]]
) -> dict[str, Any] | None:
    for e in exceptions:
        if e.get("type") != "surface":
            continue
        cat = e.get("category")
        if cat and cat != category:
            continue
        if not _glob_match(path, e.get("path")):
            continue
        return e
    return None


@dataclass(frozen=True)
class VerifyResult:
    verdict: Verdict
    contract: Contract
    evaluation: DiffEvaluation
    base_commit: str | None
    head_commit: str | None
    out_of_scope: tuple[str, ...]  # unwaived
    secret_findings: tuple[policy.SecretFinding, ...]  # unwaived
    sensitive_surfaces: dict[str, tuple[str, ...]]  # unwaived
    exceptions_applied: tuple[dict[str, Any], ...]
    reasons: tuple[str, ...]
    audit_mac: str | None = None
    # Trust spine (all optional so the contract-only path is unchanged):
    provenance: ProvenanceResult | None = None  # was the perimeter signed by a human?
    forbidden_hits: tuple[str, ...] = ()  # paths the perimeter forbids outright
    gate_tamper_hits: tuple[str, ...] = ()  # edits to the gate's own trust surfaces
    perimeter_id: str | None = None
    strict: bool = False

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return self.evaluation.changed_paths


def _gate_tamper_hits(diff_text: str) -> tuple[str, ...]:
    """Diff paths that touch the gate's own trust surfaces (perimeter, approver
    keys, the workflow that runs the check). Always a BLOCK: a diff must not be
    able to edit its own judge.

    Scans the RAW parsed diff, not ``evaluation.changed_paths``, because the
    latter strips ``.quill/`` - which would hide exactly the approver-key and
    perimeter edits this check exists to catch.
    """
    paths = {f.path for f in policy.parse_unified_diff(diff_text)}
    return tuple(sorted(p for p in paths if any(_glob_hit(p, g) for g in GATE_TAMPER_GLOBS)))


def verify(
    *,
    contract: Contract,
    root: Path | None = None,
    head: str = "HEAD",
    audit: AuditLog | None = None,
    session_id: str = "quill-change-control",
    perimeter: Perimeter | None = None,
    strict: bool = False,
    env: dict[str, str] | None = None,
) -> VerifyResult:
    """Run the full verification and return a VerifyResult.

    Generates the diff, evaluates it against the contract scope, subtracts
    logged exceptions, composes the verdict, and (when an audit log is given)
    chains a ``verification.run`` event whose mac is attached to the result so a
    passport can cite the tamper-evident record.

    When a signed ``perimeter`` is supplied this also enforces the standing
    boundary (forbidden paths -> BLOCK, perimeter-chosen review surfaces) and,
    in ``strict`` mode, requires the perimeter's provenance to be a valid
    signature from a trusted approver - otherwise the boundary is unestablished
    and the verdict is BLOCK. Gate-tamper edits (the workflow, the approver keys,
    the perimeter itself) are always a BLOCK, perimeter or not.
    """
    root = repo_root(root)
    diff_text = git_diff(contract.base_commit, root, head=head)
    evaluation = policy.evaluate_diff(diff_text, contract.allowed_paths)
    exceptions = load_exceptions(root)

    applied: list[dict[str, Any]] = []

    unwaived_scope: list[str] = []
    for p in evaluation.out_of_scope:
        e = _waived_scope(p, exceptions)
        if e is None:
            unwaived_scope.append(p)
        else:
            applied.append(e)

    unwaived_secrets: list[policy.SecretFinding] = []
    for f in evaluation.secret_findings:
        e = _waived_secret(f, exceptions)
        if e is None:
            unwaived_secrets.append(f)
        else:
            applied.append(e)

    unwaived_surfaces: dict[str, list[str]] = {"tests": [], "ci": [], "lockfiles": []}
    for category, paths in evaluation.sensitive_surfaces.items():
        for p in paths:
            e = _waived_surface(category, p, exceptions)
            if e is None:
                unwaived_surfaces[category].append(p)
            else:
                applied.append(e)

    changed = evaluation.changed_paths
    gate_tamper = _gate_tamper_hits(diff_text)

    forbidden_hits: tuple[str, ...] = ()
    provenance: ProvenanceResult | None = None
    perimeter_id: str | None = None
    review_categories: set[str] | None = None  # None = report every surface (legacy)
    if perimeter is not None:
        perimeter_id = perimeter.perimeter_id
        forbidden_hits = tuple(p for p in changed if perimeter.forbids(p))
        review_categories = set(perimeter.review_surfaces)
        provenance = provenance_mod.verify_artifact(
            perimeter.to_dict(), perimeter_mod.signature_path(root), root, env
        )

    reasons: list[str] = []
    if unwaived_secrets:
        reasons.append(f"{len(unwaived_secrets)} secret(s) detected on added lines")
    if unwaived_scope:
        reasons.append(f"{len(unwaived_scope)} path(s) changed outside the approved scope")
    if forbidden_hits:
        reasons.append(f"{len(forbidden_hits)} path(s) touch a forbidden perimeter surface")
    if gate_tamper:
        reasons.append(
            f"{len(gate_tamper)} edit(s) to Quill's own trust surfaces "
            "(workflow / approver keys / perimeter)"
        )

    surface_hits = {k: v for k, v in unwaived_surfaces.items() if v}
    if review_categories is not None:
        review_hits = {k: v for k, v in surface_hits.items() if k in review_categories}
    else:
        review_hits = surface_hits
    if review_hits:
        reasons.append(
            "sensitive surfaces touched: "
            + ", ".join(f"{k} ({len(v)})" for k, v in review_hits.items())
        )

    provenance_blocks = bool(
        strict
        and perimeter is not None
        and provenance is not None
        and not provenance.status.is_trustworthy
    )
    strict_no_perimeter = bool(strict and perimeter is None)
    if provenance_blocks and provenance is not None:
        reasons.append(f"perimeter provenance not established: {provenance.detail}")
    elif perimeter is not None and provenance is not None and not provenance.status.is_trustworthy:
        # Non-strict: surface the gap as a warning without failing the build.
        reasons.append(f"warning: perimeter provenance unverified ({provenance.detail})")
    if strict_no_perimeter:
        reasons.append("strict mode requires a signed perimeter, but none is configured")

    block = bool(
        unwaived_secrets
        or unwaived_scope
        or forbidden_hits
        or gate_tamper
        or provenance_blocks
        or strict_no_perimeter
    )
    if block:
        verdict = Verdict.BLOCK
    elif review_hits:
        verdict = Verdict.NEEDS_REVIEW
    else:
        verdict = Verdict.PASS
        reasons.append(
            "diff is within the approved boundary: in scope, no secrets, nothing forbidden"
        )
        if provenance is not None and provenance.status.is_trustworthy:
            reasons.append(provenance.detail)

    head_commit = head_sha(root)

    audit_mac: str | None = None
    if audit is not None:
        audit_mac = audit.emit(
            event_type=ev.VERIFICATION_RUN,
            session_id=session_id,
            risk="high" if verdict is Verdict.BLOCK else "low",
            payload={
                "contract_id": contract.contract_id,
                "verdict": verdict.value,
                "base_commit": contract.base_commit or "",
                "head_commit": head_commit or "",
                "changed_files": len(evaluation.files),
                "out_of_scope": list(unwaived_scope),
                "secret_findings": [
                    {"path": f.path, "line": f.line, "pattern": f.pattern_name}
                    for f in unwaived_secrets
                ],
                "sensitive_surfaces": {k: list(v) for k, v in surface_hits.items()},
                "forbidden_hits": list(forbidden_hits),
                "gate_tamper_hits": list(gate_tamper),
                "perimeter_id": perimeter_id or "",
                "provenance": provenance.status.value if provenance is not None else "n/a",
                "provenance_key_id": provenance.key_id if provenance is not None else "",
                "strict": strict,
                "exceptions_applied": len(applied),
            },
        )

    return VerifyResult(
        verdict=verdict,
        contract=contract,
        evaluation=evaluation,
        base_commit=contract.base_commit,
        head_commit=head_commit,
        out_of_scope=tuple(unwaived_scope),
        secret_findings=tuple(unwaived_secrets),
        sensitive_surfaces={k: tuple(v) for k, v in unwaived_surfaces.items()},
        exceptions_applied=tuple(applied),
        reasons=tuple(reasons),
        audit_mac=audit_mac,
        provenance=provenance,
        forbidden_hits=forbidden_hits,
        gate_tamper_hits=gate_tamper,
        perimeter_id=perimeter_id,
        strict=strict,
    )
