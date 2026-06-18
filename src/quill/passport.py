"""The Quill Change Passport: the evidence artifact a verification produces.

A passport is a small, self-contained summary of one `quill verify` run - the
verdict, the contract it was measured against, and the evidence behind it (scope
violations, secret hits, sensitive surfaces, applied exceptions). It is rendered
two ways from the same VerifyResult:

  - ``passport.json`` - machine-readable, for downstream tooling / status checks.
  - ``passport.md``   - human-readable, designed to be posted on a pull request.

The passport cites the ``verification.run`` audit mac, so a reader can trace the
verdict back to the tamper-evident chain rather than trusting the markdown alone.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from quill.verify import Verdict, VerifyResult

_VERDICT_BADGE = {
    Verdict.PASS: "✅ PASS",
    Verdict.NEEDS_REVIEW: "⚠️ NEEDS REVIEW",
    Verdict.BLOCK: "⛔ BLOCK",
}


def build_passport(result: VerifyResult, *, generated_at: str | None = None) -> dict[str, Any]:
    """Assemble the machine-readable passport from a VerifyResult."""
    c = result.contract
    return {
        "schema": "quill.change-passport/v1",
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "verdict": result.verdict.value,
        "exit_code": result.verdict.exit_code,
        "contract": {
            "id": c.contract_id,
            "task": c.task,
            "task_source": c.task_source,
            "allowed_paths": list(c.allowed_paths),
            "approved_by": c.approved_by,
            "created_at": c.created_at,
        },
        "base_commit": result.base_commit,
        "head_commit": result.head_commit,
        "reasons": list(result.reasons),
        "evidence": {
            "changed_files": list(result.changed_paths),
            "out_of_scope": list(result.out_of_scope),
            "secret_findings": [
                {"path": f.path, "line": f.line, "pattern": f.pattern_name}
                for f in result.secret_findings
            ],
            "sensitive_surfaces": {k: list(v) for k, v in result.sensitive_surfaces.items() if v},
            "exceptions_applied": list(result.exceptions_applied),
        },
        "audit": {"verification_run_mac": result.audit_mac},
    }


def render_markdown(result: VerifyResult, *, generated_at: str | None = None) -> str:
    """Render the PR-ready markdown passport."""
    c = result.contract
    badge = _VERDICT_BADGE[result.verdict]
    ts = generated_at or datetime.now(UTC).isoformat()
    lines: list[str] = []
    lines.append("# Quill Change Passport")
    lines.append("")
    lines.append(f"## Verdict: {badge}")
    lines.append("")
    for r in result.reasons:
        lines.append(f"- {r}")
    lines.append("")

    lines.append("## Contract")
    lines.append("")
    lines.append(f"- **Task:** {c.task}")
    lines.append(f"- **Contract id:** `{c.contract_id}`")
    if c.approved_by:
        lines.append(f"- **Approved by:** {c.approved_by}")
    scope = ", ".join(f"`{p}`" for p in c.allowed_paths) or "_(no path restriction)_"
    lines.append(f"- **Approved scope:** {scope}")
    lines.append(f"- **Base commit:** `{_short(result.base_commit)}`")
    lines.append(f"- **Head commit:** `{_short(result.head_commit)}`")
    lines.append("")

    lines.append("## Evidence")
    lines.append("")
    changed = result.changed_paths
    lines.append(f"### Changed files ({len(changed)})")
    lines.append("")
    if changed:
        for p in changed:
            lines.append(f"- `{p}`")
    else:
        lines.append("_No changes between base and head._")
    lines.append("")

    lines.append(f"### Out-of-scope paths ({len(result.out_of_scope)})")
    lines.append("")
    if result.out_of_scope:
        for p in result.out_of_scope:
            lines.append(f"- ⛔ `{p}` — outside approved scope")
    else:
        lines.append("_None — every change is within the approved scope._")
    lines.append("")

    secrets = result.secret_findings
    lines.append(f"### Secret scan ({len(secrets)})")
    lines.append("")
    if secrets:
        for f in secrets:
            lines.append(f"- ⛔ `{f.path}:{f.line}` — {f.pattern_name}")
    else:
        lines.append("_No secrets detected on added lines._")
    lines.append("")

    surfaces = {k: v for k, v in result.sensitive_surfaces.items() if v}
    lines.append("### Sensitive surfaces")
    lines.append("")
    if surfaces:
        for category, paths in surfaces.items():
            lines.append(f"- **{category}:**")
            for p in paths:
                lines.append(f"  - `{p}`")
    else:
        lines.append("_No tests, CI workflows, or lockfiles touched._")
    lines.append("")

    if result.exceptions_applied:
        lines.append(f"### Human exceptions applied ({len(result.exceptions_applied)})")
        lines.append("")
        for e in result.exceptions_applied:
            reason = e.get("reason", "(no reason given)")
            target = e.get("path") or e.get("category") or "*"
            lines.append(f"- `{e.get('type', '?')}` on `{target}` — {reason}")
        lines.append("")

    lines.append("---")
    mac = result.audit_mac or "(not chained)"
    lines.append(f"_Generated {ts} · verification.run audit mac: `{_short(mac, 16)}`_")
    lines.append("")
    return "\n".join(lines)


def write_passport(
    result: VerifyResult,
    *,
    out_dir: Path,
    generated_at: str | None = None,
) -> tuple[Path, Path]:
    """Write passport.json and passport.md into `out_dir`. Returns both paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "passport.json"
    md_path = out_dir / "passport.md"
    json_path.write_text(
        json.dumps(build_passport(result, generated_at=generated_at), indent=2) + "\n"
    )
    md_path.write_text(render_markdown(result, generated_at=generated_at))
    return json_path, md_path


def _short(sha: str | None, n: int = 12) -> str:
    if not sha:
        return "—"
    return sha[:n]
