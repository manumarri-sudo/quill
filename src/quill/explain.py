"""Deterministic remediation layer over a Change Passport.

Turns passport.json findings into three-part remediation records a
non-technical reader can act on: what's wrong in plain English, a concrete
self-fix (with a literal shell command where one applies), and a paste-ready
instruction for the coding agent. Pure rendering over existing evidence —
no model anywhere, same as the verdict itself.

The `plain` field must never use gate jargon (perimeter, provenance, MAC,
surface); tests enforce this.
"""

from __future__ import annotations

from typing import Any

CLOSER = "Fix these {n} thing(s), commit again, and re-run the check."

PASS_LINE = "✅ You're good — this change is inside what was approved. Nothing to do."

_REVIEW_INTRO = (
    "⚠️  This change needs a human to look at it before it merges — that's a "
    "checkpoint, not a failure. Here's what to look at and why."
)
_BLOCK_INTRO = "⛔ This change can't be merged yet. Here's what's wrong and how to fix each one."


def build_remediations(passport: dict[str, Any]) -> list[dict[str, str]]:
    """Map passport evidence to remediation records, most severe first.

    De-duplication: a path reported by several checks is reported once under
    the most specific reason (gate-tamper over forbidden over out-of-scope).
    """
    ev = passport.get("evidence", {})
    task = passport.get("contract", {}).get("task", "")
    out: list[dict[str, str]] = []

    tamper = list(ev.get("gate_tamper_hits", []))
    forbidden = [p for p in ev.get("forbidden_hits", []) if p not in tamper]
    covered = set(tamper) | set(forbidden)

    for s in ev.get("secret_findings", []):
        out.append(
            {
                "kind": "secret",
                "where": f"{s['path']}:{s['line']}",
                "plain": (
                    f"A password or key ({s['pattern']}) is written directly in the "
                    "code — anyone who sees the file can steal it."
                ),
                "self_fix": (
                    f"Delete line {s['line']} of {s['path']} and load the value from "
                    "an environment variable instead."
                ),
                "cc_prompt": (
                    f"In {s['path']} line {s['line']} there is a hardcoded "
                    f"{s['pattern']}. Remove it and read it from an environment "
                    "variable instead, and make sure the real value is never "
                    "committed anywhere."
                ),
            }
        )

    for p in tamper:
        out.append(
            {
                "kind": "gate_tamper",
                "where": p,
                "plain": (
                    "This change edits Quill's own safety settings — that is "
                    "always blocked, no matter the task."
                ),
                "self_fix": (
                    f"Undo it: git checkout {p} — these files must not change in a normal task."
                ),
                "cc_prompt": (
                    f"Revert {p}; I should not modify Quill's own configuration, "
                    "keys, or workflow files."
                ),
            }
        )

    for p in forbidden:
        out.append(
            {
                "kind": "forbidden",
                "where": p,
                "plain": (
                    "This edits a protected area a human marked off-limits for automatic changes."
                ),
                "self_fix": (
                    f"Undo it: git checkout {p} — or ask the project owner to approve this edit."
                ),
                "cc_prompt": (
                    f"Undo my changes to {p}; it's a protected area I wasn't allowed to touch."
                ),
            }
        )

    for p in ev.get("out_of_scope", []):
        if p in covered:
            continue
        out.append(
            {
                "kind": "out_of_scope",
                "where": p,
                "plain": (f'This file has nothing to do with the approved task "{task}".'),
                "self_fix": f"Undo it: git checkout {p}",
                "cc_prompt": (
                    f"Undo my changes to {p} — it was outside the task "
                    f"'{task}'. Keep only changes that belong to that task."
                ),
            }
        )

    for c in ev.get("symlink_changes", []):
        target = c.get("target") or "(unreadable)"
        out.append(
            {
                "kind": "symlink",
                "where": c["path"],
                "plain": (
                    f"A link was added at {c['path']} pointing to {target}. Links "
                    "can quietly redirect an approved location at something "
                    "off-limits, so a human has to confirm this one."
                ),
                "self_fix": (
                    f"If the link isn't needed, undo it: git checkout {c['path']} "
                    "— otherwise confirm the target is intended."
                ),
                "cc_prompt": (
                    f"Explain why {c['path']} is a symlink to {target} and replace "
                    "it with a regular file unless the link is genuinely required."
                ),
            }
        )

    for c in ev.get("submodule_changes", []):
        out.append(
            {
                "kind": "submodule",
                "where": c["path"],
                "plain": (
                    "A sub-project pointer moved; a human needs to check which "
                    "version was pulled in."
                ),
                "self_fix": (
                    "Confirm the new version is intended, or undo the pointer "
                    f"change: git checkout {c['path']}"
                ),
                "cc_prompt": (
                    f"Explain what changed in the submodule at {c['path']} and "
                    "whether the new commit is safe to pull in."
                ),
            }
        )

    for name, paths in ev.get("sensitive_surfaces", {}).items():
        for p in paths:
            out.append(
                {
                    "kind": "sensitive",
                    "where": p,
                    "plain": (
                        f"This touches a sensitive area ({name}) that always gets "
                        "a human look before merging — it may be fine, it just "
                        "can't be auto-approved."
                    ),
                    "self_fix": (
                        "If the edit is part of the task, ask a reviewer to look; "
                        f"if it isn't, undo it: git checkout {p}"
                    ),
                    "cc_prompt": (
                        f"Explain why the task required changing {p} so a "
                        "reviewer can approve it quickly."
                    ),
                }
            )

    for d in ev.get("scan_dispositions", []):
        out.append(
            {
                "kind": "scan_incomplete",
                "where": "",
                "plain": (
                    f"The change was too big to fully check, so it can't be auto-approved ({d})."
                ),
                "self_fix": (
                    "Split the change into smaller pull requests, or raise the "
                    "size limit if you trust it."
                ),
                "cc_prompt": "",
            }
        )

    return out


def explain_dict(passport: dict[str, Any]) -> dict[str, Any]:
    """The machine-readable form of `quill explain` (and of the passport block)."""
    remediations = build_remediations(passport)
    return {
        "verdict": passport.get("verdict", ""),
        "task": passport.get("contract", {}).get("task", ""),
        "allowed_paths": list(passport.get("contract", {}).get("allowed_paths", [])),
        "remediations": remediations,
        "closer": CLOSER.format(n=len(remediations)),
    }


def render_text(passport: dict[str, Any]) -> str:
    """Human terminal rendering: numbered issues, friendly closer."""
    verdict = passport.get("verdict", "")
    if verdict == "PASS":
        return PASS_LINE + "\n"

    d = explain_dict(passport)
    lines = [_BLOCK_INTRO if verdict == "BLOCK" else _REVIEW_INTRO, ""]
    if d["task"]:
        lines.append(f'The approved task was: "{d["task"]}"')
    if d["allowed_paths"]:
        lines.append(f"Approved area: {', '.join(d['allowed_paths'])}")
    lines.append("")

    for n, r in enumerate(d["remediations"], start=1):
        where = f"   Where: {r['where']}" if r["where"] else None
        lines.append(f"── Issue {n}: {r['plain']}")
        if where:
            lines.append(where)
        lines.append(f"   Fix it yourself: {r['self_fix']}")
        if r["cc_prompt"]:
            lines.append("   Or paste this to your coding agent:")
            lines.append(f'     "{r["cc_prompt"]}"')
        lines.append("")

    lines.append(d["closer"])
    return "\n".join(lines) + "\n"
