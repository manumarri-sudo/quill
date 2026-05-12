"""Agent Receipts - derived audit-log artifact.

A Receipt is what the agent actually did during a session, in the human-readable
form auditors and the user both want:
    did[]         - distinct actions performed
    changed[]     - files the agent mutated
    uncertain[]   - high/critical-risk calls the human allowed (or the agent
                    self-flagged with agent.flag.uncertain)
    to_verify[]   - explicit "please confirm" items the agent surfaced
    trust_delta   - net change in (executed - blocked - asked)
    intervention_count
    tdr_contribution

Receipts are *derived* from the existing audit log; nothing new is written
unless the user explicitly runs `quill receipts emit` to write a session.receipt
event back to the chain.

Schema source: docs/research/agent-trust-infra-2026-05.md §6.1.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from quill import events as ev
from quill.config import default_audit_path

# Tool names whose first/second arg is a path the agent is mutating.
_MUTATING_TOOLS_PATH_KEYS: dict[str, tuple[str, ...]] = {
    "Edit": ("file_path",),
    "Write": ("file_path",),
    "MultiEdit": ("file_path",),
    "NotebookEdit": ("notebook_path",),
}


def _arg_path(tool_name: str, args: Mapping[str, Any]) -> str | None:
    keys = _MUTATING_TOOLS_PATH_KEYS.get(tool_name)
    if not keys:
        return None
    for k in keys:
        v = args.get(k)
        if isinstance(v, str) and v:
            return v
    return None


@dataclass(slots=True)
class Receipt:
    """Per-session receipt aggregated from audit-log events.

    `did` and `changed` are insertion-ordered, deduped lists. The
    `_did_set` / `_changed_set` shadow fields provide O(1) membership
    so derivation over a 5000-event log stays linear instead of O(N^2).
    They are internal: `to_dict` and the public API still expose the
    list forms.
    """

    session_id: str
    opened_at: str = ""
    closed_at: str = ""
    intent: str = ""
    did: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    uncertain: list[str] = field(default_factory=list)
    to_verify: list[str] = field(default_factory=list)
    intervention_count: int = 0
    tool_call_count: int = 0
    tdr_contribution: float = 0.0
    trust_delta: float = 0.0
    # Internal: O(1) dedup membership for `did` / `changed`. Not exported.
    _did_set: set[str] = field(default_factory=set, repr=False, compare=False)
    _changed_set: set[str] = field(default_factory=set, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "opened_at": self.opened_at,
            "closed_at": self.closed_at,
            "intent": self.intent,
            "did": self.did,
            "changed": self.changed,
            "uncertain": self.uncertain,
            "to_verify": self.to_verify,
            "intervention_count": self.intervention_count,
            "tool_call_count": self.tool_call_count,
            "tdr_contribution": round(self.tdr_contribution, 3),
            "trust_delta": round(self.trust_delta, 3),
        }


def derive_from_events(events: list[dict[str, Any]]) -> dict[str, Receipt]:
    """Fold a list of audit events into per-session Receipts.

    Returns {session_id: Receipt}. Sessions without an explicit session.open
    are still returned (opened_at remains empty); this lets us derive
    receipts from older logs that pre-date the session-lifecycle events.
    """
    receipts: dict[str, Receipt] = {}

    def _r(sid: str) -> Receipt:
        if sid not in receipts:
            receipts[sid] = Receipt(session_id=sid)
        return receipts[sid]

    for evt in events:
        sid = str(evt.get("session_id") or "")
        if not sid:
            continue
        etype = evt.get("type", "")
        ts = evt.get("ts", "")
        payload = evt.get("payload") or {}
        if not isinstance(payload, Mapping):
            payload = {}
        risk = str(evt.get("risk") or "")
        tool_name = str(payload.get("tool_name") or "")
        r = _r(sid)

        if etype == ev.SESSION_OPEN:
            r.opened_at = str(ts)
            intent = payload.get("intent")
            if isinstance(intent, str):
                r.intent = intent

        elif etype == ev.SESSION_CLOSE:
            r.closed_at = str(ts)

        elif etype == ev.TOOL_ATTEMPTED:
            r.tool_call_count += 1
            if tool_name and tool_name not in r._did_set:
                r._did_set.add(tool_name)
                r.did.append(tool_name)
            args = payload.get("args_preview") or payload.get("args") or {}
            if isinstance(args, Mapping):
                p = _arg_path(tool_name, args)
                if p and p not in r._changed_set:
                    r._changed_set.add(p)
                    r.changed.append(p)

        elif etype == ev.VERDICT_ALLOWED and risk in ("high", "critical"):
            reason = str(payload.get("reason") or tool_name or "")
            r.uncertain.append(f"{risk}: {reason}")

        elif etype == ev.VERDICT_BLOCKED:
            r.intervention_count += 1
            r.trust_delta -= 1.0

        elif etype == ev.VERDICT_ASK:
            r.intervention_count += 1
            r.trust_delta -= 0.5

        elif etype == ev.AGENT_FLAG_UNCERTAIN:
            note = str(payload.get("uncertainty") or "")
            if note:
                r.to_verify.append(note)

    # TDR = executed / (executed + blocked + asked).
    for r in receipts.values():
        denom = r.tool_call_count + r.intervention_count
        r.tdr_contribution = (r.tool_call_count / denom) if denom else 1.0
        if r.tool_call_count > 0:
            r.trust_delta = r.trust_delta / r.tool_call_count

    return receipts


def load_audit_events(path: Path | None = None) -> list[dict[str, Any]]:
    """Read the audit log JSONL and return a list of events.

    Best-effort: malformed lines are skipped, not raised.
    """
    p = path or default_audit_path()
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    with p.open() as f:
        for line in f:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    out.append(obj)
            except json.JSONDecodeError:
                continue
    return out
