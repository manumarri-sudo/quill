"""Deterministic replay-verify harness.

Quill makes a strong claim: the audit log is the single source of truth, and
every human-facing artifact (receipts, trifecta state, the A2A handoff graph)
is a *pure, deterministic fold* over that log. This module is the executable
proof of that claim. It does two independent things and reports both:

  1. **Chain integrity** - re-verify the HMAC chain end-to-end. Any edit,
     insertion, deletion, or reorder breaks a `prev_mac` link and is reported
     as a failing line number. (Tamper-EVIDENT, not tamper-proof: a holder of
     the MAC key can forge a consistent chain - see SECURITY.md.)

  2. **Replay determinism** - fold the log into receipts / taint / handoffs
     *twice* and assert the two results are byte-identical, then hash the
     canonical result into a `state_digest`. Pin that digest in a test and any
     accidental non-determinism (dict ordering, wall-clock leakage, set
     iteration) trips the test loudly instead of silently corrupting an audit.

Determinism technique, stated plainly: the folds take *all* their inputs from
the event stream (including each event's own timestamp) and hold no hidden
state, so f(log) == f(log) for all logs. The harness is what continuously
checks that property against real data rather than trusting it.

Used by `quill audit replay` and by tests/test_harness_replay.py.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _canonical(obj: Any) -> str:
    """Stable JSON for digesting/comparison - sorted keys, tight separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _receipts_state(events: list[dict[str, Any]]) -> dict[str, Any]:
    from quill.receipt import derive_from_events
    return {sid: r.to_dict() for sid, r in derive_from_events(events).items()}


def _taint_state(events: list[dict[str, Any]]) -> dict[str, Any]:
    from quill.taint import fold_audit_events
    return {sid: t.to_dict() for sid, t in fold_audit_events(events).items()}


def _handoff_state(events: list[dict[str, Any]]) -> dict[str, Any]:
    from quill.bridge import fold_handoffs
    out: dict[str, Any] = {}
    for ph, h in fold_handoffs(events).items():
        out[ph] = {"is_orphan": bool(h.is_orphan), "is_cascade": bool(h.is_cascade)}
    return out


# The named folds the harness replays. Add a row here when a new
# derived-artifact fold ships; the determinism guarantee then covers it too.
_FOLDS = {
    "receipts": _receipts_state,
    "taint": _taint_state,
    "handoffs": _handoff_state,
}


@dataclass(slots=True)
class ReplayResult:
    """Outcome of a single replay-verify pass over one audit log."""

    path: str
    total_events: int = 0
    chain_failures: list[int] = field(default_factory=list)
    nondeterministic_folds: list[str] = field(default_factory=list)
    state_digest: str = ""
    fold_digests: dict[str, str] = field(default_factory=dict)

    @property
    def chain_ok(self) -> bool:
        return not self.chain_failures

    @property
    def deterministic(self) -> bool:
        return not self.nondeterministic_folds

    @property
    def ok(self) -> bool:
        return self.chain_ok and self.deterministic

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "total_events": self.total_events,
            "chain_ok": self.chain_ok,
            "chain_failures": self.chain_failures,
            "deterministic": self.deterministic,
            "nondeterministic_folds": self.nondeterministic_folds,
            "fold_digests": self.fold_digests,
            "state_digest": self.state_digest,
            "ok": self.ok,
        }


def replay(path: Path, hmac_key: bytes) -> ReplayResult:
    """Verify the chain and replay every fold twice over the log at `path`.

    Returns a ReplayResult. Never raises on a bad log: a corrupt chain or a
    non-deterministic fold is reported in the result, not thrown, so callers
    can decide the exit code.
    """
    from quill.audit import verify_chain
    from quill.receipt import load_audit_events

    result = ReplayResult(path=str(path))
    if not path.exists():
        return result

    total, failures = verify_chain(path, hmac_key)
    result.total_events = total
    result.chain_failures = failures

    events = load_audit_events(path)
    combined: dict[str, Any] = {}
    for name, fold in _FOLDS.items():
        first = fold(list(events))
        second = fold(list(events))
        if _canonical(first) != _canonical(second):
            result.nondeterministic_folds.append(name)
        digest = hashlib.sha256(_canonical(first).encode("utf-8")).hexdigest()
        result.fold_digests[name] = digest
        combined[name] = first

    result.state_digest = hashlib.sha256(
        _canonical(combined).encode("utf-8"),
    ).hexdigest()
    return result
