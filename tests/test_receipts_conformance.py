"""Receipt conformance: a realistic session must produce a FULLY populated
Receipt - did / changed / uncertain / to_verify all non-empty - and that
summary must be freezable into the chain as a verifiable `session.receipt`.

This is the regression guard for the bug where to_verify / uncertain stayed
perpetually empty because `agent.flag.uncertain` was never emitted and the
overnight auto-allow event type was ignored by the deriver.
"""
from __future__ import annotations

import secrets
from pathlib import Path

from quill import events as ev
from quill import overnight
from quill.adapters.claude_code import run_hook
from quill.audit import AuditLog, verify_chain
from quill.receipt import derive_from_events, emit_receipt, load_audit_events

KEY = b"\x01" * 32
SID = "11111111-2222-3333-4444-555555555555"


def _hook_event(tool_name: str, tool_input: dict, *, sid: str, tp: str) -> str:
    import json
    return json.dumps({
        "session_id": sid,
        "transcript_path": tp,
        "cwd": "/work/project",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    })


def test_full_session_receipt_is_populated(tmp_path: Path) -> None:
    """Drive the real Claude Code adapter through an overnight session and
    confirm every Receipt list fills from genuinely emitted events."""
    log = tmp_path / "audit.log.jsonl"
    transcript = str(tmp_path / "session.jsonl")

    # Force overnight mode on so a HIGH-risk Edit auto-approves and Quill
    # self-flags it for morning review.
    overnight.turn_on(duration_hours=8)

    with AuditLog(path=log, hmac_key=KEY) as audit:
        # HIGH-risk Edit -> overnight auto-allow (uncertain) + agent.flag
        # (to_verify) + tool.attempted (did/changed).
        out = run_hook(
            _hook_event("Edit", {"file_path": "/work/project/app.py"},
                        sid=SID, tp=transcript),
            audit=audit,
        )
        assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
        # A LOW Bash call -> adds a second distinct `did` entry.
        run_hook(
            _hook_event("Bash", {"command": "ls -la"}, sid=SID, tp=transcript),
            audit=audit,
        )

    events = load_audit_events(log)
    types = {e["type"] for e in events}
    assert ev.VERDICT_ALLOWED_OVERNIGHT in types
    assert ev.AGENT_FLAG_UNCERTAIN in types

    r = derive_from_events(events)[SID]
    assert r.did, "did[] should list the tools used"
    assert "Edit" in r.did and "Bash" in r.did
    assert r.changed == ["/work/project/app.py"], "changed[] should list mutated files"
    assert r.uncertain, "uncertain[] should capture the overnight auto-allow"
    assert any("overnight" in u for u in r.uncertain)
    assert r.to_verify, "to_verify[] should capture the agent.flag.uncertain"

    # The summary must freeze into the chain and re-verify.
    with AuditLog(path=log, hmac_key=KEY) as audit:
        mac = emit_receipt(audit, SID, log_path=log)
    assert mac, "emit_receipt should write a session.receipt"
    total, failures = verify_chain(log, KEY)
    assert failures == [], "chain must stay intact after emitting the receipt"
    assert any(e["type"] == ev.SESSION_RECEIPT for e in load_audit_events(log))


def test_emit_receipt_is_idempotent(tmp_path: Path) -> None:
    """A second emit for the same session is a no-op unless forced."""
    log = tmp_path / "audit.log.jsonl"
    with AuditLog(path=log, hmac_key=KEY) as audit:
        audit.emit(event_type=ev.SESSION_OPEN, session_id=SID, risk="low",
                   payload={"intent": "ship"})
        audit.emit(event_type=ev.TOOL_ATTEMPTED, session_id=SID, risk="low",
                   payload={"tool_name": "Read"})
        audit.emit(event_type=ev.AGENT_FLAG_UNCERTAIN, session_id=SID, risk="high",
                   payload={"uncertainty": "double-check the migration order"})

    with AuditLog(path=log, hmac_key=KEY) as audit:
        first = emit_receipt(audit, SID, log_path=log)
        # re-load so the just-emitted receipt is visible to the idempotence check
        second = emit_receipt(audit, SID, log_path=log)
    assert first is not None
    assert second is None, "second emit without --force must be a no-op"

    r = derive_from_events(load_audit_events(log))[SID]
    assert r.to_verify == ["double-check the migration order"]


def test_flag_event_feeds_to_verify(tmp_path: Path) -> None:
    """A bare agent.flag.uncertain (the `quill flag` path) lands in to_verify."""
    log = tmp_path / "audit.log.jsonl"
    with AuditLog(path=log, hmac_key=secrets.token_bytes(32)) as audit:
        audit.emit(event_type="agent.flag.uncertain", session_id=SID, risk="high",
                   payload={"uncertainty": "unsure about deleting the cache dir"})
    r = derive_from_events(load_audit_events(log))[SID]
    assert r.to_verify == ["unsure about deleting the cache dir"]
