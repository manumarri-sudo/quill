"""Deterministic replay-verify harness tests.

Pins the two guarantees in quill.harness.replay:
  1. A clean log replays deterministically with an intact chain.
  2. Tampering with any line is detected (chain_failures non-empty).
And that the state_digest is stable run-to-run (the golden-snapshot anchor).
"""
from __future__ import annotations

from pathlib import Path

from quill import events as ev
from quill.audit import AuditLog
from quill.bridge import payload_hash
from quill.harness import replay

KEY = b"\x02" * 32


def _build_log(path: Path) -> None:
    h = payload_hash({"to": "sub", "from": "root"})
    with AuditLog(path=path, hmac_key=KEY) as audit:
        audit.emit(event_type=ev.SESSION_OPEN, session_id="root", risk="low",
                   payload={"intent": "ship the thing"})
        audit.emit(event_type=ev.TOOL_ATTEMPTED, session_id="root", risk="high",
                   payload={"tool_name": "Edit", "args_preview": {"file_path": "/a/b.py"}})
        audit.emit(event_type=ev.VERDICT_ALLOWED_OVERNIGHT, session_id="root",
                   risk="high", payload={"tool_name": "Edit", "reason": "auto"})
        audit.emit(event_type=ev.AGENT_FLAG_UNCERTAIN, session_id="root", risk="high",
                   payload={"uncertainty": "verify the edit"})
        audit.emit(event_type=ev.AGENT_HANDOFF_OUT, session_id="root", risk="low",
                   payload={"to_agent_id": "sub", "payload_hash": h})
        audit.emit(event_type=ev.AGENT_HANDOFF_IN, session_id="sub", risk="low",
                   payload={"from_session_id": "root", "payload_hash": h})
        audit.emit(event_type=ev.SESSION_CLOSE, session_id="root", risk="low",
                   payload={"reason": "user_quit"})


def test_clean_log_replays_ok(tmp_path: Path) -> None:
    log = tmp_path / "audit.log.jsonl"
    _build_log(log)
    res = replay(log, KEY)
    assert res.chain_ok, res.chain_failures
    assert res.deterministic, res.nondeterministic_folds
    assert res.ok
    assert res.total_events == 7
    assert res.state_digest
    assert set(res.fold_digests) == {"receipts", "taint", "handoffs"}


def test_state_digest_is_stable(tmp_path: Path) -> None:
    log = tmp_path / "audit.log.jsonl"
    _build_log(log)
    d1 = replay(log, KEY).state_digest
    d2 = replay(log, KEY).state_digest
    assert d1 == d2 and d1 != ""


def test_tamper_is_detected(tmp_path: Path) -> None:
    log = tmp_path / "audit.log.jsonl"
    _build_log(log)
    lines = log.read_text().splitlines()
    # Corrupt a payload field on line 2 without touching its mac.
    lines[1] = lines[1].replace("/a/b.py", "/a/EVIL.py")
    log.write_text("\n".join(lines) + "\n")

    res = replay(log, KEY)
    assert not res.chain_ok, "a mutated payload must break the chain"
    assert not res.ok
    assert 2 in res.chain_failures


def test_missing_log_is_safe(tmp_path: Path) -> None:
    res = replay(tmp_path / "nope.jsonl", KEY)
    assert res.total_events == 0
    assert res.ok  # nothing to fail
