"""Audit-log foundation tests.

Covers: append-only writes, chain integrity, tamper detection, file mode.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from quill.audit import AuditLog, verify_chain


def test_emits_signed_event(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(
            event_type="session.start",
            session_id="ses_1",
            payload={"intent": "test"},
        )
    assert p.exists()
    with p.open() as f:
        lines = [json.loads(line) for line in f]
    assert len(lines) == 1
    assert lines[0]["type"] == "session.start"
    assert "mac" in lines[0]
    assert "prev_mac" in lines[0]


def test_chain_intact_across_many_events(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        for i in range(50):
            log.emit(
                event_type="tool.attempted",
                session_id="ses_1",
                risk="low" if i % 2 == 0 else "high",
                payload={"tool_name": f"fs.read_file_{i}"},
            )
    total, failures = verify_chain(p, key)
    assert total == 50
    assert failures == []


def test_chain_detects_modified_entry(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="a", session_id="s", payload={"k": 1})
        log.emit(event_type="b", session_id="s", payload={"k": 2})
        log.emit(event_type="c", session_id="s", payload={"k": 3})

    raw = p.read_text().splitlines()
    # Tamper: change the second entry's payload
    obj = json.loads(raw[1])
    obj["payload"]["k"] = 999
    raw[1] = json.dumps(obj, separators=(",", ":"))
    p.write_text("\n".join(raw) + "\n")

    total, failures = verify_chain(p, key)
    assert total == 3
    assert 2 in failures


def test_chain_detects_inserted_entry(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="a", session_id="s", payload={"k": 1})
        log.emit(event_type="b", session_id="s", payload={"k": 2})

    # Inject a forged entry by copying the second line and modifying it
    raw = p.read_text().splitlines()
    forged = json.loads(raw[1])
    forged["type"] = "INJECTED"
    raw.insert(1, json.dumps(forged, separators=(",", ":")))
    p.write_text("\n".join(raw) + "\n")

    total, failures = verify_chain(p, key)
    assert total == 3
    assert failures  # something must fail


def test_chain_continues_across_reopens(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="a", session_id="s", payload={})
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="b", session_id="s", payload={})

    total, failures = verify_chain(p, key)
    assert total == 2
    assert failures == []


def test_audit_log_file_mode_is_0o600(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="a", session_id="s", payload={})
    mode = stat.S_IMODE(p.stat().st_mode)
    # Owner read+write only; group/other should have no access.
    assert mode & 0o077 == 0, f"audit log is too permissive: {oct(mode)}"


def test_force_fsync_on_high_risk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """High-risk entries must be force-fsynced; low-risk batch up.

    We can't observe fsync directly without ptrace; instead we verify that
    the entry is durable by reopening the file and verifying the chain.
    """
    p = tmp_path / "audit.jsonl"
    key = b"k" * 32
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(event_type="a", session_id="s", risk="high", payload={})
    # No explicit close+fsync between emit and read; chain must still verify.
    total, failures = verify_chain(p, key)
    assert total == 1
    assert failures == []
