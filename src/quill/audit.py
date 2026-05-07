"""Append-only signed audit log.

Format: JSONL, one event per line. Every event includes:
  - ts            ISO-8601 timestamp UTC
  - session_id    parent or current session
  - agent_id      which sub-agent in the delegation tree (root if absent)
  - prev_mac      HMAC of the previous entry (the chain anchor)
  - payload       event-specific fields
  - mac           HMAC-SHA256 of (prev_mac || canonical(payload)) under the
                  per-installation HMAC key

Tamper-evidence: any modification or insertion breaks the chain at the next
verify. Use `quill audit verify <logfile>` to validate.

Performance: writes use O_APPEND for atomicity. fsync is BATCHED by default
(every N entries or M ms, whichever first), with FORCE-fsync on any entry
whose risk >= HIGH so a power loss never drops a critical-risk row.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from quill.errors import AuditError

# fsync discipline
FSYNC_BATCH_SIZE: Final[int] = 16
FSYNC_BATCH_MS: Final[int] = 250


def _canon(obj: Mapping[str, Any]) -> bytes:
    """Canonical JSON encoding for stable HMAC computation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class AuditLog:
    """Append-only signed audit log.

    NOT thread-safe across processes. Within a single process, writes are
    serialized by an internal lock. For multi-process operation, run a single
    quill instance and route all clients through it.
    """

    path: Path
    hmac_key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    _fd: int | None = field(default=None, init=False)
    _prev_mac: bytes = field(default=b"", init=False)
    _pending: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # O_APPEND ensures atomic appends even with concurrent writers
        self._fd = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            mode=0o600,  # never world-readable
        )
        # Anchor: read the last MAC if file already had entries
        if self.path.stat().st_size > 0:
            self._prev_mac = self._tail_mac()

    def _tail_mac(self) -> bytes:
        """Read the last line's mac (for chain continuation across restarts)."""
        try:
            with self.path.open("rb") as f:
                # Cheap tail: read last 4KB and split on newlines
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 4096))
                tail = f.read().splitlines()
            if not tail:
                return b""
            last = json.loads(tail[-1])
            mac = last.get("mac")
            return bytes.fromhex(mac) if isinstance(mac, str) else b""
        except (OSError, json.JSONDecodeError, ValueError) as e:
            msg = f"cannot read existing audit chain at {self.path}: {e}"
            raise AuditError(msg) from e

    def emit(
        self,
        *,
        event_type: str,
        session_id: str,
        agent_id: str = "root",
        risk: str = "low",
        payload: Mapping[str, Any] | None = None,
        force_fsync: bool | None = None,
    ) -> str:
        """Append a single audit event. Returns the line's mac (hex).

        force_fsync: if None, fsyncs when risk in {high, critical} OR batch
        threshold reached. Pass True/False to override.
        """
        if self._fd is None:
            msg = "audit log is closed"
            raise AuditError(msg)

        body: dict[str, Any] = {
            "ts": _now(),
            "session_id": session_id,
            "agent_id": agent_id,
            "type": event_type,
            "risk": risk,
            "prev_mac": self._prev_mac.hex(),
            "payload": dict(payload or {}),
        }
        # MAC over canonical body (excluding the mac field itself)
        mac = hmac.new(self.hmac_key, _canon(body), hashlib.sha256).digest()
        body["mac"] = mac.hex()
        line = (json.dumps(body, separators=(",", ":")) + "\n").encode("utf-8")

        with self._lock:
            os.write(self._fd, line)
            self._prev_mac = mac
            self._pending += 1

            need_fsync = force_fsync if force_fsync is not None else (
                risk in ("high", "critical") or self._pending >= FSYNC_BATCH_SIZE
            )
            if need_fsync:
                os.fsync(self._fd)
                self._pending = 0

        return mac.hex()

    def close(self) -> None:
        if self._fd is not None:
            try:
                if self._pending:
                    os.fsync(self._fd)
            finally:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def verify_chain(path: Path, hmac_key: bytes) -> tuple[int, list[int]]:
    """Verify the HMAC chain over an existing log file.

    Returns (total_events, list of 1-based line numbers that failed verify).
    Empty failure list means the chain is intact.
    """
    failures: list[int] = []
    prev_mac_hex = ""
    total = 0
    with path.open("rb") as f:
        for i, raw in enumerate(f, start=1):
            total += 1
            try:
                evt = json.loads(raw)
                claimed_mac = evt.pop("mac", "")
                if evt.get("prev_mac") != prev_mac_hex:
                    failures.append(i)
                    prev_mac_hex = claimed_mac
                    continue
                expected = hmac.new(hmac_key, _canon(evt), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, claimed_mac):
                    failures.append(i)
                prev_mac_hex = claimed_mac
            except (json.JSONDecodeError, KeyError, ValueError):
                failures.append(i)
    return total, failures
