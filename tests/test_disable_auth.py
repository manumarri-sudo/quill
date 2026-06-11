"""Tests for the Touch-ID gate on turning the Quill gate OFF.

Verifies the self-disable defense without a real fingerprint or touching the
real gate state: an agent running `quill off` must clear Touch ID when it's
available, but the operator is never locked out of their own recovery hatch
when biometry is unavailable.
"""

from __future__ import annotations

import pytest
import typer

import quill.touchid as touchid
from quill.cli import _require_disable_auth


class _Console:
    """Minimal stand-in that swallows print() so the helper can run headless."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def print(self, *args, **_kwargs) -> None:
        self.messages.append(" ".join(str(a) for a in args))


def test_bypass_env_skips_auth(monkeypatch) -> None:
    monkeypatch.setenv("QUILL_SKIP_DISABLE_AUTH", "1")
    _require_disable_auth(_Console())  # must not raise


def test_no_biometry_falls_open_with_warning(monkeypatch) -> None:
    """No sensor / SSH: do not lock the operator out, but warn loudly."""
    monkeypatch.delenv("QUILL_SKIP_DISABLE_AUTH", raising=False)
    monkeypatch.setattr(touchid, "is_available", lambda: False)
    c = _Console()
    _require_disable_auth(c)  # must not raise
    assert any("Touch ID unavailable" in m for m in c.messages)


def test_blocks_when_touchid_fails(monkeypatch) -> None:
    """Touch ID present but the fingerprint is canceled/failed: gate stays ON."""
    monkeypatch.delenv("QUILL_SKIP_DISABLE_AUTH", raising=False)
    monkeypatch.setattr(touchid, "is_available", lambda: True)
    monkeypatch.setattr(
        touchid,
        "authenticate",
        lambda **_k: touchid.TouchIDResult(False, "user_canceled"),
    )
    with pytest.raises(typer.Exit):
        _require_disable_auth(_Console())


def test_passes_on_touchid_success(monkeypatch) -> None:
    monkeypatch.delenv("QUILL_SKIP_DISABLE_AUTH", raising=False)
    monkeypatch.setattr(touchid, "is_available", lambda: True)
    monkeypatch.setattr(
        touchid,
        "authenticate",
        lambda **_k: touchid.TouchIDResult(True, "ok"),
    )
    _require_disable_auth(_Console())  # must not raise


def test_pause_json_is_protected_in_sandbox() -> None:
    """The gate-off state file must be in the kernel-floor protected set."""
    from quill import sandbox

    files, _trees = sandbox.default_protected()
    assert any("pause.json" in f for f in files)


def test_pause_json_is_in_adapter_gate_surface() -> None:
    from quill.adapters.claude_code import _GATE_CONFIG_SUFFIXES

    assert any("pause.json" in s for s in _GATE_CONFIG_SUFFIXES)
