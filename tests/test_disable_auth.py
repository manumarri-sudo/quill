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


def test_env_bypass_var_is_removed(monkeypatch) -> None:
    """QUILL_SKIP_DISABLE_AUTH must NOT bypass the prompt.

    The agent controls its own environment; an env-var skip in the production
    code path was a real self-disable vector. Setting it must not weaken the
    gate; the Touch ID path still fires (and we fail the test if the prompt
    silently passes when biometry is mocked-fail).
    """
    monkeypatch.setenv("QUILL_SKIP_DISABLE_AUTH", "1")
    monkeypatch.setattr(touchid, "is_available", lambda: True)
    monkeypatch.setattr(
        touchid,
        "authenticate",
        lambda **_k: touchid.TouchIDResult(False, "user_canceled"),
    )
    # If the env var still bypassed, this would NOT raise. It must raise:
    with pytest.raises(typer.Exit):
        _require_disable_auth(_Console())


def test_no_biometry_refuses_by_default(monkeypatch) -> None:
    """SECURITY: no sensor (e.g. an agent's own process) REFUSES by default,
    so a hijacked agent can't self-disable the gate. Regression for the
    `quill off` fall-open hole (audit 2026-06-12, same class as c9b522a)."""
    monkeypatch.setattr(touchid, "is_available", lambda: False)
    with pytest.raises(typer.Exit):
        _require_disable_auth(_Console())


def test_no_biometric_opt_in_proceeds(monkeypatch) -> None:
    """A genuine headless operator can opt in explicitly with --no-biometric;
    it proceeds (and is logged loudly)."""
    monkeypatch.setattr(touchid, "is_available", lambda: False)
    c = _Console()
    _require_disable_auth(c, no_biometric=True)  # must not raise
    assert any("--no-biometric" in m for m in c.messages)


def test_blocks_when_touchid_fails(monkeypatch) -> None:
    """Touch ID present but the fingerprint is canceled/failed: refused."""
    monkeypatch.setattr(touchid, "is_available", lambda: True)
    monkeypatch.setattr(
        touchid,
        "authenticate",
        lambda **_k: touchid.TouchIDResult(False, "user_canceled"),
    )
    with pytest.raises(typer.Exit):
        _require_disable_auth(_Console())


def test_passes_on_touchid_success(monkeypatch) -> None:
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
