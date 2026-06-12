"""The hook-layer half of the self-disable defense.

The HARD guarantee that an AI agent cannot turn the Quill gate off is NOT the
CLI Touch-ID / tty check (that only runs for a human in their own terminal, and
is defense-in-depth). It is this: an agent running `quill off|pause|night`
through its gated Bash tool classifies CRITICAL, so the PreToolUse hook DENIES
it before it runs - even under bypass mode, where HIGH would silently downshift.

These tests pin that classification so a refactor of the pattern set can't
silently re-open the hole. (audit #1/#3, self-disable closure 2026-06-12.)
"""

from __future__ import annotations

import pytest

from quill.policy import Risk, classify_command


@pytest.mark.parametrize(
    "cmd",
    [
        "quill off",
        "quill off --for 24h",
        "quill off --no-biometric",
        "quill pause",
        "quill pause --for 30m --reason x",
        "quill night",
        "QUILL OFF",  # IGNORECASE
        "sudo quill off",
    ],
)
def test_agent_gate_disable_is_critical(cmd: str) -> None:
    assert classify_command(cmd).risk is Risk.CRITICAL


@pytest.mark.parametrize(
    "cmd",
    [
        "quill on",  # turning the gate back ON is never blocked
        "quill audit show",
        "quill receipts",
        "quill doctor",
        "quill version",
    ],
)
def test_non_disable_quill_commands_are_not_critical(cmd: str) -> None:
    assert classify_command(cmd).risk is not Risk.CRITICAL


def test_disable_in_quoted_string_is_masked_not_flagged() -> None:
    """A quoted mention (e.g. echoing docs) is masked by _mask_quoted, so it
    does not false-positive as an agent disabling the gate."""
    assert classify_command("echo 'run quill off to pause'").risk is not Risk.CRITICAL
