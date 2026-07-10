"""The hook-layer half of the self-disable defense.

The HARD guarantee that an AI agent cannot turn the Notari gate off is NOT the
CLI Touch-ID / tty check (that only runs for a human in their own terminal, and
is defense-in-depth). It is this: an agent running `notari off|pause|night`
through its gated Bash tool classifies CRITICAL, so the PreToolUse hook DENIES
it before it runs - even under bypass mode, where HIGH would silently downshift.

These tests pin that classification so a refactor of the pattern set can't
silently re-open the hole. (audit #1/#3, self-disable closure 2026-06-12.)
"""

from __future__ import annotations

import pytest

from notari.policy import Risk, classify_command


@pytest.mark.parametrize(
    "cmd",
    [
        "notari off",
        "notari off --for 24h",
        "notari off --no-biometric",
        "notari pause",
        "notari pause --for 30m --reason x",
        "notari night",
        "NOTARI OFF",  # IGNORECASE
        "sudo notari off",
    ],
)
def test_agent_gate_disable_is_critical(cmd: str) -> None:
    assert classify_command(cmd).risk is Risk.CRITICAL


@pytest.mark.parametrize(
    "cmd",
    [
        "notari on",  # turning the gate back ON is never blocked
        "notari audit show",
        "notari receipts",
        "notari doctor",
        "notari version",
    ],
)
def test_non_disable_notari_commands_are_not_critical(cmd: str) -> None:
    assert classify_command(cmd).risk is not Risk.CRITICAL


def test_disable_in_quoted_string_is_masked_not_flagged() -> None:
    """A quoted mention (e.g. echoing docs) is masked by _mask_quoted, so it
    does not false-positive as an agent disabling the gate."""
    assert classify_command("echo 'run notari off to pause'").risk is not Risk.CRITICAL


# ---------------------------------------------------------------------------
# Bypass closures from the 2nd independent security review.
# Gap #1: the CLI-string pattern does not cover the LIBRARY entry point.
# Gap #2: pause.json was protected against Write/Edit but not against a Bash
#         write/redirect (and a quoted path masked the original rule).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        'python -c "from notari import pause; pause.pause(duration_hours=24)"',
        'python3 -c "import notari.pause as m; m.pause()"',
        'python -c "from notari import overnight; overnight.enable()"',
        'uv run python -c "from notari import pause; pause.pause()"',
    ],
)
def test_library_disable_call_is_critical(cmd: str) -> None:
    # Was MEDIUM/auto-allowed before the fix: pausing via the library API
    # neuters the whole gate, so an agent running it via Bash must be denied.
    assert classify_command(cmd).risk is Risk.CRITICAL


@pytest.mark.parametrize(
    "cmd",
    [
        "echo '{}' > ~/.notari/pause.json",
        'cat /tmp/x > "$HOME/.notari/pause.json"',  # quoted path (masking case)
        "cp /tmp/x ~/.notari/pause.json",
        "tee ~/.notari/pause.json",
    ],
)
def test_bash_write_to_pause_json_is_critical(cmd: str) -> None:
    # pause.json is the gate-off switch; writing it via Bash was LOW/allow.
    assert classify_command(cmd).risk is Risk.CRITICAL


def test_benign_python_c_is_not_critical() -> None:
    # The library-disable pattern must not fire on an ordinary one-liner.
    assert classify_command('python -c "print(1 + 1)"').risk is not Risk.CRITICAL
