"""The force-push rule must fire on real force pushes and stay quiet otherwise.

Found by dogfooding on 2026-07-22: `git push -q origin main && chrome
--force-device-scale-factor=2` was classified CRITICAL as a force push, because
the pattern's `.*?` ran across the command separator and `--force` matched the
`--force-*` prefix of an unrelated flag. Over-blocking is how a gate gets
uninstalled, so both halves are pinned here.
"""

from __future__ import annotations

import pytest

from notari.policy import Risk, classify_command

REAL_FORCE_PUSHES = [
    "git push --force",
    "git push --force origin main",
    "git push origin main --force",
    "git push -f origin main",
    "git push origin main -f",
    "git push --force-with-lease=main --force",
]

NOT_FORCE_PUSHES = [
    # the exact shape that misfired
    "git push -q origin main && chrome --force-device-scale-factor=2",
    "git push origin main; chrome --headless --force-device-scale-factor=2",
    "git push origin main | tee log.txt",
    # the safe variants are the documented remediation, they must never block
    "git push --force-with-lease origin main",
    "git push --force-if-includes origin main",
    # other --force-* flags that belong to a different tool entirely
    "git push origin main && ffmpeg --force-key-frames 1",
    "git push origin main",
]


@pytest.mark.parametrize("cmd", REAL_FORCE_PUSHES)
def test_real_force_push_is_critical(cmd: str) -> None:
    assert classify_command(cmd).risk is Risk.CRITICAL, cmd


@pytest.mark.parametrize("cmd", NOT_FORCE_PUSHES)
def test_innocent_push_is_not_flagged_as_force(cmd: str) -> None:
    c = classify_command(cmd)
    reason = (getattr(c, "reason", "") or "") + (getattr(c, "rule", "") or "")
    assert "git push --force" not in reason, f"{cmd} -> {reason}"
