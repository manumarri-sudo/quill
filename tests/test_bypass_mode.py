"""Tests for Claude Code --dangerously-skip-permissions bypass-mode awareness.

When the user explicitly opts out of friction via Claude Code's bypass flag,
Notari should respect that intent: silently log high-risk events instead of
asking, but never soften the critical class. The bright line never moves.
"""

from __future__ import annotations

from notari.adapters.claude_code import _detect_bypass_mode, classify_event
from notari.policy import Risk

# ---------------------------------------------------------------------------
# detection precedence


def test_bypass_via_hook_payload_permission_mode(monkeypatch):
    monkeypatch.delenv("NOTARI_BYPASS_MODE", raising=False)
    monkeypatch.delenv("CLAUDE_DANGEROUSLY_SKIP_PERMISSIONS", raising=False)
    assert _detect_bypass_mode({"permission_mode": "bypass"})
    assert _detect_bypass_mode({"bypass_mode": True})
    assert _detect_bypass_mode({"dangerously_skip_permissions": True})


def test_bypass_via_notari_env(monkeypatch):
    monkeypatch.setenv("NOTARI_BYPASS_MODE", "1")
    assert _detect_bypass_mode()
    monkeypatch.setenv("NOTARI_BYPASS_MODE", "true")
    assert _detect_bypass_mode()


def test_bypass_via_claude_env(monkeypatch):
    monkeypatch.delenv("NOTARI_BYPASS_MODE", raising=False)
    monkeypatch.setenv("CLAUDE_DANGEROUSLY_SKIP_PERMISSIONS", "1")
    assert _detect_bypass_mode()


def test_no_bypass_by_default(monkeypatch):
    monkeypatch.delenv("NOTARI_BYPASS_MODE", raising=False)
    monkeypatch.delenv("CLAUDE_DANGEROUSLY_SKIP_PERMISSIONS", raising=False)
    assert not _detect_bypass_mode()
    assert not _detect_bypass_mode({})


# ---------------------------------------------------------------------------
# classify_event behavior under bypass mode


def test_critical_still_blocks_in_bypass_mode():
    """The bright line never softens. rm -rf, force-push, DROP TABLE, etc.
    all still gate even when the user has explicitly opted out of friction."""
    risk, reason, _ = classify_event(
        "Bash",
        {"command": "rm -rf /"},
        bypass_mode=True,
    )
    assert risk is Risk.CRITICAL
    assert "rm -rf" in reason or "critical" in reason.lower()


def test_critical_force_push_still_blocks(monkeypatch):
    risk, _, _ = classify_event(
        "Bash",
        {"command": "git push --force origin main"},
        bypass_mode=True,
    )
    assert risk is Risk.CRITICAL


def test_critical_sudo_rm_still_blocks():
    risk, _, _ = classify_event(
        "Bash",
        {"command": "sudo rm -rf /etc"},
        bypass_mode=True,
    )
    assert risk is Risk.CRITICAL


def test_default_edit_downgrades_under_bypass():
    """Edit is default-HIGH (asks for confirmation). In bypass mode it
    becomes silent-log low so the user who said 'don't interrupt me' is
    not interrupted on routine edits."""
    risk, reason, _ = classify_event(
        "Edit",
        {"file_path": "/tmp/x.py", "old_string": "a", "new_string": "b"},
        bypass_mode=True,
    )
    assert risk is Risk.LOW
    assert "bypass mode" in reason


def test_default_edit_normal_mode_still_high():
    """In normal mode (bypass_mode=False), default Edit remains high-risk."""
    risk, _, _ = classify_event(
        "Edit",
        {"file_path": "/tmp/x.py", "old_string": "a", "new_string": "b"},
        bypass_mode=False,
    )
    assert risk is Risk.HIGH


def test_secret_in_write_still_blocks_under_bypass():
    """Secret detection bypasses everything, even bypass mode.
    The secret-leak attack class is the GitHub-PAT-leak failure mode and
    must always block."""
    risk, reason, _ = classify_event(
        "Write",
        {
            "file_path": "/tmp/cfg.py",
            "content": "TOKEN = 'ghp_" + "A" * 36 + "'",
        },
        bypass_mode=True,
    )
    assert risk is Risk.CRITICAL
    assert "secret" in reason.lower()


def test_low_risk_unchanged_under_bypass():
    """Read tools are low-risk in both modes; bypass shouldn't alter behavior."""
    risk_normal, _, _ = classify_event(
        "Bash",
        {"command": "ls"},
        bypass_mode=False,
    )
    risk_bypass, _, _ = classify_event(
        "Bash",
        {"command": "ls"},
        bypass_mode=True,
    )
    assert risk_normal == risk_bypass
    assert risk_normal is Risk.LOW


# ---------------------------------------------------------------------------
# sensitive-directory writes ask even in bypass mode (live-perimeter gap fix)


def test_sensitive_dir_write_asks_even_in_bypass():
    """A Write into a sensitive directory (migrations, auth, payments, secrets,
    infra) escalates to HIGH and is NOT downshifted by bypass mode, closing the
    gap where an AI-authored write to such a path landed silently under
    --dangerously-skip-permissions."""
    for path in (
        "/repo/migrations/0001_init.sql",
        "/repo/migration/PLAN.md",
        "/repo/src/auth/tokens.py",
        "/repo/payments/charge.py",
        "/repo/secrets/keys.env",
        "/repo/infra/main.tf",
    ):
        risk, reason, _ = classify_event(
            "Write", {"file_path": path, "content": "x = 1\n"}, bypass_mode=True
        )
        assert risk is Risk.HIGH, f"{path} should ask even in bypass, got {risk}"
        assert "sensitive" in reason.lower()


def test_sensitive_dir_edit_asks_even_in_bypass():
    risk, _, _ = classify_event(
        "Edit",
        {"file_path": "/repo/migrations/0002.sql", "new_string": "alter table x"},
        bypass_mode=True,
    )
    assert risk is Risk.HIGH


def test_non_sensitive_write_still_downshifts_in_bypass():
    """The convenience is preserved: an ordinary write still downshifts to LOW
    in bypass, so only the sensitive dirs keep the human in the loop."""
    risk, _, _ = classify_event(
        "Write", {"file_path": "/repo/src/util.py", "content": "x = 1\n"}, bypass_mode=True
    )
    assert risk is Risk.LOW


def test_filename_named_like_sensitive_dir_is_not_escalated():
    """Matching is on directory components, not the filename: a file merely
    named migration.md at the repo root is a normal write."""
    risk, _, _ = classify_event(
        "Write", {"file_path": "/repo/migration.md", "content": "notes"}, bypass_mode=True
    )
    assert risk is Risk.LOW


def test_sensitive_dir_write_not_downshifted_without_bypass():
    """Outside bypass a sensitive-dir write is HIGH (ask) for a pattern reason
    (not the plain default), so a [policy] override cannot silently unlock it."""
    risk, reason, _ = classify_event(
        "Write", {"file_path": "/repo/auth/login.py", "content": "x = 1\n"}
    )
    assert risk is Risk.HIGH
    assert "sensitive" in reason.lower()
