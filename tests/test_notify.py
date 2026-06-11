"""Notification dispatcher tests.

Channels are mocked - we don't actually fire macOS banners or open SMTP
connections from the test suite. We verify:
  - BlockMessage rendering (short title, short body, long body)
  - NotifyConfig.from_dict honors all fields and email subsection
  - should_fire respects on_blocked/on_ask/on_critical_only flags
  - fire() runs channels on a background thread and audit-emits results
"""

from __future__ import annotations

import time
from typing import Any

from quill.notify import (
    BlockMessage,
    NotifyConfig,
    NotifyDispatcher,
    _send_macos,
    _send_slack,
    _send_webhook,
)


def _msg(decision: str = "blocked", risk: str = "critical") -> BlockMessage:
    return BlockMessage(
        risk=risk,
        decision=decision,
        tool_name="Bash",
        args_preview={"command": "rm -rf x"},
        what="rm -rf node_modules",
        why="matches `rm -rf` pattern",
        try_instead="mv node_modules /tmp/quarantine_$(date +%s)",
        approve_token="abc123",
        cwd="/Users/me/proj",
        session_id="ses-1",
    )


def test_short_title_includes_decision_and_tool() -> None:
    assert _msg("blocked").short_title() == "quill blocked: Bash"
    assert _msg("ask").short_title() == "quill asking: Bash"


def test_short_body_includes_what_why_try_approve() -> None:
    body = _msg().short_body()
    assert "rm -rf node_modules" in body
    assert "matches" in body
    assert "try:" in body
    assert "quill approve abc123" in body


def test_long_body_renders_multiline_with_all_fields() -> None:
    body = _msg().long_body()
    assert "What:" in body
    assert "Tool:" in body
    assert "Why:" in body
    assert "Try:" in body
    assert "Cwd:" in body
    assert "Session:" in body
    assert "quill approve abc123" in body


def test_config_from_dict_disabled_when_empty() -> None:
    cfg = NotifyConfig.from_dict({})
    assert cfg.enabled is False


def test_config_from_dict_enabled_with_section() -> None:
    cfg = NotifyConfig.from_dict(
        {
            "macos": True,
            "slack_webhook_url": "https://hooks.slack.com/x",
            "on_blocked": True,
            "on_ask": True,
            "email": {
                "smtp_host": "smtp.example.com",
                "smtp_port": 25,
                "smtp_user": "x@example.com",
                "smtp_password_env": "SMTP_PASS",
            },
        }
    )
    assert cfg.enabled is True
    assert cfg.macos is True
    assert cfg.slack_webhook_url == "https://hooks.slack.com/x"
    assert cfg.on_ask is True
    assert cfg.smtp_host == "smtp.example.com"
    assert cfg.smtp_port == 25
    assert cfg.smtp_user == "x@example.com"
    assert cfg.smtp_password_env == "SMTP_PASS"


def test_should_fire_respects_on_blocked() -> None:
    cfg = NotifyConfig(enabled=True, on_blocked=False)
    d = NotifyDispatcher(config=cfg)
    assert d.should_fire(_msg("blocked")) is False


def test_should_fire_respects_on_ask() -> None:
    cfg_off = NotifyConfig(enabled=True, on_ask=False)
    cfg_on = NotifyConfig(enabled=True, on_ask=True)
    assert NotifyDispatcher(config=cfg_off).should_fire(_msg("ask")) is False
    assert NotifyDispatcher(config=cfg_on).should_fire(_msg("ask")) is True


def test_should_fire_respects_on_critical_only() -> None:
    cfg = NotifyConfig(enabled=True, on_blocked=True, on_critical_only=True)
    d = NotifyDispatcher(config=cfg)
    assert d.should_fire(_msg(risk="critical")) is True
    assert d.should_fire(_msg(risk="high")) is False
    assert d.should_fire(_msg(risk="medium")) is False


def test_disabled_config_never_fires() -> None:
    d = NotifyDispatcher(config=NotifyConfig(enabled=False))
    assert d.should_fire(_msg()) is False


def test_macos_skipped_when_osascript_missing(monkeypatch: Any) -> None:
    """If osascript isn't on PATH (Linux/Windows), macos channel returns False."""
    monkeypatch.setattr("quill.notify.shutil.which", lambda _: None)
    cfg = NotifyConfig(enabled=True, macos=True)
    assert _send_macos(cfg, _msg()) is False


def test_macos_skipped_when_disabled() -> None:
    cfg = NotifyConfig(enabled=True, macos=False)
    assert _send_macos(cfg, _msg()) is False


def test_slack_skipped_when_no_webhook() -> None:
    cfg = NotifyConfig(enabled=True, slack_webhook_url="")
    assert _send_slack(cfg, _msg()) is False


def test_webhook_skipped_when_no_url() -> None:
    cfg = NotifyConfig(enabled=True, webhook_url="")
    assert _send_webhook(cfg, _msg()) is False


def test_fire_dispatches_on_background_thread_and_audits() -> None:
    """fire() returns immediately; audit_emit gets the per-channel results."""
    captured: list[tuple[str, dict[str, Any]]] = []

    def _emit(event_type: str, payload: dict[str, Any]) -> None:
        captured.append((event_type, payload))

    cfg = NotifyConfig(enabled=True, macos=False, on_blocked=True)
    d = NotifyDispatcher(config=cfg, audit_emit=_emit)
    d.fire(_msg())
    # fire() spawns a daemon thread; give it time to land.
    deadline = time.time() + 2.0
    while time.time() < deadline and not captured:
        time.sleep(0.01)
    assert len(captured) == 1
    event_type, payload = captured[0]
    assert event_type == "notify.dispatched"
    assert payload["tool_name"] == "Bash"
    assert payload["decision"] == "blocked"
    assert "channels" in payload


def test_fire_silent_when_should_fire_false() -> None:
    captured: list[Any] = []
    cfg = NotifyConfig(enabled=False)
    d = NotifyDispatcher(config=cfg, audit_emit=lambda *_: captured.append(_))
    d.fire(_msg())
    time.sleep(0.05)
    assert captured == []


def test_short_body_omits_try_when_no_suggestion() -> None:
    msg = BlockMessage(
        risk="critical",
        decision="blocked",
        tool_name="Bash",
        args_preview={},
        what="x",
        why="y",
    )
    body = msg.short_body()
    assert "try:" not in body
    assert "quill approve" not in body  # no token either
