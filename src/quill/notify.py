"""Out-of-band notification dispatcher.

When Quill blocks a tool call, the user needs to know:
  WHAT was attempted (tool name + arg preview)
  WHY it was blocked (risk classification + matched pattern)
  WHAT TO TRY INSTEAD (the suggestion from policy.py)
  HOW TO APPROVE if it's actually fine (`quill approve <token>`)

The agent's terminal may not be where the user is looking. This module
fans the structured message out to channels the user explicitly opted in
to via [notify] in config.toml:

    [notify]
    macos = true                          # macOS Notification Center
    sound = "Glass"                       # optional, macOS only
    email_to = "manu@example.com"         # SMTP via [notify.email]
    slack_webhook_url = "https://..."     # incoming-webhook URL
    webhook_url = "https://..."           # generic POST endpoint
    on_blocked = true                     # default true
    on_ask = false                        # default false; opt-in for ask events
    on_critical_only = false              # if true, fire only on CRITICAL

    [notify.email]
    smtp_host = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = "manu@example.com"
    smtp_password_env = "QUILL_SMTP_PASS" # password loaded from this env var

Channels run on a thread so they never block the gate (the hook has a
10s deadline). Failures are logged to the audit chain but not raised.

Zero new dependencies - stdlib only. macOS uses `osascript`, email uses
`smtplib`, Slack/webhook use `urllib.request`.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import smtplib
import subprocess
import threading
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.mime.text import MIMEText
from typing import Any


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()

# -----------------------------------------------------------------------------
# Structured message every channel renders


@dataclass(slots=True)
class BlockMessage:
    """The structured event a notification carries.

    Channels render this differently - macOS gets a short banner, email gets
    a full body, Slack gets a markdown block, webhook gets the raw JSON.
    """

    risk: str                              # "low" | "medium" | "high" | "critical"
    decision: str                          # "blocked" | "ask"
    tool_name: str
    args_preview: dict[str, Any]
    what: str                              # one-line: "rm -rf node_modules"
    why: str                               # plain-English: "matches `rm -rf` rule"
    try_instead: str = ""                  # paste-able safer alt
    approve_token: str = ""                # `quill approve <token>` if set
    cwd: str = ""
    session_id: str = ""

    def short_title(self) -> str:
        verb = "asking" if self.decision == "ask" else "blocked"
        return f"quill {verb}: {self.tool_name}"

    def short_body(self) -> str:
        """One-paragraph rendering for desktop banners."""
        body = f"{self.what}\n{self.why}"
        if self.try_instead:
            body += f"\ntry: {self.try_instead}"
        if self.approve_token:
            body += f"\napprove: quill approve {self.approve_token}"
        return body

    def long_body(self) -> str:
        """Multi-paragraph rendering for email / Slack."""
        parts = [
            f"quill {self.decision} {self.risk.upper()} call",
            "",
            f"What:   {self.what}",
            f"Tool:   {self.tool_name}",
            f"Why:    {self.why}",
        ]
        if self.try_instead:
            parts.append(f"Try:    {self.try_instead}")
        if self.cwd:
            parts.append(f"Cwd:    {self.cwd}")
        if self.session_id:
            parts.append(f"Session: {self.session_id}")
        if self.approve_token:
            parts += [
                "",
                "To allow this exact call (one-shot, expires in 10 minutes):",
                f"    quill approve {self.approve_token}",
            ]
        return "\n".join(parts)


# -----------------------------------------------------------------------------
# Config


@dataclass(slots=True)
class NotifyConfig:
    """All notification channel settings. Loaded from config.toml [notify]."""

    enabled: bool = False
    macos: bool = False
    sound: str = ""
    email_to: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password_env: str = ""
    slack_webhook_url: str = ""
    webhook_url: str = ""
    on_blocked: bool = True
    on_ask: bool = False
    on_critical_only: bool = False

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any] | None) -> NotifyConfig:
        if not raw:
            return cls()
        email = raw.get("email") or {}
        if not isinstance(email, Mapping):
            email = {}
        return cls(
            enabled=True,  # if [notify] section exists, treat as opt-in
            macos=bool(raw.get("macos", False)),
            sound=str(raw.get("sound") or ""),
            email_to=str(raw.get("email_to") or ""),
            smtp_host=str(email.get("smtp_host") or ""),
            smtp_port=int(email.get("smtp_port") or 587),
            smtp_user=str(email.get("smtp_user") or ""),
            smtp_password_env=str(email.get("smtp_password_env") or ""),
            slack_webhook_url=str(raw.get("slack_webhook_url") or ""),
            webhook_url=str(raw.get("webhook_url") or ""),
            on_blocked=bool(raw.get("on_blocked", True)),
            on_ask=bool(raw.get("on_ask", False)),
            on_critical_only=bool(raw.get("on_critical_only", False)),
        )


# -----------------------------------------------------------------------------
# Channels - each is a function that takes (NotifyConfig, BlockMessage) and
# either dispatches or returns silently. Failure is logged, not raised.


def _send_macos(cfg: NotifyConfig, msg: BlockMessage) -> bool:
    """Fire a macOS Notification Center banner via osascript.

    Returns True only if osascript exits 0. Even on exit 0 the banner can
    be silently suppressed by Focus mode / DND / per-app permissions.
    The dispatcher writes a fallback log to `$QUILL_HOME/notify.log` so
    the user can grep "did this fire?" without relying on the GUI.
    """
    if not cfg.macos:
        return False
    if not shutil.which("osascript"):
        return False
    title = msg.short_title()
    body = msg.short_body()
    # AppleScript string-escape: backslashes and quotes.
    def _esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    script = f'display notification "{_esc(body)}" with title "{_esc(title)}"'
    if cfg.sound:
        script += f' sound name "{_esc(cfg.sound)}"'
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            check=False, capture_output=True, timeout=5,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0


def _send_email(cfg: NotifyConfig, msg: BlockMessage) -> bool:
    if not (cfg.email_to and cfg.smtp_host and cfg.smtp_user):
        return False
    password = os.environ.get(cfg.smtp_password_env or "QUILL_SMTP_PASS", "")
    if not password:
        return False
    body = msg.long_body()
    mime = MIMEText(body)
    mime["Subject"] = msg.short_title()
    mime["From"] = cfg.smtp_user
    mime["To"] = cfg.email_to
    try:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=8) as server:
            server.starttls()
            server.login(cfg.smtp_user, password)
            server.send_message(mime)
    except (smtplib.SMTPException, OSError):
        return False
    return True


def _send_slack(cfg: NotifyConfig, msg: BlockMessage) -> bool:
    if not cfg.slack_webhook_url:
        return False
    color = {"critical": "#c1442f", "high": "#b8862b",
             "medium": "#5E81AC", "low": "#7a7a7a"}.get(msg.risk, "#7a7a7a")
    payload = {
        "text": msg.short_title(),
        "attachments": [{
            "color": color,
            "title": msg.short_title(),
            "text": f"```\n{msg.long_body()}\n```",
            "mrkdwn_in": ["text"],
        }],
    }
    return _post_json(cfg.slack_webhook_url, payload)


def _send_webhook(cfg: NotifyConfig, msg: BlockMessage) -> bool:
    if not cfg.webhook_url:
        return False
    payload = {
        "decision": msg.decision,
        "risk": msg.risk,
        "tool_name": msg.tool_name,
        "what": msg.what,
        "why": msg.why,
        "try_instead": msg.try_instead,
        "approve_token": msg.approve_token,
        "cwd": msg.cwd,
        "session_id": msg.session_id,
        "args_preview": msg.args_preview,
    }
    return _post_json(cfg.webhook_url, payload)


def _post_json(url: str, payload: Mapping[str, Any]) -> bool:
    try:
        body = json.dumps(payload).encode("utf-8")
        # nosec - url is user-configured, not user-input from a request.
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with contextlib.closing(urllib.request.urlopen(req, timeout=8)) as resp:
            status: int = resp.status
            return 200 <= status < 300
    except Exception:
        return False


_CHANNELS = (_send_macos, _send_email, _send_slack, _send_webhook)


# -----------------------------------------------------------------------------
# Public dispatcher


@dataclass(slots=True)
class NotifyDispatcher:
    """Fan a BlockMessage out to every configured channel.

    Dispatch is fire-and-forget on a background thread so the gate's hot
    path never blocks. The audit log gets one `notify.dispatched` event
    per channel that succeeded so you can grep `quill audit show --type
    notify.dispatched` to see what actually fired.
    """

    config: NotifyConfig
    audit_emit: Any = None  # callable(event_type, payload) → None; injected by proxy
    _channels: tuple[Any, ...] = field(default=_CHANNELS)

    def should_fire(self, msg: BlockMessage) -> bool:
        if not self.config.enabled:
            return False
        if msg.decision == "blocked" and not self.config.on_blocked:
            return False
        if msg.decision == "ask" and not self.config.on_ask:
            return False
        if self.config.on_critical_only and msg.risk != "critical":
            return False
        return True

    def fire(self, msg: BlockMessage, *, wait_timeout: float | None = None) -> None:
        """Dispatch the block message to every configured channel.

        With `wait_timeout=None` (default): spawn a daemon background thread
        and return immediately. Suitable for long-lived processes.

        With `wait_timeout=<seconds>` (e.g. 0.1): spawn the thread but
        `join()` it for up to that many seconds before returning. Required
        for short-lived hook subprocesses (Claude Code's PreToolUse), where
        daemon threads get killed when the parent exits before they can
        complete the channel call or emit the audit event. Channels are
        designed to be fast (<50ms each); 100ms is a comfortable budget.
        """
        if not self.should_fire(msg):
            return
        t = threading.Thread(target=self._dispatch, args=(msg,), daemon=True)
        t.start()
        if wait_timeout is not None:
            t.join(timeout=wait_timeout)

    def _dispatch(self, msg: BlockMessage) -> None:
        results: dict[str, bool] = {}
        for chan in self._channels:
            name = chan.__name__.removeprefix("_send_")
            try:
                results[name] = bool(chan(self.config, msg))
            except Exception:  # pragma: no cover - channels are best-effort
                results[name] = False
        if self.audit_emit is not None:
            with contextlib.suppress(Exception):
                self.audit_emit(
                    "notify.dispatched",
                    {
                        "tool_name": msg.tool_name,
                        "decision": msg.decision,
                        "risk": msg.risk,
                        "channels": results,
                        "approve_token": msg.approve_token,
                    },
                )
        # Fallback delivery log: write a single JSON line to
        # $QUILL_HOME/notify.log so the user can grep "did this fire?"
        # even when Focus mode / DND silently suppressed every GUI banner.
        # Best-effort - failures here never propagate.
        with contextlib.suppress(Exception):
            self._append_delivery_log(msg, results)

    def _append_delivery_log(
        self, msg: BlockMessage, results: dict[str, bool],
    ) -> None:
        from quill.paths import default_path
        line = json.dumps(
            {
                "ts": _now_iso(),
                "decision": msg.decision,
                "risk": msg.risk,
                "tool_name": msg.tool_name,
                "what": msg.what,
                "approve_token": msg.approve_token,
                "channels": results,
                "any_succeeded": any(results.values()),
            },
            separators=(",", ":"),
        )
        p = default_path("notify.log", env_override="QUILL_NOTIFY_LOG")
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a") as f:
            f.write(line + "\n")
        with contextlib.suppress(OSError):
            p.chmod(0o600)
