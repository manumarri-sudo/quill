"""Claude Code PreToolUse hook adapter.

Claude Code's built-in tools (Bash, Edit, Write, Read, ...) do not flow
through any MCP server, so the Quill MCP proxy cannot see them. Claude Code
exposes a `PreToolUse` hook that fires synchronously before each tool call;
this adapter implements that hook contract so Quill can gate the built-ins.

Wiring (one paste into ~/.claude/settings.json):

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "Bash|Edit|Write|NotebookEdit",
            "hooks": [
              { "type": "command", "command": "quill claude-hook", "timeout": 10 }
            ]
          }
        ]
      }
    }

The hook contract (Claude Code → stdin):

    {
      "session_id": "uuid",
      "transcript_path": "/path/to/session.jsonl",
      "cwd": "/current/dir",
      "permission_mode": "auto|plan|acceptEdits|dontAsk|default",
      "hook_event_name": "PreToolUse",
      "tool_name": "Bash",
      "tool_input": {"command": "rm -rf /"}
    }

The hook reply (stdout, exit 0):

    {
      "hookSpecificOutput": {
        "permissionDecision": "allow|deny|ask",
        "permissionDecisionReason": "<plain English>"
      }
    }

Mapping rules (defaults; per-tool overrides loaded from ~/.quill/config.toml):
    LOW      -> "allow"     (silent; logged)
    MEDIUM   -> "allow"     (silent; logged)
    HIGH     -> "ask"       (delegate confirmation to Claude Code's UI; logged)
    CRITICAL -> "deny"      (with plain-English reason; logged)

Every invocation appends an entry to the audit log regardless of decision,
so you can review what the agent attempted even when Claude Code's UI moved
on. The audit log path defaults to ~/.quill/audit.log.jsonl; override with
QUILL_LOG.
"""
from __future__ import annotations

import contextlib
import json
import os
import secrets
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from quill.audit import AuditLog
from quill.config import default_audit_path, load_config
from quill.errors import ConfigError
from quill.policy import Risk, classify, classify_command

# Map Claude Code's built-in tool names to a default risk *when args do not
# carry enough info to classify by content*. Bash uses classify_command on
# args["command"]; everything else falls back to this table.
DEFAULT_BUILTIN_RISK: Final[Mapping[str, Risk]] = {
    "Bash": Risk.MEDIUM,        # superseded by classify_command on args["command"]
    "BashOutput": Risk.LOW,
    "KillShell": Risk.MEDIUM,
    "Edit": Risk.HIGH,
    "Write": Risk.HIGH,
    "NotebookEdit": Risk.HIGH,
    "Read": Risk.LOW,
    "Glob": Risk.LOW,
    "Grep": Risk.LOW,
    "WebFetch": Risk.MEDIUM,
    "WebSearch": Risk.LOW,
    "Task": Risk.MEDIUM,         # spawns a sub-agent; logged as such
    "TodoWrite": Risk.LOW,
}


@dataclass(slots=True)
class HookDecision:
    """The gate's verdict for a single Claude Code PreToolUse event."""

    permission: str        # "allow" | "deny" | "ask"
    reason: str
    risk: Risk
    audit_event_type: str  # written to the audit log


def _default_load_hmac_key() -> bytes:
    """Mirror cli._hmac_key() but importable from the adapter without a circular import."""
    p = Path(os.environ.get("QUILL_KEY", "~/.quill/key")).expanduser()
    if p.exists():
        return p.read_bytes()
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    p.write_bytes(key)
    p.chmod(0o600)
    return key


def classify_event(tool_name: str, tool_input: Mapping[str, Any]) -> tuple[Risk, str]:
    """Decide the risk + plain-English reason for a Claude Code tool call."""
    if tool_name == "Bash":
        cmd = str(tool_input.get("command", ""))
        c = classify_command(cmd)
        return c.risk, c.reason

    # User config can override per-tool risk via the [policy] table:
    # ["Bash"] = "high", ["Edit"] = "low", etc. Loaded best-effort: the hook
    # never crashes on a missing/invalid config, it just falls back to defaults.
    user_override: Risk | None = None
    with contextlib.suppress(ConfigError, OSError, ValueError):
        cfg = load_config()
        user_override = cfg.policy.get(tool_name)

    if user_override is not None:
        return user_override, "user policy override"

    if tool_name in DEFAULT_BUILTIN_RISK:
        return DEFAULT_BUILTIN_RISK[tool_name], f"default risk for {tool_name}"

    # Unknown tool name (custom MCP tool surfaced through Claude Code) — use
    # the namespace-based classifier as a last resort.
    return classify(tool_name), f"namespace classifier for {tool_name}"


def decide(tool_name: str, tool_input: Mapping[str, Any]) -> HookDecision:
    """Risk + decision for a single Claude Code PreToolUse event."""
    risk, reason = classify_event(tool_name, tool_input)
    if risk is Risk.CRITICAL:
        return HookDecision(
            permission="deny",
            reason=f"Quill blocked: {reason}. To allow, lower the risk in "
                   "your quill config or run the command outside Claude Code.",
            risk=risk,
            audit_event_type="verdict.blocked",
        )
    if risk is Risk.HIGH:
        return HookDecision(
            permission="ask",
            reason=f"Quill flagged this as high risk ({reason}). Claude "
                   "Code is asking you to confirm.",
            risk=risk,
            audit_event_type="verdict.ask",
        )
    return HookDecision(
        permission="allow",
        reason=f"Quill allowed: {reason}.",
        risk=risk,
        audit_event_type="verdict.allowed",
    )


def _redacted_input(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    """Truncate string args so we never log secrets in full.

    Args longer than 200 chars are shown with their length and a 200-char
    head only. Non-string args pass through.
    """
    out: dict[str, Any] = {}
    for k, v in tool_input.items():
        if isinstance(v, str) and len(v) > 200:
            out[k] = f"{v[:200]}…[truncated, {len(v)} chars]"
        else:
            out[k] = v
    return out


def run_hook(stdin_text: str, audit: AuditLog | None = None) -> dict[str, Any]:
    """Pure-function entry point for tests.

    Reads a JSON event from stdin_text, returns the dict that should be
    written to stdout. If `audit` is given, appends an audit entry; otherwise
    skips logging (used by tests).
    """
    try:
        event: dict[str, Any] = json.loads(stdin_text)
    except json.JSONDecodeError as e:
        return {
            "hookSpecificOutput": {
                "permissionDecision": "allow",  # fail-open on malformed input;
                # the alternative (deny) would trap users behind a parser bug.
                "permissionDecisionReason": f"quill: malformed hook input: {e}",
            },
        }

    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, Mapping):
        tool_input = {}
    session_id = str(event.get("session_id", "claude-code"))

    decision = decide(tool_name, tool_input)

    if audit is not None:
        # Always emit BOTH the attempt and the verdict so the chain is
        # complete on a tool-by-tool basis even when the verdict is "allow".
        with contextlib.suppress(Exception):
            audit.emit(
                event_type="tool.attempted",
                session_id=session_id,
                agent_id="claude-code",
                risk=decision.risk.value,
                payload={
                    "tool_name": tool_name,
                    "arg_keys": sorted(tool_input.keys()),
                    "arg_count": len(tool_input),
                    "args_preview": _redacted_input(tool_input),
                    "via": "claude-code-hook",
                },
            )
            audit.emit(
                event_type=decision.audit_event_type,
                session_id=session_id,
                agent_id="claude-code",
                risk=decision.risk.value,
                payload={
                    "tool_name": tool_name,
                    "by": "quill.adapters.claude_code",
                    "reason": decision.reason,
                    "permission": decision.permission,
                },
                force_fsync=decision.risk in (Risk.HIGH, Risk.CRITICAL),
            )

    return {
        "hookSpecificOutput": {
            "permissionDecision": decision.permission,
            "permissionDecisionReason": decision.reason,
        },
    }


def main() -> int:
    """CLI entry: read stdin, write stdout, exit 0.

    Wired to `quill claude-hook` via the CLI module.
    """
    stdin_text = sys.stdin.read()
    log_path = Path(os.environ.get("QUILL_LOG", "")).expanduser() or default_audit_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with AuditLog(path=log_path, hmac_key=_default_load_hmac_key()) as audit:
            response = run_hook(stdin_text, audit=audit)
    except Exception as e:  # noqa: BLE001 — fail-open on any internal error
        sys.stderr.write(f"quill claude-hook: internal error, allowing fail-open: {e}\n")
        response = {
            "hookSpecificOutput": {
                "permissionDecision": "allow",
                "permissionDecisionReason": f"quill internal error (fail-open): {e}",
            },
        }
    sys.stdout.write(json.dumps(response))
    sys.stdout.flush()
    return 0


# --------------------------------------------------------------------------
# Install helper: write the settings.json snippet for the user.
# --------------------------------------------------------------------------

DEFAULT_CC_SETTINGS = Path("~/.claude/settings.json").expanduser()


def install_snippet(matcher: str = "Bash|Edit|Write|NotebookEdit",
                    timeout: int = 10) -> dict[str, Any]:
    """Return the JSON fragment that should be merged into Claude Code settings."""
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": matcher,
                    "hooks": [
                        {
                            "type": "command",
                            "command": "quill claude-hook",
                            "timeout": timeout,
                        },
                    ],
                },
            ],
        },
    }


def install_into_settings(
    settings_path: Path | None = None,
    *,
    matcher: str = "Bash|Edit|Write|NotebookEdit",
    timeout: int = 10,
) -> tuple[Path, bool]:
    """Merge the Quill hook snippet into a Claude Code settings.json.

    Returns (path_written, was_already_installed).

    Conservative behaviour: if a PreToolUse hook with the same matcher and
    command already exists, we don't duplicate. We also never replace
    user-installed unrelated hooks; we append.
    """
    p = settings_path or DEFAULT_CC_SETTINGS
    p.parent.mkdir(parents=True, exist_ok=True)

    existing: dict[str, Any] = {}
    if p.exists():
        with contextlib.suppress(json.JSONDecodeError, OSError):
            existing = json.loads(p.read_text() or "{}")

    hooks_root = existing.setdefault("hooks", {})
    pre_list = hooks_root.setdefault("PreToolUse", [])

    new_block = install_snippet(matcher=matcher, timeout=timeout)["hooks"]["PreToolUse"][0]

    for block in pre_list:
        if (
            block.get("matcher") == matcher
            and any(
                h.get("command") == "quill claude-hook"
                for h in (block.get("hooks") or [])
            )
        ):
            return p, True  # already installed

    pre_list.append(new_block)
    p.write_text(json.dumps(existing, indent=2) + "\n")
    return p, False


if __name__ == "__main__":
    raise SystemExit(main())
