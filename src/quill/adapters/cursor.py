"""Cursor 1.7+ pre-tool-call hook adapter.

Cursor (the AI-first VS Code fork, ~1.5M MAU) shipped a `hooks` system in
v1.7 (Sept 2025) that's near-identical to Claude Code's PreToolUse: the
IDE spawns a subprocess on every tool/shell/MCP call, hands it stdin JSON,
reads a verdict on stdout. Eighteen events; the three that matter for
Quill's gate are:

  - `beforeShellExecution`  - Cursor's built-in shell tool
  - `beforeMCPExecution`    - every call routed through any MCP server
  - `beforeReadFile`        - file reads (less critical; opt-in)

Quill's existing risk classifier + audit log + approvals + Touch ID flow
all work unchanged. The only adapter-layer work is the field-rename
between Cursor's input/output JSON and Quill's internal `decide()` core.

FEATURE GAPS RELATIVE TO CLAUDE CODE ADAPTER
--------------------------------------------
The Cursor adapter is intentionally smaller than the Claude Code adapter
and skips four pieces of plumbing that are wired in `claude_code.py`.
Cursor users get the gate, the audit log, and the approve-flow; they do
NOT get the dashboard / receipts / bridge observability primitives that
depend on these events. This is a known parity gap, not a bug.

  1. Session tracking. `claude_code.py` calls `_track_session` and emits
     `session.open` on first sight of a `session_id` (so receipts and the
     dashboard can group events by session). Cursor adapter does not -
     each event carries `session_id` but no open-event anchors the group.

  2. Lethal-trifecta enforcement. `claude_code.py` calls
     `taint.would_close_trifecta` before allowing and escalates to DENY
     if this call would close the trifecta (untrusted input + private
     data + exfil vector). Cursor adapter has no such check, so a tool
     call that would close the trifecta in Cursor is allowed through.

  3. Sub-agent handoff emission. `claude_code.py` emits
     `agent.handoff.out` on first sight of a sub-session (Task tool
     spawn). Cursor adapter does not. As a result, `quill bridge` will
     show no A2A edges for Cursor-driven multi-agent workflows.

  4. Lazy daemon spawn. `claude_code.py` calls `watch.ensure_daemon` so
     the dashboard self-heals across reboots. Cursor adapter does not.
     A Cursor user has to run `quill start` or `quill watch` manually.

Closing this gap is roughly 200 LOC and should factor a
`run_hook_common(adapter_name, ...)` helper rather than duplicating the
Claude Code logic. Until then: Cursor users see audit events and gating,
but `quill receipts`, `quill bridge`, and the dashboard's session view
will be empty for sessions originating from Cursor.

Hook contract (verified at https://cursor.com/docs/hooks):

  Config at `~/.cursor/hooks.json`:
    {
      "version": 1,
      "hooks": {
        "beforeShellExecution": [
          { "command": "quill cursor-hook", "type": "command", "timeout": 30 }
        ]
      }
    }

  Stdin (Cursor → Quill, one JSON line):
    { "command": "rm -rf /",
      "cwd": "/repo",
      "sandbox": false,
      "conversation_id": "...",
      "hook_event_name": "beforeShellExecution" }

  Stdout (Quill → Cursor, one JSON line):
    { "permission": "deny",
      "agent_message": "rm -rf is blocked by Quill policy",
      "user_message": "Use git clean -fdx if you really mean it." }

Per [the Cursor forum](https://forum.cursor.com/t/beforeshellexecution-hook-permissions-allow-ask-ignored-allow-list-takes-precedence/144244)
`permission: "ask"` can be silently overridden by Cursor's allow-list when
the user has enabled Auto-Run mode. Quill returns `"deny"` (not `"ask"`)
on HIGH-risk calls when running under Cursor so the gate isn't bypassed.
"""
from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Mapping
from typing import Any

from quill.adapters.claude_code import (
    HookDecision,
    _maybe_notify,
    _redacted_input,
    classify_event,
)
from quill.adapters.claude_code import (
    decide as _claude_decide,
)
from quill.audit import AuditLog
from quill.config import default_audit_path
from quill.errors import ConfigError
from quill.policy import Risk

# Cursor's event names → the abstract "tool name" we feed to classify_event.
# beforeShellExecution maps to "Bash" so the shell-command classifier fires.
# beforeMCPExecution maps to whatever MCP tool name was advertised (already
# in the payload). beforeReadFile maps to "Read".
_EVENT_TOOL_NAME: dict[str, str] = {
    "beforeShellExecution": "Bash",
    "beforeReadFile": "Read",
    "beforeMCPExecution": "",   # use payload's tool_name verbatim
    # Cursor's other events (afterFileEdit, beforeSubmitPrompt, etc.) are
    # observability hooks, not gate hooks - Quill ignores them by passing
    # through `allow`.
}


def _normalize_input(raw: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    """Cursor stdin → (tool_name, tool_input) for Quill's classifier.

    Cursor's stdin schema varies per hook event. Normalize so the
    risk classifier sees the same shape it does for Claude Code.
    """
    event = str(raw.get("hook_event_name", "") or "")
    if event == "beforeShellExecution":
        return "Bash", {
            "command": str(raw.get("command", "") or ""),
            "cwd": str(raw.get("cwd", "") or ""),
        }
    if event == "beforeReadFile":
        return "Read", {
            "file_path": str(raw.get("path", "") or raw.get("file_path", "") or ""),
        }
    if event == "beforeMCPExecution":
        # Cursor's MCP hook payload includes `tool_name` and `tool_input`
        # (or `arguments`) verbatim from the upstream MCP server.
        tool = str(raw.get("tool_name", "") or "")
        args = raw.get("tool_input") or raw.get("arguments") or {}
        if not isinstance(args, Mapping):
            args = {}
        return tool, dict(args)
    # Unknown / future event: fall through, let it allow.
    tool = str(raw.get("tool_name", "") or event or "")
    args = raw.get("tool_input") or {}
    if not isinstance(args, Mapping):
        args = {}
    return tool, dict(args)


def decide(tool_name: str, tool_input: Mapping[str, Any]) -> HookDecision:
    """Cursor-specific decide(). Same risk model as Claude Code, but on
    HIGH risk we return `deny` instead of `ask` because Cursor's allow-list
    in Auto-Run can silently bypass `ask` (forum-reported, see module doc).
    """
    base = _claude_decide(tool_name, tool_input)
    if base.permission == "ask":
        # Force a hard deny + paste-able fix instead of a soft ask. The
        # user explicitly approves via `quill approve <token>` (the same
        # one-shot approval flow as Claude Code), which Cursor's allow-list
        # CAN'T override.
        risk, reason, suggestion = classify_event(tool_name, tool_input)
        body = f"high risk: {reason}"
        if suggestion:
            body = f"{body} · try: {suggestion}"
        return HookDecision(
            permission="deny",
            reason=body + " · approve via `quill approve <token>` to release",
            risk=risk,
            audit_event_type="verdict.blocked",
            what=base.what, why=base.why, try_instead=base.try_instead,
        )
    return base


def run_hook(stdin_text: str, audit: AuditLog | None = None) -> dict[str, Any]:
    """Pure-function entry point for tests.

    Reads Cursor's stdin JSON, returns the dict that should be written to
    stdout. Matches the contract documented at cursor.com/docs/hooks.
    """
    try:
        event: dict[str, Any] = json.loads(stdin_text)
    except json.JSONDecodeError as e:
        # Fail-open on malformed input - same stance as the Claude Code
        # adapter. Cursor's hook system shouldn't crash on a parse bug.
        return {
            "permission": "allow",
            "agent_message": f"quill: malformed cursor-hook input: {e}",
        }

    event_name = str(event.get("hook_event_name", "") or "")
    tool_name, tool_input = _normalize_input(event)
    if not tool_name:
        return {"permission": "allow"}

    cwd = str(event.get("cwd", "") or "")
    session_id = str(
        event.get("conversation_id") or event.get("session_id") or "cursor",
    )

    decision = decide(tool_name, tool_input)
    agent_id = "cursor"

    # One-shot approval check (same flow as Claude Code).
    approval_token_used = ""
    if decision.permission != "allow":
        with contextlib.suppress(Exception):
            from quill.approvals import ApprovalStore
            store = ApprovalStore.load()
            consumed = store.consume(tool_name, dict(tool_input))
            if consumed is not None:
                approval_token_used = consumed.token
                decision = HookDecision(
                    permission="allow",
                    reason=f"approved one-shot via quill approve {consumed.token[:8]}",
                    risk=decision.risk,
                    audit_event_type="verdict.allowed",
                    what=decision.what,
                    why=f"user-approved (token {consumed.token[:8]})",
                    try_instead="",
                )

    # Audit-emit + issue approval token + fire notifications.
    if audit is not None:
        from quill import events as ev

        with contextlib.suppress(Exception):
            issued_token = approval_token_used
            if not issued_token and decision.permission != "allow":
                with contextlib.suppress(Exception):
                    from quill.approvals import ApprovalStore
                    store = ApprovalStore.load()
                    ap = store.issue(
                        tool_name, dict(tool_input),
                        reason=decision.why or decision.reason,
                    )
                    issued_token = ap.token

            audit.emit(
                event_type=ev.TOOL_ATTEMPTED,
                session_id=session_id,
                agent_id=agent_id,
                risk=decision.risk.value,
                payload={
                    "tool_name": tool_name,
                    "via": "cursor-hook",
                    "hook_event_name": event_name,
                    "args_preview": _redacted_input(tool_input),
                    "cwd": cwd,
                },
            )
            audit.emit(
                event_type=decision.audit_event_type,
                session_id=session_id,
                agent_id=agent_id,
                risk=decision.risk.value,
                payload={
                    "tool_name": tool_name,
                    "by": "quill.adapters.cursor",
                    "reason": decision.reason,
                    "permission": decision.permission,
                    "cwd": cwd,
                    "approve_token": issued_token,
                    "what": decision.what,
                    "why": decision.why,
                    "try_instead": decision.try_instead,
                },
                force_fsync=decision.risk in (Risk.HIGH, Risk.CRITICAL),
            )

            if decision.permission == "deny" and issued_token:
                with contextlib.suppress(Exception):
                    _maybe_notify(
                        decision=decision,
                        tool_name=tool_name,
                        tool_input=tool_input,
                        session_id=session_id,
                        cwd=cwd,
                        approve_token=issued_token,
                        audit=audit,
                    )

    # Cursor's response shape (NOT Claude Code's hookSpecificOutput).
    response: dict[str, Any] = {"permission": decision.permission}
    if decision.permission != "allow":
        # `agent_message` goes into the LLM's context (so the agent can
        # course-correct). `user_message` is what Cursor shows the human.
        response["agent_message"] = decision.reason
        if decision.try_instead:
            response["user_message"] = (
                f"Quill blocked: {decision.what or tool_name}. "
                f"Try: {decision.try_instead}"
            )
        else:
            response["user_message"] = f"Quill blocked: {decision.reason}"
    elif approval_token_used:
        # Allow-after-approval: tell the agent the gate was released
        # out-of-band so it doesn't retry-spam.
        response["agent_message"] = decision.reason
    return response


def install_into_settings(settings_path: Any = None) -> tuple[Any, bool]:
    """Idempotently merge Quill into ~/.cursor/hooks.json.

    Returns (path, was_already_installed). Adds three hook events
    (beforeShellExecution, beforeMCPExecution, beforeReadFile) pointing
    at `quill cursor-hook`. Does NOT clobber other hooks the user has.
    """
    from pathlib import Path

    path = settings_path or Path.home() / ".cursor" / "hooks.json"
    path.parent.mkdir(parents=True, exist_ok=True)

    existing: dict[str, Any] = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text() or "{}")
        except json.JSONDecodeError:
            existing = {}
    if not isinstance(existing, dict):
        existing = {}

    if "version" not in existing:
        existing["version"] = 1
    hooks_block = existing.setdefault("hooks", {})
    if not isinstance(hooks_block, dict):
        hooks_block = {}
        existing["hooks"] = hooks_block

    quill_entry = {"command": "quill cursor-hook", "type": "command", "timeout": 30}
    was_already = True
    for event_name in ("beforeShellExecution", "beforeMCPExecution", "beforeReadFile"):
        existing_handlers = hooks_block.get(event_name) or []
        if not isinstance(existing_handlers, list):
            existing_handlers = []
        already = any(
            isinstance(h, dict) and h.get("command", "").startswith("quill ")
            for h in existing_handlers
        )
        if not already:
            existing_handlers.append(dict(quill_entry))
            was_already = False
        hooks_block[event_name] = existing_handlers

    with contextlib.suppress(OSError):
        path.write_text(json.dumps(existing, indent=2) + "\n")
        path.chmod(0o600)
    return path, was_already


def main() -> int:
    """CLI entry: read stdin, write stdout, exit 0.

    Wired to `quill cursor-hook` via the CLI module. Routes the audit
    log to <cwd>/.quill/audit.log.jsonl when the user has opted in to
    per-project mode (just like the Claude Code adapter).
    """
    from quill.adapters.claude_code import _default_load_hmac_key, _resolve_project_paths

    stdin_text = sys.stdin.read()
    cwd_for_routing = ""
    try:
        peek = json.loads(stdin_text or "{}")
        if isinstance(peek, dict):
            cwd_for_routing = str(peek.get("cwd", "") or "")
    except json.JSONDecodeError:
        pass

    log_path, project_cfg_path = _resolve_project_paths(cwd_for_routing)
    if project_cfg_path is not None:
        with contextlib.suppress(ConfigError, OSError, ValueError):
            from quill.config import load_config
            load_config(project_cfg_path)

    log_path = log_path or default_audit_path()
    try:
        with AuditLog(path=log_path, hmac_key=_default_load_hmac_key()) as audit:
            response = run_hook(stdin_text, audit=audit)
    except Exception as e:
        # NEVER crash the hook - Cursor would surface the error to the
        # agent, which would interpret it as "the call is fine."
        response = {
            "permission": "allow",
            "agent_message": f"quill: hook crashed (bug, fail-open): {e}",
        }

    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
    return 0
