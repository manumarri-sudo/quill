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
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from quill.taint import TaintState

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
    """The gate's verdict for a single Claude Code PreToolUse event.

    Carries the structured triple a notification needs:
      - what:        one-line summary of the call
      - why:         plain-English risk reason
      - try_instead: paste-able safer alternative (if any)

    `reason` is the compact form Claude Code's UI shows; the structured
    fields are passed to the notification dispatcher.
    """

    permission: str        # "allow" | "deny" | "ask"
    reason: str
    risk: Risk
    audit_event_type: str  # written to the audit log
    what: str = ""         # human-readable: "rm -rf node_modules"
    why: str = ""          # human-readable: "matches `rm -rf` rule"
    try_instead: str = ""  # paste-able alternative


def _default_load_hmac_key() -> bytes:
    """Mirror cli._hmac_key() but importable from the adapter without a circular import."""
    from quill.paths import default_path
    p = default_path("key", env_override="QUILL_KEY")
    if p.exists():
        return p.read_bytes()
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    p.write_bytes(key)
    p.chmod(0o600)
    return key


def classify_event(tool_name: str, tool_input: Mapping[str, Any]) -> tuple[Risk, str, str]:
    """Decide the risk + plain-English reason + safer-alternative suggestion."""
    if tool_name == "Bash":
        cmd = str(tool_input.get("command", ""))
        c = classify_command(cmd)
        return c.risk, c.reason, c.suggestion

    # Secret detection on file writes runs FIRST: an agent writing a hardcoded
    # AWS / OpenAI / Anthropic / GitHub / Stripe credential into source is
    # the GitHub-PAT-leak failure mode (Anthropic Nov 2025 incident class).
    # If hits found, escalate to CRITICAL regardless of any policy override.
    from quill.secrets import hit_summary, scan_args
    secret_hits = scan_args(tool_name, tool_input)
    if secret_hits:
        summary = hit_summary(secret_hits)
        return (
            Risk.CRITICAL,
            f"secret detected in write: {summary}",
            "move the value to a secrets manager / env var and reference it by name",
        )

    # User config can override per-tool risk via the [policy] table:
    # ["Bash"] = "high", ["Edit"] = "low", etc. Loaded best-effort: the hook
    # never crashes on a missing/invalid config, it just falls back to defaults.
    user_override: Risk | None = None
    with contextlib.suppress(ConfigError, OSError, ValueError):
        cfg = load_config()
        user_override = cfg.policy.get(tool_name)

    if user_override is not None:
        # Permission Decay: a per-tool policy override is a permission the
        # user granted to themselves. Track it. If it's been dormant past
        # its decay window, ignore the override and let the default fire,
        # AND emit an audit signal so the user sees the fall-back.
        from quill import decay as _decay  # local import to avoid cycles
        store = _decay.DecayStore.load()
        # determine the natural risk of the tool BEFORE the override so
        # we can pick the right decay window (downgrades from critical
        # decay faster than downgrades from medium).
        natural = classify(tool_name)
        kind = _decay.policy_kind(natural.value, user_override.value)
        permission, was_decayed = store.record_use(kind, tool_name)
        if permission.is_decayed:
            # decayed - fall through to default-classifier path. Reason
            # explains why the override didn't apply.
            return (
                natural,
                f"policy override decayed ({permission.age_days}d > "
                f"{permission.decay_after_days}d window) - falling back "
                f"to default {natural.value}; reaffirm with: "
                f"quill decay reaffirm {tool_name}",
                "",
            )
        return user_override, "user policy override", ""

    if tool_name in DEFAULT_BUILTIN_RISK:
        return DEFAULT_BUILTIN_RISK[tool_name], f"default risk for {tool_name}", ""

    # Unknown tool name (custom MCP tool surfaced through Claude Code) - use
    # the namespace-based classifier as a last resort.
    return classify(tool_name), f"namespace classifier for {tool_name}", ""


def _summarize_call(tool_name: str, tool_input: Mapping[str, Any]) -> str:
    """One-line human-readable summary of an attempted tool call.

    Used as the WHAT field on notifications and audit events. Examples:
      Bash + command="rm -rf node_modules"  →  "rm -rf node_modules"
      Edit + file_path="/x/y.py"            →  "Edit /x/y.py"
      Read + file_path=".env"               →  "Read .env"
    """
    if tool_name == "Bash":
        cmd = str(tool_input.get("command", ""))
        return cmd[:200]
    for key in ("file_path", "path", "filename", "url", "uri"):
        v = tool_input.get(key)
        if isinstance(v, str) and v:
            return f"{tool_name} {v[:160]}"
    return tool_name


def decide(tool_name: str, tool_input: Mapping[str, Any]) -> HookDecision:
    """Risk + decision for a single Claude Code PreToolUse event.

    Reasons are kept TIGHT. No "Quill blocked: " / "Quill allowed: "
    prefix - the Claude Code UI already says which decision it is, and
    the prefix wastes tokens (every blocked call ships ~80 chars of
    boilerplate back into the agent's context window). Just the
    machine-readable reason and the paste-able suggestion when one
    exists.

    Also populates the structured WHAT / WHY / TRY-INSTEAD triple on the
    decision so the notification dispatcher can render it consistently
    across macOS Notification Center, email, Slack, and webhooks.
    """
    risk, reason, suggestion = classify_event(tool_name, tool_input)
    what = _summarize_call(tool_name, tool_input)
    if risk is Risk.CRITICAL:
        body = reason
        if suggestion:
            body = f"{reason} · try instead: {suggestion}"
        # Overnight mode counter only - decision is unchanged. CRITICAL
        # NEVER auto-approves; safety contract for the rm-rf / drop-table
        # / vercel-prod / sudo / force-push class is load-bearing.
        with contextlib.suppress(Exception):
            from quill import overnight as _ovn
            ovn_active, _ = _ovn.is_active_from_config()
            if ovn_active:
                _ovn.record_event("critical")
        return HookDecision(
            permission="deny",
            reason=body,
            risk=risk,
            audit_event_type="verdict.blocked",
            what=what, why=reason, try_instead=suggestion,
        )
    if risk is Risk.HIGH:
        body = f"high risk: {reason}"
        if suggestion:
            body = f"{body} · try instead: {suggestion}"
        # Overnight mode: a HIGH-risk action auto-approves WITH a distinct
        # audit_event_type so the morning recap can identify what got
        # through and operators can post-review. The decision string still
        # carries the original reason and the suggestion - none of that
        # context is lost, only the prompt is skipped.
        try:
            from quill import overnight as _ovn
            ovn_active, ovn_reason = _ovn.is_active_from_config()
        except Exception:
            ovn_active, ovn_reason = False, ""
        if ovn_active:
            with contextlib.suppress(Exception):
                from quill import overnight as _ovn2
                _ovn2.record_event("high")
            audit_body = f"{reason} [overnight: {ovn_reason}]"
            return HookDecision(
                permission="allow",
                reason=audit_body,
                risk=risk,
                audit_event_type="verdict.allowed.overnight",
                what=what,
                why=f"auto-approved by overnight mode ({ovn_reason}): {reason}",
                try_instead=suggestion,
            )
        return HookDecision(
            permission="ask",
            reason=body,
            risk=risk,
            audit_event_type="verdict.ask",
            what=what, why=f"high risk: {reason}", try_instead=suggestion,
        )
    return HookDecision(
        permission="allow",
        reason=reason,
        risk=risk,
        audit_event_type="verdict.allowed",
        what=what, why=reason, try_instead=suggestion,
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


# ---- multi-project session tracking ---------------------------------------
# Claude Code's hook payload gives us session_id, transcript_path, and cwd.
# We persist a tiny on-disk index keyed by transcript_path so we can:
#   - notice when a NEW session_id appears under the same transcript
#     (the parent agent spawned a Task sub-agent)
#   - tag every audit event with parent_session_id when applicable
#   - record cwd so audit_show can filter by project
# State file lives at ~/.quill/sessions.json (mode 0o600), schema:
#   { "<transcript_path>": { "root": "<sid>", "seen": ["<sid>", "<sid>", ...],
#                             "cwd": "<path>" } }


def _session_index_path() -> Path:
    from quill.paths import default_path
    return default_path("sessions.json", env_override="QUILL_SESSIONS")


def _taint_path() -> Path:
    from quill.paths import default_path
    return default_path("taint.json", env_override="QUILL_TAINT_FILE")


def _cascade_receivers_path() -> Path:
    from quill.paths import default_path
    return default_path(
        "cascade_receivers.json",
        env_override="QUILL_CASCADE_RECEIVERS",
    )


def _record_handoff_receiver(parent_session_id: str, receiver_session_id: str) -> int:
    """Record a sub-agent receiver for one parent and return the distinct count.

    Keyed by parent_session_id because Claude Code's Task tool gives each
    spawn a UNIQUE payload_hash (the hash includes to_agent_id). The
    research spec's "same payload_hash, >=3 receivers" model maps to
    pub-sub frameworks (LangGraph/CrewAI broadcast). Claude Code's
    spawn-and-fork model produces fan-out instead: one parent, multiple
    distinct sub-agents acting on the same world. Counting sub-agents
    per parent gives the same blast-radius signal under this model.

    Backing file: `{parent_session_id: [sub_session_ids...]}`.
    Returns the new distinct sub-agent count for this parent. The
    `agent.cascade.affected` emission fires the moment this hits 3.
    """
    if not parent_session_id:
        return 0
    p = _cascade_receivers_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(p.read_text()) if p.exists() else {}
    except (OSError, json.JSONDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    receivers = data.get(parent_session_id) or []
    if not isinstance(receivers, list):
        receivers = []
    if receiver_session_id not in receivers:
        receivers.append(receiver_session_id)
    data[parent_session_id] = receivers
    with contextlib.suppress(OSError):
        p.write_text(json.dumps(data))
        p.chmod(0o600)
    return len(receivers)


def _taint_state_for(session_id: str) -> TaintState:
    """Load TaintState for one session_id from the per-session taint store."""
    from quill.taint import TaintState
    p = _taint_path()
    if not p.exists():
        return TaintState()
    try:
        all_states = json.loads(p.read_text() or "{}")
    except (OSError, json.JSONDecodeError):
        return TaintState()
    raw = all_states.get(session_id) or {}
    return TaintState(
        has_seen_untrusted=bool(raw.get("has_seen_untrusted", False)),
        has_accessed_private=bool(raw.get("has_accessed_private", False)),
        can_exfiltrate=bool(raw.get("can_exfiltrate", False)),
    )


def _save_taint_state(session_id: str, state: TaintState) -> None:
    p = _taint_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        all_states = json.loads(p.read_text() or "{}") if p.exists() else {}
    except (OSError, json.JSONDecodeError):
        all_states = {}
    if not isinstance(all_states, dict):
        all_states = {}
    all_states[session_id] = state.to_dict()
    with contextlib.suppress(OSError):
        p.write_text(json.dumps(all_states))
        p.chmod(0o600)


def _track_session(
    *, transcript_path: str, session_id: str, cwd: str,
) -> tuple[str, bool, bool]:
    """Update the session index, return (parent_session_id, is_new_subagent, is_first_seen).

    parent_session_id is "" if this IS the root session, otherwise the
    root's session_id. is_new_subagent is True the FIRST time we see a
    given non-root session_id under a transcript. is_first_seen is True
    the FIRST time we see this session_id at all (root or sub) - used to
    emit session.open exactly once per session.
    """
    p = _session_index_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        index = json.loads(p.read_text()) if p.exists() else {}
    except (OSError, json.JSONDecodeError):
        index = {}
    if not isinstance(index, dict):
        index = {}

    rec = index.get(transcript_path) or {}
    seen = rec.get("seen") or []
    if not isinstance(seen, list):
        seen = []
    root = rec.get("root")
    is_new_sub = False
    is_first_seen = False
    if not root:
        root = session_id
        seen = [session_id]
        is_first_seen = True
    elif session_id not in seen:
        seen.append(session_id)
        is_new_sub = (session_id != root)
        is_first_seen = True

    index[transcript_path] = {"root": root, "seen": seen, "cwd": cwd}
    with contextlib.suppress(OSError):
        p.write_text(json.dumps(index))
        p.chmod(0o600)

    parent = "" if session_id == root else root
    return parent, is_new_sub, is_first_seen


def _maybe_notify(
    *,
    decision: HookDecision,
    tool_name: str,
    tool_input: Mapping[str, Any],
    session_id: str,
    cwd: str,
    approve_token: str,
    audit: AuditLog,
) -> None:
    """Dispatch out-of-band notifications if [notify] is configured.

    Best-effort: if config can't be loaded, returns silently. The
    NotifyDispatcher itself runs each channel on a background thread so
    this function returns immediately even when channels are slow.
    """
    from quill.notify import BlockMessage, NotifyConfig, NotifyDispatcher

    raw_notify: Mapping[str, Any] | None = None
    # QuillConfig is strict (extra="forbid"), so [notify] is read straight
    # from the raw TOML for v0.2's first wire-up. A pydantic NotifyConfig
    # in config.py is the next refactor.
    with contextlib.suppress(Exception):
        import tomllib  # py3.11+

        from quill.config import default_config_path
        cfg_path = default_config_path()
        if cfg_path.exists():
            with cfg_path.open("rb") as f:
                raw = tomllib.load(f)
            raw_notify = raw.get("notify") if isinstance(raw, dict) else None
    if not raw_notify:
        return

    notify_cfg = NotifyConfig.from_dict(raw_notify)
    if not notify_cfg.enabled:
        return

    msg = BlockMessage(
        risk=decision.risk.value,
        decision="blocked" if decision.permission == "deny" else "ask",
        tool_name=tool_name,
        args_preview=_redacted_input(tool_input),
        what=decision.what or tool_name,
        why=decision.why or decision.reason,
        try_instead=decision.try_instead,
        approve_token=approve_token,
        cwd=cwd,
        session_id=session_id,
    )

    def _emit_dispatched(event_type: str, payload: Mapping[str, Any]) -> None:
        with contextlib.suppress(Exception):
            audit.emit(
                event_type=event_type,
                session_id=session_id,
                agent_id="quill.notify",
                risk="low",
                payload=dict(payload),
            )

    dispatcher = NotifyDispatcher(config=notify_cfg, audit_emit=_emit_dispatched)
    # The PreToolUse hook is a short-lived subprocess; daemon threads die
    # when it exits, so we block for up to 100ms to let the dispatch
    # complete. Channels are designed to return in <50ms each (osascript,
    # SMTP connect, urlopen); 100ms is comfortable headroom.
    dispatcher.fire(msg, wait_timeout=0.1)


def _resolve_project_paths(cwd: str) -> tuple[Path, Path | None]:
    """Given the cwd Claude Code passed us, return:
       (audit_log_path, per_project_config_path or None).

    Per-project audit logs live at <cwd>/.quill/audit.log.jsonl; per-project
    config at <cwd>/.quill/config.toml. Both are opt-in: the user creates
    the .quill/ directory in their project to activate per-project mode.
    Otherwise we fall back to the global ~/.quill/ paths.
    """
    raw = os.environ.get("QUILL_LOG", "").strip()
    if raw:
        return Path(raw).expanduser(), None

    cwd_p = Path(cwd).expanduser() if cwd else None
    if cwd_p and (cwd_p / ".quill").is_dir():
        return (
            cwd_p / ".quill" / "audit.log.jsonl",
            (cwd_p / ".quill" / "config.toml")
            if (cwd_p / ".quill" / "config.toml").exists() else None,
        )
    return default_audit_path(), None


def _is_bypass_mode() -> bool:
    """True if the operator has explicitly opted out of permission
    prompts at the Claude Code level (running with
    `--dangerously-skip-permissions` or with
    `skipDangerousModePermissionPrompt: true` in settings.json).

    When this is true, Quill's default-HIGH-risk Edit/Write asks are
    redundant - the operator told Claude Code "stop asking me". The
    downshift only applies to the DEFAULT classification; pattern-
    matched HIGHs (vercel --prod, rm -rf, etc.) and CRITICAL events
    still fire regardless of bypass mode.

    Cached per-process via the QUILL_BYPASS_CACHE module global. Set
    QUILL_RESPECT_BYPASS=0 to force-disable the downshift even when
    settings.json says bypass is on.
    """
    if os.environ.get("QUILL_RESPECT_BYPASS", "1") == "0":
        return False
    # Honor an explicit env override for tests / deterministic CI runs.
    forced = os.environ.get("QUILL_BYPASS_MODE", "").strip()
    if forced:
        return forced.lower() in ("1", "true", "yes", "on")
    try:
        settings = Path("~/.claude/settings.json").expanduser()
        if not settings.exists():
            return False
        data = json.loads(settings.read_text() or "{}")
        if not isinstance(data, dict):
            return False
        return bool(data.get("skipDangerousModePermissionPrompt"))
    except (OSError, json.JSONDecodeError):
        return False


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
                "hookEventName": "PreToolUse",
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
    transcript_path = str(event.get("transcript_path", "") or "")
    cwd = str(event.get("cwd", "") or "")

    # Track session lineage so we can tag sub-agent calls.
    parent_session_id = ""
    is_new_sub = False
    is_first_seen = False
    if transcript_path and session_id:
        with contextlib.suppress(Exception):
            parent_session_id, is_new_sub, is_first_seen = _track_session(
                transcript_path=transcript_path,
                session_id=session_id,
                cwd=cwd,
            )

    decision = decide(tool_name, tool_input)
    agent_id = "claude-code-sub" if parent_session_id else "claude-code"

    # Snapshot the classifier's original reason BEFORE any downstream
    # transformation (trust scope, bypass mode, approval-token consume)
    # rewrites the HookDecision. Learning uses this so a token consume
    # records the approve under the SAME pattern_id that previously
    # recorded the deny - not under a per-token "approved one-shot"
    # pattern that would split the same underlying rule into N rows.
    original_decision_reason = decision.reason

    # Trust-scope downshift: a default-HIGH-risk Edit/Write inside a
    # trusted directory (listed in `[trust] paths` in config.toml) is
    # downgraded to LOW + auto-allow. This is the fix for the
    # approval-fatigue problem: 991 high-risk Edit/Write asks in a
    # single week of dogfooding, 92% noise. Only the DEFAULT
    # classification is downshifted - pattern-matched HIGHs (Bash
    # commands matching the HIGH regex set, per-tool policy overrides)
    # and all CRITICAL events are NOT affected.
    if (
        decision.permission == "ask"
        and tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit")
        and "default risk for" in decision.reason
        and cwd
    ):
        with contextlib.suppress(Exception):
            from quill.paths import is_trusted_cwd
            if is_trusted_cwd(cwd):
                # Trust scope yields to trifecta enforcement: if the session
                # is already at 2-of-3 flags and THIS call would close the
                # third, we must not silently auto-allow. The trifecta
                # enforcement block below will turn the ask back into a
                # deny + approve-token. Trust scope still suppresses every
                # other default-risk Edit/Write ask in trusted dirs.
                would_close = False
                if session_id:
                    with contextlib.suppress(Exception):
                        from quill.taint import would_close_trifecta
                        current = _taint_state_for(session_id)
                        would_close = would_close_trifecta(current, tool_name, tool_input)
                if not would_close:
                    decision = HookDecision(
                        permission="allow",
                        reason=f"trusted scope: {tool_name} in {cwd}",
                        risk=Risk.LOW,
                        audit_event_type="verdict.allowed",
                        what=decision.what,
                        why="trusted scope (config [trust] paths)",
                        try_instead="",
                    )

    # Promoted-override downshift: the operator explicitly promoted a
    # loosening_candidate via `quill suggestions promote <key> --ttl-days N`,
    # which wrote a block into ~/.quill/overrides.toml. If THIS call's
    # pattern_id has an active (non-expired) override, downshift the
    # decision. The override is operator-approved and TTL'd; never
    # silent, never permanent.
    #
    # Same safety invariant as trust scope: ONLY downshifts the default
    # ask path. CRITICAL events (decision.permission == "deny" from
    # classify_command pattern match) bypass this check entirely and
    # still fire.
    if decision.permission == "ask" and "default risk for" in decision.reason:
        with contextlib.suppress(Exception):
            from quill.learn import _normalize_block_reason
            from quill.learning import load_active_overrides
            head = _normalize_block_reason(original_decision_reason) or original_decision_reason
            pattern_id = f"{tool_name}:{head}"[:80]
            overrides = load_active_overrides()
            if pattern_id in overrides:
                ov = overrides[pattern_id]
                decision = HookDecision(
                    permission="allow",
                    reason=(
                        f"operator-promoted override "
                        f"({ov['remaining_days']:.1f} days remaining)"
                    ),
                    risk=Risk.LOW,
                    audit_event_type="verdict.allowed",
                    what=decision.what,
                    why=f"operator promoted pattern via quill suggestions promote",
                    try_instead="",
                )

    # Bypass-mode downshift: the operator has explicitly opted out of
    # Claude Code's permission prompts (skipDangerousModePermissionPrompt
    # in settings.json, or running with --dangerously-skip-permissions).
    # In that mode, default-HIGH Edit/Write asks are redundant prompts
    # the operator already told the host harness to skip. We respect
    # the operator's setting. Pattern-matched HIGHs and CRITICAL events
    # still fire. Operator can force-disable via QUILL_RESPECT_BYPASS=0.
    if (
        decision.permission == "ask"
        and tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit")
        and "default risk for" in decision.reason
    ):
        with contextlib.suppress(Exception):
            if _is_bypass_mode():
                decision = HookDecision(
                    permission="allow",
                    reason=f"bypass mode: {tool_name} (skipDangerousModePermissionPrompt=true)",
                    risk=Risk.LOW,
                    audit_event_type="verdict.allowed",
                    what=decision.what,
                    why="operator opted into bypass mode at the Claude Code level",
                    try_instead="",
                )

    # One-shot approval check: if the user ran `quill approve <token>` for
    # this exact (tool_name, args) within the TTL, consume the approval
    # and let the call through. This is the "go ahead" path the user
    # walks after seeing a notification.
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

    # Trifecta enforcement: if THIS call would close the lethal trifecta
    # (untrusted input + private data + exfil) for the first time, escalate
    # an otherwise-allow decision to a deny so the user can decide. Skip
    # if the user already approved this exact call out-of-band.
    if (
        decision.permission == "allow"
        and not approval_token_used
        and session_id
    ):
        with contextlib.suppress(Exception):
            from quill.taint import TaintState as _TaintState
            from quill.taint import would_close_trifecta
            current = _taint_state_for(session_id) if session_id else _TaintState()
            if would_close_trifecta(current, tool_name, tool_input):
                why = (
                    "would close the lethal trifecta this session "
                    "(untrusted input + private data + exfil vector)"
                )
                # Hardcode CRITICAL: a trifecta-close attempt is the worst-
                # case prompt-injection scenario by definition; the
                # underlying call's classification (often LOW for Edit/Write)
                # is irrelevant. Notify dispatcher fans on critical, so this
                # ensures OOB notification fires on trifecta closures.
                decision = HookDecision(
                    permission="deny",
                    reason=f"trifecta close · {why} · approve to proceed",
                    risk=Risk.CRITICAL,
                    audit_event_type="verdict.blocked",
                    what=decision.what,
                    why=why,
                    try_instead="",
                )

    if audit is not None:
        from quill import events as ev
        from quill.bridge import payload_hash as _ph
        from quill.taint import update_for_call

        with contextlib.suppress(Exception):
            # session.open - first time we've ever seen this session_id.
            if is_first_seen:
                audit.emit(
                    event_type=ev.SESSION_OPEN,
                    session_id=session_id,
                    agent_id=agent_id,
                    risk="low",
                    payload={
                        "parent_session_id": parent_session_id,
                        "transcript_path": transcript_path,
                        "cwd": cwd,
                        "trust_ladder": "spot_check",
                    },
                    force_fsync=True,
                )

            # agent.handoff.out / agent.handoff.in - sub-agent spawn.
            # Both sides of the edge are emitted from the receiver's hook
            # invocation (the sub-agent's first tool call); the parent has
            # already returned from Task() and is no longer running. The
            # out is recorded under the parent's session_id, the in under
            # the sub-agent's. The pair is matched by payload_hash;
            # `from_event_mac` ties the in to the specific out for
            # cryptographic edge integrity (see
            # docs/research/agent-trust-infra-2026-05.md S6.1).
            if is_new_sub:
                handoff_payload = {
                    "to_agent_id": session_id,
                    "from_session_id": parent_session_id,
                    "transcript_path": transcript_path,
                }
                _ph_value = _ph(handoff_payload)
                out_mac = audit.emit(
                    event_type=ev.AGENT_HANDOFF_OUT,
                    session_id=parent_session_id or session_id,
                    agent_id="claude-code",
                    risk="low",
                    payload={
                        "to_agent_id": session_id,
                        "contract": "task-subagent",
                        "payload_hash": _ph_value,
                        "trust_ladder_inherited": "spot_check",
                    },
                    force_fsync=True,
                )
                # Receiver-side: same payload_hash, ties to the out's mac.
                # Without this, `quill bridge show` reports every handoff
                # as orphan (out with no matching in). The fold-by-hash
                # logic in bridge.py:fold_handoffs depends on this event
                # being present with the same payload_hash.
                in_mac = audit.emit(
                    event_type=ev.AGENT_HANDOFF_IN,
                    session_id=session_id,
                    agent_id="claude-code-sub",
                    risk="low",
                    payload={
                        "from_agent_id": "claude-code",
                        "from_session_id": parent_session_id,
                        "from_event_mac": out_mac,
                        "payload_hash": _ph_value,
                        "accepted": True,
                        "ack_reason": None,
                    },
                    force_fsync=True,
                )

                # agent.cascade.affected - fan-out detection. One parent
                # spawning 3+ distinct sub-agents is the blast-radius
                # signature in Claude Code's spawn-and-fork model. Fires
                # exactly once per parent at the 3rd sub-agent so the
                # log gets one cascade event, not one per subsequent sub.
                with contextlib.suppress(Exception):
                    subagent_count = _record_handoff_receiver(
                        parent_session_id, session_id,
                    )
                    if subagent_count == 3:
                        audit.emit(
                            event_type=ev.AGENT_CASCADE_AFFECTED,
                            session_id=parent_session_id,
                            agent_id="claude-code",
                            risk="high",
                            payload={
                                "upstream_event_mac": out_mac,
                                "parent_session_id": parent_session_id,
                                "distinct_subagents": subagent_count,
                                "latest_in_mac": in_mac,
                                "latest_subagent_session_id": session_id,
                                "transcript_path": transcript_path,
                            },
                            force_fsync=True,
                        )

            audit.emit(
                event_type=ev.TOOL_ATTEMPTED,
                session_id=session_id,
                agent_id=agent_id,
                risk=decision.risk.value,
                payload={
                    "tool_name": tool_name,
                    "arg_keys": sorted(tool_input.keys()),
                    "arg_count": len(tool_input),
                    "args_preview": _redacted_input(tool_input),
                    "via": "claude-code-hook",
                    "parent_session_id": parent_session_id,
                    "cwd": cwd,
                },
            )
            # Issue a one-shot approval token for blocked / ask decisions
            # so the notification can include `quill approve <token>` -
            # the user's "go ahead" path. Tokens TTL ~10 min.
            issued_token = approval_token_used  # already set if we consumed
            if not issued_token and decision.permission in ("deny", "ask"):
                with contextlib.suppress(Exception):
                    from quill.approvals import ApprovalStore
                    store = ApprovalStore.load()
                    ap = store.issue(
                        tool_name, dict(tool_input),
                        reason=decision.why or decision.reason,
                    )
                    issued_token = ap.token

            audit.emit(
                event_type=decision.audit_event_type,
                session_id=session_id,
                agent_id=agent_id,
                risk=decision.risk.value,
                payload={
                    "tool_name": tool_name,
                    "by": "quill.adapters.claude_code",
                    "reason": decision.reason,
                    "permission": decision.permission,
                    "parent_session_id": parent_session_id,
                    "cwd": cwd,
                    "approve_token": issued_token,
                    "what": decision.what,
                    "why": decision.why,
                    "try_instead": decision.try_instead,
                },
                force_fsync=decision.risk in (Risk.HIGH, Risk.CRITICAL),
            )

            # Fire out-of-band notifications (macOS, email, Slack, webhook)
            # asynchronously - never blocks the hook's hot path.
            if decision.permission in ("deny", "ask") and issued_token:
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

            # session.taint.update - emit only when a flag flips.
            taint_state = _taint_state_for(session_id)
            _, flipped = update_for_call(taint_state, tool_name, tool_input)
            if flipped:
                _save_taint_state(session_id, taint_state)
                audit.emit(
                    event_type=ev.SESSION_TAINT_UPDATE,
                    session_id=session_id,
                    agent_id=agent_id,
                    risk="low",
                    payload={
                        "trifecta": taint_state.to_dict(),
                        "flipped": flipped,
                        "tool_name": tool_name,
                    },
                    force_fsync=taint_state.trifecta_closed,
                )

    # Autonomous learning: record this decision so the learner can
    # update its per-pattern stats and surface auto-tightening or
    # loosen-candidates. Skipped on plain-LOW allows where the
    # operator wasn't involved (those carry no signal). Failures here
    # must NEVER break the hook - the gate verdict is already final.
    # Use the ORIGINAL classifier reason so token-flipped approves
    # group with their preceding denies under the same pattern_id.
    if decision.permission != "allow" or approval_token_used:
        if os.environ.get("QUILL_LEARNING_STRICT"):
            from quill import learning
            from quill.learn import _normalize_block_reason
            head = _normalize_block_reason(original_decision_reason) or original_decision_reason
            pattern_id = f"{tool_name}:{head}"[:80]
            verdict_label = "approve" if approval_token_used else "deny"
            learning.post_decision_update(pattern_id, verdict_label)
        else:
            with contextlib.suppress(Exception):
                from quill import learning
                from quill.learn import _normalize_block_reason
                head = _normalize_block_reason(original_decision_reason) or original_decision_reason
                pattern_id = f"{tool_name}:{head}"[:80]
                verdict_label = "approve" if approval_token_used else "deny"
                learning.post_decision_update(pattern_id, verdict_label)

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision.permission,
            "permissionDecisionReason": decision.reason,
        },
    }


def self_test() -> tuple[bool, str]:
    """Verify the gate's classifier still does its job before processing
    any operator tool call. Two invariants:

      1. A known-CRITICAL payload (DROP TABLE) must DENY.
      2. A known-LOW payload (ls -la) must ALLOW.

    If either invariant fails, something has corrupted the classifier
    (config override, policy table drift, a runtime regression) and
    the hook MUST refuse to start. Failing closed is the safe move -
    a broken gate that fail-opens is worse than no gate.

    Returns (ok, reason). Cheap: two `decide()` calls, sub-millisecond.
    Cached in-process via the QUILL_SELF_TEST_DONE module global so
    subsequent calls are free. Skippable via QUILL_NO_SELF_TEST=1.

    Why this exists: the journal parser was silently broken for ~3
    weeks because nothing checked that the post-condition (real turn
    counts in the journal) was holding. Self-test on startup is the
    fix-loud-not-fix-silent pattern applied to the classifier.
    """
    if os.environ.get("QUILL_NO_SELF_TEST"):
        return True, "skipped via QUILL_NO_SELF_TEST"
    global _SELF_TEST_DONE  # noqa: PLW0603 - module-level cache by design
    if _SELF_TEST_DONE:
        return True, "cached"
    try:
        # Known-CRITICAL: DROP TABLE in raw form (no quoting, not a
        # commit-message). The quote-masked classifier still matches.
        critical_decision = decide("Bash", {"command": "DROP TABLE users"})
        if critical_decision.permission != "deny":
            return False, (
                f"self-test FAILED: known-critical 'DROP TABLE' returned "
                f"permission={critical_decision.permission} "
                f"(expected 'deny'). Classifier may be misconfigured."
            )
        # Known-LOW: bare ls. classify_command labels as read-only.
        low_decision = decide("Bash", {"command": "ls -la"})
        if low_decision.permission != "allow":
            return False, (
                f"self-test FAILED: known-LOW 'ls -la' returned "
                f"permission={low_decision.permission} (expected 'allow'). "
                f"Classifier may be over-broad."
            )
    except Exception as e:
        return False, f"self-test crashed: {type(e).__name__}: {e}"
    _SELF_TEST_DONE = True
    return True, "ok"


_SELF_TEST_DONE: bool = False


def main() -> int:
    """CLI entry: read stdin, write stdout, exit 0.

    Wired to `quill claude-hook` via the CLI module. Routes the audit
    log to <cwd>/.quill/audit.log.jsonl when the user has opted in to
    per-project mode. ALSO lazily ensures the watch dashboard daemon is
    alive so users never need to re-type `quill watch` after a reboot.

    Runs `self_test()` once per process. If the self-test fails, the
    hook refuses to render a verdict (fails closed). The operator sees
    the error on stderr and Claude Code surfaces it.
    """
    ok, reason = self_test()
    if not ok:
        sys.stderr.write(
            f"quill claude-hook: self-test failed: {reason}\n"
            f"  Refusing to start. The classifier may be misconfigured.\n"
            f"  Run `quill doctor` to investigate.\n"
            f"  Override (NOT RECOMMENDED): QUILL_NO_SELF_TEST=1\n"
        )
        # Fail closed: deny the call. Operator-friendly reason.
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"quill self-test failed: {reason}. "
                    "Run `quill doctor`."
                ),
            },
        }
        sys.stdout.write(json.dumps(response))
        sys.stdout.flush()
        return 1
    stdin_text = sys.stdin.read()
    # Peek at cwd from the payload so we can route the log per-project.
    cwd_for_routing = ""
    try:
        peek = json.loads(stdin_text or "{}")
        if isinstance(peek, dict):
            cwd_for_routing = str(peek.get("cwd") or "")
    except (json.JSONDecodeError, TypeError):
        pass
    log_path, _ = _resolve_project_paths(cwd_for_routing)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Lazily ensure the dashboard daemon is alive. Cheap (PID-file probe +
    # localhost bind-check) when it's already running, idempotent re-spawn
    # when it isn't. Skipped via QUILL_NO_AUTO_WATCH for power users / CI.
    if not os.environ.get("QUILL_NO_AUTO_WATCH"):
        with contextlib.suppress(Exception):
            from quill import watch as _watch  # local import to avoid cycles
            _watch.ensure_daemon(log_path, open_browser=False)
    try:
        with AuditLog(path=log_path, hmac_key=_default_load_hmac_key()) as audit:
            response = run_hook(stdin_text, audit=audit)
    except Exception as e:
        sys.stderr.write(f"quill claude-hook: internal error, allowing fail-open: {e}\n")
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
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
