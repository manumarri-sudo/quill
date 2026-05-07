"""Deterministic policy primitives: SessionIntent, Scope, Risk levels.

No AI in the gate. Every check is O(1) hash lookup or compiled regex.
Pre-compile patterns at config load, then policy decisions are constant time
on the hot path.
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

from pydantic import BaseModel, ConfigDict, Field


class Risk(str, enum.Enum):
    """Risk classification for a tool action.

      LOW       logged + auto-allowed (reads, low-stake metadata)
      MEDIUM    logged + auto-allowed (writes inside scope)
      HIGH      logged + prompts human ACK
      CRITICAL  logged + prompts human ACK + type-to-confirm

    The default-classification table in policy.classify maps common dangerous
    actions (rm -rf, DROP TABLE, deploy:production, force-push, etc.) to
    CRITICAL out of the box.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Tools that should always be CRITICAL unless explicitly downgraded in config.
DEFAULT_CRITICAL_PATTERNS: Final[tuple[str, ...]] = (
    # filesystem destruction
    r"^fs\..*delete.*$",
    r"^fs\..*rm.*$",
    r"^filesystem\..*delete.*$",
    # version control destructive
    r"^git\.push.*--force.*$",
    r"^github\.delete.*$",
    r"^github\.create_pull_request.*$",  # public PR == action
    # database destructive
    r".*\.drop_table.*",
    r".*\.delete_database.*",
    r".*\.truncate.*",
    # deployment
    r".*deploy.*production.*",
    r".*deploy.*prod\b.*",
    # money
    r".*\.refund.*",
    r".*\.charge.*",
    r".*\.transfer.*",
    r".*\.payout.*",
    r"stripe\..*",
    # outbound communication
    r".*\.send_email.*",
    r".*\.send_message.*",
)

DEFAULT_HIGH_PATTERNS: Final[tuple[str, ...]] = (
    r"^fs\..*write.*$",
    r"^github\..*create.*$",
    r"^github\..*update.*$",
    r".*\.execute.*",
    r".*\.run.*",
    r".*\.create.*",
)


# ---------------------------------------------------------------------------
# Content-aware classification for shell commands.
#
# Quill's tool-name classifier is fast and right for namespaced MCP tools, but
# Claude Code's built-in `Bash` tool exposes one tool name to gate hundreds of
# commands. The risk depends on the command string, not the tool name.
#
# These patterns are conservative on purpose: when in doubt, escalate. The
# operator can downgrade in their per-tool policy override.
# ---------------------------------------------------------------------------

CRITICAL_COMMAND_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    # Filesystem destruction
    (r"\brm\s+(?:-[a-zA-Z]*[rRf][a-zA-Z]*\s+)+(?!\s*$)", "rm -rf"),
    (r"\bfind\b.*-delete\b", "find -delete"),
    (r"\bdd\s+if=", "dd low-level disk write"),
    (r"\bmkfs\.", "filesystem format"),
    (r":\(\)\s*\{.*:\|:&.*\}\s*;\s*:", "fork bomb"),
    # Version control destructive
    (r"\bgit\s+push\s+(?:--force|--force-with-lease|-f)\b", "git push --force"),
    (r"\bgit\s+reset\s+--hard\b", "git reset --hard"),
    (r"\bgit\s+clean\s+-[a-zA-Z]*[fdx]+", "git clean -fdx"),
    (r"\bgit\s+update-ref\s+-d\b", "git update-ref -d"),
    # Database destructive
    (r"\bdrop\s+(?:table|database|schema|index)\b", "DROP TABLE/DATABASE/SCHEMA"),
    (r"\btruncate\s+(?:table\s+)?\w+", "TRUNCATE TABLE"),
    (r"\bdelete\s+from\s+\w+(?!.*\bwhere\b)", "DELETE FROM without WHERE"),
    # Remote code execution
    (r"\bcurl\s+[^|]*\|\s*(?:sh|bash|zsh|fish)\b", "curl | sh"),
    (r"\bwget\s+[^|]*\|\s*(?:sh|bash|zsh|fish)\b", "wget | sh"),
    (r"\beval\b\s+[\"']?\$\(", "eval $(...)"),
    # Privilege & deploys
    (r"\bsudo\b", "sudo invocation"),
    (r"\bchmod\s+(?:[0-7]*7[0-7]?7|\+s)", "chmod 777 / setuid"),
    (r"\bnpm\s+publish\b", "npm publish"),
    (r"\byarn\s+publish\b", "yarn publish"),
    (r"\bvercel\s+(?:--prod\b|deploy\s+(?:\S+\s+)*--prod\b)", "vercel --prod"),
    (r"\bflyctl\s+deploy\b(?!.*--config\s+.*staging)", "flyctl deploy"),
    (r"\brailway\s+up\b.*--service\s+prod", "railway up --service prod"),
    (r"\bkubectl\s+(?:delete|apply\s+-f.*prod)", "kubectl delete / prod apply"),
    (r"\bdocker\s+(?:rmi|system\s+prune)", "docker rmi / system prune"),
    (r"\bterraform\s+(?:destroy|apply\s+-auto-approve)", "terraform destroy / auto-apply"),
    # Secret exfil shape
    (r"\bcat\b.*~/\.(?:ssh|aws|kube)/", "read ~/.ssh ~/.aws ~/.kube"),
    (r"\bcat\b\s+\.env\b", "read .env"),
)

HIGH_COMMAND_PATTERNS: Final[tuple[tuple[str, str], ...]] = (
    (r"\bgit\s+push\b", "git push"),
    (r"\bgit\s+commit\b", "git commit"),
    (r"\brm\s+(?!-[a-zA-Z]*[rRf])", "rm (single file)"),
    (r"\bsed\s+-i\b", "sed -i (in-place)"),
    (r"\bgh\s+pr\s+merge\b", "gh pr merge"),
    (r"\bgh\s+repo\s+(?:delete|edit)\b", "gh repo delete/edit"),
    (r"\bnpm\s+install\s+(?:-g|--global)\b", "npm install -g"),
    (r"\bnpm\s+install\b", "npm install (mutates lockfile)"),
    (r"\bvercel\s+deploy\b", "vercel deploy (preview)"),
    (r"\bdocker\s+(?:push|run\b.*--privileged)", "docker push / privileged run"),
    (r"\bcurl\s+-X\s+(?:POST|PUT|DELETE|PATCH)\b", "curl write request"),
    (r"\bopen\s+\S+://", "open URL/app"),
    (r"\bpip\s+install\s+(?:[^-]|-(?!h))", "pip install"),
    (r"\bbrew\s+install\b", "brew install"),
)

LOW_COMMAND_PATTERNS: Final[tuple[str, ...]] = (
    r"^\s*(?:ls|pwd|cat|head|tail|wc|file|stat|which|tree|du|df)\b",
    r"^\s*grep\b(?!.*-[a-zA-Z]*r)",  # grep yes, grep -r no
    r"^\s*find\s+\S+(?!.*-(?:delete|exec))",
    r"^\s*git\s+(?:status|log|diff|branch|show|remote|config\s+--list|rev-parse)\b",
    r"^\s*npm\s+(?:--version|list|ls|view|info|outdated|audit)\b",
    r"^\s*(?:node|python|python3|ruby|go)\s+--version\b",
    r"^\s*echo\b",
    r"^\s*date\b",
    r"^\s*env\s*$",
    r"^\s*printenv\b",
)


@dataclass(frozen=True, slots=True)
class CommandClassification:
    """Result of classifying a shell command."""

    risk: Risk
    reason: str


_CRITICAL_CMD_RE: Final[tuple[tuple[re.Pattern[str], str], ...]] = tuple(
    (re.compile(p, re.IGNORECASE), r) for p, r in CRITICAL_COMMAND_PATTERNS
)
_HIGH_CMD_RE: Final[tuple[tuple[re.Pattern[str], str], ...]] = tuple(
    (re.compile(p, re.IGNORECASE), r) for p, r in HIGH_COMMAND_PATTERNS
)
_LOW_CMD_RE: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(p, re.IGNORECASE) for p in LOW_COMMAND_PATTERNS
)


def classify_command(command: str) -> CommandClassification:
    """Classify a single shell command by content.

    For tools whose risk depends on the command string (Claude Code's `Bash`,
    a generic `shell.exec`, etc.). Conservative by design: when uncertain,
    return MEDIUM and let the caller decide.
    """
    cmd = (command or "").strip()
    if not cmd:
        return CommandClassification(Risk.LOW, "empty command")
    for rex, reason in _CRITICAL_CMD_RE:
        if rex.search(cmd):
            return CommandClassification(Risk.CRITICAL, reason)
    for rex, reason in _HIGH_CMD_RE:
        if rex.search(cmd):
            return CommandClassification(Risk.HIGH, reason)
    for rex in _LOW_CMD_RE:
        if rex.search(cmd):
            return CommandClassification(Risk.LOW, "read-only command")
    return CommandClassification(Risk.MEDIUM, "uncategorised shell command")


@dataclass(frozen=True, slots=True)
class _CompiledPolicy:
    critical: tuple[re.Pattern[str], ...]
    high: tuple[re.Pattern[str], ...]


def _compile_defaults() -> _CompiledPolicy:
    return _CompiledPolicy(
        critical=tuple(re.compile(p) for p in DEFAULT_CRITICAL_PATTERNS),
        high=tuple(re.compile(p) for p in DEFAULT_HIGH_PATTERNS),
    )


_DEFAULT_POLICY: Final[_CompiledPolicy] = _compile_defaults()


def classify(tool_name: str) -> Risk:
    """Return the default risk classification for a tool by name.

    Uses a pre-compiled regex table. O(n) in pattern count but the count is
    fixed and small; effectively constant per call. This is the hot path.
    """
    for pat in _DEFAULT_POLICY.critical:
        if pat.search(tool_name):
            return Risk.CRITICAL
    for pat in _DEFAULT_POLICY.high:
        if pat.search(tool_name):
            return Risk.HIGH
    if tool_name.startswith(("fs.read", "filesystem.read", "github.list", "github.get")):
        return Risk.LOW
    return Risk.MEDIUM


class Scope(BaseModel):
    """A grant of authority captured at session start.

    Format: 'namespace:action[:resource]'. Examples:
      payments:refund:customer:c_8e4f
      github:read:repo:user/public-repo
      fs:write:src/dashboard

    A tool call is in-scope if any granted Scope matches by prefix or by
    explicit resource match. Out-of-scope calls are blocked deterministically
    before the human is asked.
    """

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")
    namespace: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=128)
    resource: str | None = Field(default=None, max_length=512)

    def __str__(self) -> str:
        if self.resource:
            return f"{self.namespace}:{self.action}:{self.resource}"
        return f"{self.namespace}:{self.action}"

    @classmethod
    def parse(cls, raw: str) -> Scope:
        parts = raw.split(":", maxsplit=2)
        if len(parts) < 2:
            msg = f"invalid scope (need ns:action[:resource]): {raw!r}"
            raise ValueError(msg)
        ns, action = parts[0].strip(), parts[1].strip()
        resource = parts[2].strip() if len(parts) == 3 else None
        return cls(namespace=ns, action=action, resource=resource)

    def matches_tool(self, tool_name: str, *, args: dict[str, object]) -> bool:
        """Cheap deterministic check.

        True if the tool's namespace prefix matches this scope's namespace,
        AND (no resource constraint OR any resource segment appears in args).

        Resource matching is intentionally tolerant: a scope like
        `payments:refund:customer:c_8e4f` (resource='customer:c_8e4f') will
        match args containing `customer_id='c_8e4f'` because we split the
        resource on ':' and accept either-direction substring match per
        segment. This trades a small amount of strictness for usability.
        """
        tool_ns = tool_name.split(".", maxsplit=1)[0]
        if tool_ns != self.namespace:
            return False
        if self.resource is None:
            return True
        # split resource into segments and accept any segment match
        segments = [s for s in self.resource.split(":") if s]
        for v in args.values():
            if not isinstance(v, str):
                continue
            for seg in segments:
                if seg in v or v in seg:
                    return True
        return False


class SessionIntent(BaseModel):
    """The human's mandate, captured at session start.

    The intent string is what the human said when they kicked off the agent
    session. Scope is the explicit allowlist. Budget is the dollar ceiling
    that propagates across all sub-agents.
    """

    model_config = ConfigDict(strict=True, extra="forbid")
    session_id: str = Field(min_length=4, max_length=64)
    intent: str = Field(min_length=1, max_length=2000)
    scope: tuple[Scope, ...] = Field(default_factory=tuple)
    budget_usd: float | None = Field(default=None, ge=0)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    parent_session_id: str | None = None

    def covers(self, tool_name: str, args: dict[str, object]) -> bool:
        """True iff some granted Scope matches this tool call.

        An empty scope grants nothing — the operator must be explicit.
        """
        if not self.scope:
            return False
        return any(s.matches_tool(tool_name, args=args) for s in self.scope)

    def in_scope_reason(self, tool_name: str, args: dict[str, object]) -> str | None:
        """Plain-English explanation of why a tool was rejected, or None.

        Designed to be readable by a non-technical operator, not just an
        engineer reading a stack trace.
        """
        if self.covers(tool_name, args):
            return None
        target = next(
            (str(v) for v in args.values() if isinstance(v, (str, int, float))),
            "(no target)",
        )
        scopes = ", ".join(str(s) for s in self.scope) or "(empty)"
        return (
            f"the agent tried to call {tool_name!r}, which is not in your "
            f"session's allow-list. your scope was: {scopes}. this call's "
            f"target was: {target!r}."
        )
