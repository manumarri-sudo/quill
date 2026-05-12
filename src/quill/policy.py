"""Deterministic policy primitives: SessionIntent, Scope, Risk levels.

No AI in the gate. Every check is O(1) hash lookup or compiled regex.
Pre-compile patterns at config load, then policy decisions are constant time
on the hot path.
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from datetime import UTC, datetime
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
    # money - mutating verbs only. The old `stripe\..*` pattern blocked
    # read-only calls (list_charges, get_payment_intent) which made the
    # gate noisy without protecting anything; banking/drive/communication
    # APIs from the May-7 demo were missing entirely. Narrow + extend.
    r".*\.refund.*",
    r".*\.charge.*",
    r".*\.transfer.*",
    r".*\.payout.*",
    # stripe mutating verbs; reads (list_/get_/retrieve_) are NOT critical.
    # Use (?:_|$) instead of \b so the verb can be followed by _<noun>
    # (e.g. stripe.create_charge) or stand alone (e.g. stripe.refund).
    # \b doesn't fire between two word chars, so 'create' + '_charge'
    # would have failed to match without this.
    r"stripe\.(?:create|update|delete|cancel|capture|attach|detach|confirm|charge|refund|payout|transfer)(?:_|$)",
    # banking - send/move money or change auth
    r"banking\.(?:send_money|wire_transfer|update_password|reset_password|close_account|update_beneficiary)(?:_|$)",
    # cloud drive - destruction or share-out
    r"(?:drive|gdrive|onedrive|dropbox)\.(?:delete_file|delete_folder|empty_trash|share_with_anyone)(?:_|$)",
    # workspace destructive admin
    r"slack\.(?:invite_user_to_slack|kick_from_channel|delete_channel|delete_workspace)(?:_|$)",
    r"discord\.(?:ban_member|kick_member|delete_channel|delete_server)(?:_|$)",
    # travel - mutating reservations
    r"(?:travel|expedia|booking|airbnb)\.(?:reserve|book|cancel|charge)(?:_|$)",
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

# (regex_pattern, reason, suggested_fix)
# The suggested_fix is shown to the user when this pattern blocks a command,
# so the gate is constructive rather than just punitive. Keep suggestions
# concrete - a paste-able command, not advice.
CRITICAL_COMMAND_PATTERNS: Final[tuple[tuple[str, str, str], ...]] = (
    # Filesystem destruction
    (r"\brm\s+(?:-[a-zA-Z]*[rRf][a-zA-Z]*\s+)+(?!\s*$)", "rm -rf",
     "Move to a quarantine dir instead so you can recover: "
     "`mv <target> /tmp/quarantine_$(date +%s)`"),
    (r"\bfind\b.*-delete\b", "find -delete",
     "Run without -delete first to preview matches: replace `-delete` with `-print`"),
    (r"\bdd\s+if=", "dd low-level disk write",
     "Verify the of= target with `lsblk` first; one wrong character corrupts the wrong disk"),
    (r"\bmkfs\.", "filesystem format",
     "Confirm the device path with `lsblk -f` first - formatting the wrong drive is unrecoverable"),
    (r":\(\)\s*\{.*:\|:&.*\}\s*;\s*:", "fork bomb",
     "This is a fork bomb pattern. Refuse."),
    # Version control destructive
    (r"\bgit\s+push\s+(?:--force|--force-with-lease|-f)\b", "git push --force",
     "Use `git push --force-with-lease` to avoid clobbering a teammate's commits - "
     "or rebase first: `git fetch && git rebase origin/<branch>`"),
    (r"\bgit\s+reset\s+--hard\b", "git reset --hard",
     "Stash uncommitted work first: `git stash push -u -m 'pre-reset'`, then reset"),
    (r"\bgit\s+clean\s+-[a-zA-Z]*[fdx]+", "git clean -fdx",
     "Preview first with `git clean -ndx` (dry run); commit anything you want to keep"),
    (r"\bgit\s+update-ref\s+-d\b", "git update-ref -d",
     "Tag the commit before deleting the ref: `git tag backup-$(date +%s) <ref>`"),
    # Database destructive
    (r"\bdrop\s+(?:table|database|schema|index)\b", "DROP TABLE/DATABASE/SCHEMA",
     "Back up first: `pg_dump -t <table> > /tmp/backup_$(date +%s).sql`. "
     "Then run the DROP in a transaction so you can `ROLLBACK` if needed."),
    (r"\btruncate\s+(?:table\s+)?\w+", "TRUNCATE TABLE",
     "TRUNCATE is unrecoverable. `DELETE FROM <table>` (in a transaction) "
     "lets you ROLLBACK; or back up with `pg_dump -t <table>` first"),
    (r"\bdelete\s+from\s+\w+(?!.*\bwhere\b)", "DELETE FROM without WHERE",
     "Add a WHERE clause. To delete all rows intentionally, use TRUNCATE explicitly "
     "(in a transaction) so the intent is documented"),
    # Remote code execution
    (r"\bcurl\s+[^|]*\|\s*(?:sh|bash|zsh|fish)\b", "curl | sh",
     "Download first, read the script, *then* run: "
     "`curl -fsSL <url> -o /tmp/install.sh && cat /tmp/install.sh && bash /tmp/install.sh`"),
    (r"\bwget\s+[^|]*\|\s*(?:sh|bash|zsh|fish)\b", "wget | sh",
     "Download first, read it, then run: `wget <url> -O /tmp/install.sh && cat /tmp/install.sh`"),
    (r"\beval\b\s+[\"']?\$\(", "eval $(...)",
     "Capture the command first and inspect it: `cmd=$(...)` then `echo \"$cmd\"`"),
    # Privilege & deploys
    (r"(?:^|[;&|`(\s])sudo(?=\s)", "sudo invocation",
     "Confirm you actually need root for this. Many tools (npm, pip, brew) "
     "should never be run with sudo"),
    (r"\bchmod\s+(?:[0-7]*7[0-7]?7|\+s)", "chmod 777 / setuid",
     "World-writable or setuid is almost never what you want. Try `chmod 644` "
     "for files / `chmod 755` for executables"),
    (r"\bnpm\s+publish\b", "npm publish",
     "Dry-run first to see exactly what gets uploaded: `npm publish --dry-run`. "
     "Verify version, files, and that no secrets are in the tarball"),
    (r"\byarn\s+publish\b", "yarn publish",
     "Dry-run first: `yarn pack` produces the tarball without publishing. Inspect it"),
    (r"\bvercel\s+(?:--prod\b|deploy\s+(?:\S+\s+)*--prod\b)", "vercel --prod",
     "Preview-deploy first: `vercel deploy` (without --prod) - verify the preview "
     "URL, then promote: `vercel promote <preview-url>`"),
    (r"\bflyctl\s+deploy\b(?!.*--config\s+.*staging)", "flyctl deploy",
     "Deploy to staging first: `flyctl deploy --config fly.staging.toml` - verify, "
     "then deploy prod"),
    (r"\brailway\s+up\b.*--service\s+prod", "railway up --service prod",
     "Use a staging service first; railway has no built-in rollback once a "
     "prod deploy goes out"),
    (r"\bkubectl\s+(?:delete|apply\s+-f.*prod)", "kubectl delete / prod apply",
     "Dry-run first: `kubectl ... --dry-run=server -o yaml` shows what would change"),
    (r"\bdocker\s+(?:rmi|system\s+prune)", "docker rmi / system prune",
     "List what would be removed first: `docker images` / `docker system df`"),
    (r"\bterraform\s+(?:destroy|apply\s+-auto-approve)", "terraform destroy / auto-apply",
     "Always plan first: `terraform plan -out=plan.tfplan`, review, then "
     "`terraform apply plan.tfplan`. Never auto-approve in prod"),
    # Secret exfil shape
    (r"\bcat\b.*~/\.(?:ssh|aws|kube)/", "read ~/.ssh ~/.aws ~/.kube",
     "If you need a credential value, read the specific file you mean and "
     "redact for display: `head -c 20 <file>; echo '...'`"),
    (r"\bcat\b\s+\.env\b", "read .env",
     "Show only keys, not values: `grep -oE '^[A-Z_]+=' .env`"),
)

HIGH_COMMAND_PATTERNS: Final[tuple[tuple[str, str, str], ...]] = (
    (r"\bgit\s+push\b", "git push",
     "Verify branch + diff first: `git status && git log @{u}..HEAD --oneline`"),
    (r"\bgit\s+commit\b", "git commit",
     "Show staged hunks first: `git diff --staged`"),
    (r"\brm\s+(?!-[a-zA-Z]*[rRf])", "rm (single file)",
     "Move to /tmp first: `mv <file> /tmp/` lets you recover for the session"),
    (r"\bsed\s+-i\b", "sed -i (in-place)",
     "Drop `-i` and pipe through `diff` first to preview the change"),
    (r"\bgh\s+pr\s+merge\b", "gh pr merge",
     "Verify checks: `gh pr checks` before merging"),
    (r"\bgh\s+repo\s+(?:delete|edit)\b", "gh repo delete/edit",
     "Repo-level changes are visible to collaborators - confirm with the team first"),
    (r"\bnpm\s+install\s+(?:-g|--global)\b", "npm install -g",
     "Prefer `npx <pkg>` for one-off use, or project-local install. "
     "Globals can run install scripts at root"),
    (r"\bnpm\s+install\b", "npm install (mutates lockfile)",
     "If your lockfile should be authoritative, prefer `npm ci`"),
    (r"\bvercel\s+deploy\b", "vercel deploy (preview)",
     "Preview is cheap; promote with `vercel promote <url>` after verifying"),
    (r"\bdocker\s+(?:push|run\b.*--privileged)", "docker push / privileged run",
     "Drop privileges if possible, use `--cap-add` selectively"),
    (r"\bcurl\s+-X\s+(?:POST|PUT|DELETE|PATCH)\b", "curl write request",
     "Confirm URL + body. Use the API's `--dry-run` if available"),
    (r"\bopen\s+\S+://", "open URL/app",
     "Verify the URL first if it came from an untrusted source"),
    (r"\bpip\s+install\s+(?:[^-]|-(?!h))", "pip install",
     "Use a venv: `python -m venv .venv && .venv/bin/pip install ...`"),
    (r"\bbrew\s+install\b", "brew install",
     "Confirm the formula source: `brew info <pkg>` shows the homepage"),
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
    """Result of classifying a shell command.

    `suggestion` is a paste-able safer alternative shown to the user when
    the gate blocks. Empty string when no suggestion applies (LOW/MEDIUM).
    """

    risk: Risk
    reason: str
    suggestion: str = ""


_CRITICAL_CMD_RE: Final[tuple[tuple[re.Pattern[str], str, str], ...]] = tuple(
    (re.compile(p, re.IGNORECASE), r, s) for p, r, s in CRITICAL_COMMAND_PATTERNS
)
_HIGH_CMD_RE: Final[tuple[tuple[re.Pattern[str], str, str], ...]] = tuple(
    (re.compile(p, re.IGNORECASE), r, s) for p, r, s in HIGH_COMMAND_PATTERNS
)
_LOW_CMD_RE: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(p, re.IGNORECASE) for p in LOW_COMMAND_PATTERNS
)


def _user_bash_allowlist() -> tuple[re.Pattern[str], ...]:
    """User-config-driven allowlist for Bash command patterns.

    Read from `[bash] allowlist = [...]` in ~/.quill/config.toml. Each entry is
    a regex (case-insensitive). Patterns matching here short-circuit the
    classifier to LOW - useful for legitimate maintenance commands the
    operator runs often (rm KILL files, pkill of own daemons, kill -<sig> of
    own PIDs, force-pushes to a personal branch, etc.).

    Cached on first call; restart the agent / re-run the hook process to
    pick up edits.
    """
    global _USER_BASH_ALLOWLIST  # noqa: PLW0603 - module-level cache by design
    cached = globals().get("_USER_BASH_ALLOWLIST")
    if cached is not None:
        return cached
    patterns: list[re.Pattern[str]] = []
    try:
        import tomllib  # py311+

        from quill.config import default_config_path
        p = default_config_path()
        if p.exists():
            with p.open("rb") as f:
                raw = tomllib.load(f)
            bash_section = raw.get("bash") or {}
            for entry in (bash_section.get("allowlist") or []):
                if isinstance(entry, str) and entry.strip():
                    try:
                        patterns.append(re.compile(entry, re.IGNORECASE))
                    except re.error:
                        continue
    except Exception:
        pass
    _USER_BASH_ALLOWLIST = tuple(patterns)
    return _USER_BASH_ALLOWLIST


_USER_BASH_ALLOWLIST: tuple[re.Pattern[str], ...] | None = None


# ---------------------------------------------------------------------------
# Quote stripping - the pre-2026 classifier matched `TRUNCATE TABLE` and
# `sudo ` inside commit messages and echo literals. The fix: blank out the
# *contents* of matched quote pairs before running the dangerous-pattern
# regexes, but keep the surrounding command structure (so `git commit -m '…'`
# is still recognisable as a git command). Single, double, and `$'…'`
# ANSI-C quoted strings are stripped; backticks and `$(…)` are NOT (those
# ARE shell-executed code and must remain matchable).
# ---------------------------------------------------------------------------

_QUOTE_RE = re.compile(
    r"""
    (?P<sq>'(?:\\.|[^'\\])*')          # single-quoted: literal except \'
    | (?P<dq>"(?:\\.|[^"\\])*")        # double-quoted: backslash escapes
    | (?P<ansic>\$'(?:\\.|[^'\\])*')   # $'...'
    """,
    re.VERBOSE,
)


def _mask_quoted(cmd: str) -> str:
    """Replace contents of single/double/$'…' quoted regions with spaces.

    Returns a string of identical length so column offsets in regex error
    reports still line up with the source. Quotes themselves are kept so
    `git commit -m 'msg'` still parses as a git invocation.
    """
    def _blank(m: re.Match[str]) -> str:
        s = m.group(0)
        # Keep the quote chars at the ends, blank the middle.
        if len(s) <= 2:
            return s
        return s[0] + (" " * (len(s) - 2)) + s[-1]

    return _QUOTE_RE.sub(_blank, cmd)


# ---------------------------------------------------------------------------
# Claude Code bashPermissions subcommand-bypass gate (CVE-2025-59536,
# CVE-2026-21852, disclosed Apr 2026). The IDE's PreToolUse permission
# analyser capped per-subcommand inspection at 50; commands with >50
# subcommands chained via `&&`, `||`, `;`, `|` skipped *all* deny rules.
# Mitigation: any command whose chain depth exceeds this threshold is
# forced to CRITICAL regardless of content. We classify at a lower
# threshold (>=20) because there is no legitimate agent workflow that
# needs 20+ chained subcommands - anything beyond that is either a
# bypass attempt or a script that should live in a file.
# ---------------------------------------------------------------------------

SUBCOMMAND_CHAIN_LIMIT: Final[int] = 20

_CHAIN_RE = re.compile(r"(?:&&|\|\||;|(?<!\|)\|(?!\|))")


def _count_chain_segments(cmd: str) -> int:
    """Count subcommand segments split by `&&`, `||`, `;`, `|`.

    Operates on the quote-masked form so chaining operators *inside*
    quoted strings don't inflate the count (e.g. `echo 'a; b; c'`).
    """
    masked = _mask_quoted(cmd)
    parts = _CHAIN_RE.split(masked)
    return sum(1 for p in parts if p.strip())


def classify_command(command: str) -> CommandClassification:
    """Classify a single shell command by content.

    For tools whose risk depends on the command string (Claude Code's `Bash`,
    a generic `shell.exec`, etc.). Conservative by design: when uncertain,
    return MEDIUM and let the caller decide. CRITICAL/HIGH classifications
    carry a paste-able safer-alternative `suggestion`.

    Security gates (ordered):
      1. User allowlist (`[bash] allowlist`) short-circuits to LOW.
      2. Subcommand-chain bypass guard: commands with >SUBCOMMAND_CHAIN_LIMIT
         segments are CRITICAL regardless of content (CVE-2025-59536 class).
      3. Pattern matching runs on the *quote-masked* form so SQL/destructive
         keywords inside commit messages or echo literals don't false-fire.
      4. The original raw form is used for chain-counting and for the
         allowlist match (operators may want to allowlist quoted forms).
    """
    cmd = (command or "").strip()
    if not cmd:
        return CommandClassification(Risk.LOW, "empty command")
    for rex in _user_bash_allowlist():
        if rex.search(cmd):
            return CommandClassification(Risk.LOW, "operator allowlist match")

    # Gate 1: subcommand-chain bypass (Claude Code CVE-2025-59536 / 21852).
    n_segments = _count_chain_segments(cmd)
    if n_segments > SUBCOMMAND_CHAIN_LIMIT:
        return CommandClassification(
            Risk.CRITICAL,
            f"subcommand chain ({n_segments} segments) exceeds gate limit "
            f"({SUBCOMMAND_CHAIN_LIMIT}) - known bypass for per-subcommand "
            "permission analysers",
            "split into separate calls; long chains routinely bypass "
            "permission gates (CVE-2025-59536). Put the script in a "
            "file and run it: `bash /tmp/work.sh`",
        )

    # Gate 2: pattern matching on the quote-masked form. Quoted SQL in a
    # commit message no longer trips DROP/TRUNCATE/DELETE patterns.
    masked = _mask_quoted(cmd)
    for rex, reason, suggestion in _CRITICAL_CMD_RE:
        if rex.search(masked):
            return CommandClassification(Risk.CRITICAL, reason, suggestion)
    for rex, reason, suggestion in _HIGH_CMD_RE:
        if rex.search(masked):
            return CommandClassification(Risk.HIGH, reason, suggestion)
    for rex in _LOW_CMD_RE:
        if rex.search(masked):
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

        True iff:
            1. tool's namespace == this scope's namespace, AND
            2. tool's action portion is covered by this scope's action
               (`*` / `any` matches anything; otherwise prefix-match), AND
            3. resource matches if a resource constraint exists.

        Action match: the tool name's portion AFTER the namespace prefix is
        the tool's action. `filesystem.read_file` → action=`read_file`. A
        scope action of `read` matches `read_file` and `read_dir` (prefix);
        `write` does NOT match `read_file`. Use `*` or `any` to grant the
        whole namespace.

        Resource matching: a scope like `payments:refund:customer:c_8e4f`
        (resource='customer:c_8e4f') matches args containing
        `customer_id='c_8e4f'` because we split resource on ':' and accept
        either-direction substring match per segment. Tolerant by design.
        """
        parts = tool_name.split(".", maxsplit=1)
        tool_ns = parts[0]
        tool_action = parts[1] if len(parts) == 2 else ""

        if tool_ns != self.namespace:
            return False

        scope_action = self.action.strip()
        if scope_action not in ("*", "any"):
            # Empty tool_action (no namespace dot in the tool name) only
            # matches a wildcard scope action - never a specific one.
            if not tool_action:
                return False
            # Prefix match: scope `read` covers `read_file`, `read_dir`.
            # Equality short-circuit for the common case (`refund` == `refund`).
            if not (
                tool_action == scope_action
                or tool_action.startswith(scope_action + "_")
                or tool_action.startswith(scope_action + ".")
            ):
                return False

        if self.resource is None:
            return True
        # Resource segments must be at least 3 chars to be considered a
        # meaningful identifier. Below that, any string containing a single
        # letter from the segment matched (e.g. resource `c_8e4f` matched
        # any arg containing 'c'). Bi-directional substring matching was
        # also too permissive: only `seg in v` is sound - `v in seg` lets
        # an attacker pass an arg that is a prefix of the resource and
        # be granted authority over the full resource.
        segments = [s for s in self.resource.split(":") if len(s) >= 3]
        if not segments:
            return False
        for v in args.values():
            if not isinstance(v, str) or len(v) < 3:
                continue
            for seg in segments:
                if seg in v:
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
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    parent_session_id: str | None = None

    def covers(self, tool_name: str, args: dict[str, object]) -> bool:
        """True iff some granted Scope matches this tool call.

        An empty scope grants nothing - the operator must be explicit.
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
