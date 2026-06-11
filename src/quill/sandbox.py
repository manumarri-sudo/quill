"""Seatbelt sandbox floor for Quill (macOS kernel-layer enforcement).

Quill's PreToolUse hook is an application-layer gate: it sees the tool
calls an agent routes through the framework and classifies their text.
That leaves three holes it cannot close by construction - the
write-then-run loophole (destructive logic inside an interpreter Quill
already allowed to start), raw network egress (a Python `requests.post`
that never touches `curl`), and anything that routes around the hook.

This module generates a Seatbelt profile (SBPL) that closes those at the
kernel. macOS enforces the profile in the TrustedBSD MAC layer on the
actual syscall, and a child process inherits its parent's sandbox, so
launching the agent under a profile confines every interpreter and
subprocess it spawns.

Grounded in macOS sandbox internals, verified on Darwin 25:
  - SBPL is LAST-MATCH-WINS: the most-specific deny must come last to win.
  - Children INHERIT the sandbox - the whole reason launch-level confinement
    works.
  - Matching is on CANONICAL paths: `/tmp` is a symlink to `/private/tmp`
    and `~` must be expanded, or a deny silently matches nothing. Every
    path here is run through `os.path.realpath`.
  - Base is `(allow default)` plus targeted denies, not `(deny default)`,
    which would need hundreds of mach/dyld re-grants to keep a dev
    toolchain alive.

Two postures:
  - floor (default): allow-default plus a deny on the gate's own config and
    the shell/persistence surface. Closes self-tamper and gate-disable at
    the kernel without breaking dev tooling.
  - seal (--seal): also confine ALL writes to an allowlist and seal network
    egress to localhost. High assurance, may break tools that write outside
    the allowlist. For running untrusted work.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

# Shell rc / login files an agent could write to persist env (e.g. QUILL_*
# escape-hatch vars) into the next session. Denied as exact literals.
_SHELL_RC = (
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".bashrc",
    ".bash_profile",
    ".profile",
)

# Gate-disable surface: the files an agent would rewrite to neuter Quill or
# the host harness from the inside. Kept self-contained (not imported from the
# adapter) so this module ships independently; it intentionally mirrors the
# adapter's _GATE_CONFIG_SUFFIXES.
_PROTECTED_FILES = (
    "~/.claude/settings.json",
    "~/.claude/settings.local.json",
    "~/.cursor/hooks.json",
    "~/.quill/config.toml",
    "~/.quill/overrides.toml",
    "~/.quill/key",
    "~/.quill/pause.json",  # the gate-off state; agent must not flip it directly
)
_PROTECTED_TREES = (
    "~/.claude/hooks",  # the firewall / trust-ladder hook scripts
    "~/Library/LaunchAgents",  # login-item persistence
)

# Always writable, even under --seal: the gate and host harness must keep
# functioning. Quill's hook writes its audit log + state under ~/.quill;
# Claude Code writes session state under ~/.claude. The protected denies
# above are layered AFTER these and win by last-match-wins.
_ALWAYS_WRITABLE = (
    "~/.quill",
    "~/.claude",
)

# Common tool caches a dev toolchain writes outside the project. Included
# in the --seal allowlist so `pip`, `npm`, `cargo`, etc. keep working.
_DEV_CACHES = (
    "~/Library/Caches",
    "~/.cache",
    "~/.npm",
    "~/.cargo",
    "~/.rustup",
    "~/.gradle",
    "~/.m2",
    "~/.pyenv",
    "~/.config",
)


def _canonical(raw: str) -> str | None:
    """Resolve `raw` to a canonical absolute path, or None if unresolvable.

    Expands `~`, resolves symlinks (the `/tmp` -> `/private/tmp` trap).
    Best-effort: any error returns None so a bad entry is skipped rather
    than crashing profile generation.
    """
    if not raw or not isinstance(raw, str):
        return None
    try:
        return os.path.realpath(Path(raw).expanduser())
    except (OSError, ValueError):
        return None


def _sbpl_str(path: str) -> str:
    """Quote a path as an SBPL string literal (escape backslash + quote)."""
    return path.replace("\\", "\\\\").replace('"', '\\"')


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


@dataclass(slots=True)
class SandboxSpec:
    """A resolved confinement request, ready to render to SBPL."""

    writable: list[str] = field(default_factory=list)
    protected_files: list[str] = field(default_factory=list)
    protected_trees: list[str] = field(default_factory=list)
    confine_writes: bool = False  # True under --seal
    network: str = "all"  # "all" | "localhost"


def default_protected() -> tuple[list[str], list[str]]:
    """(files, trees) on the gate-disable / persistence surface.

    Files = the gate-config surface plus the shell rc / login files an agent
    could write to persist a QUILL_* escape-hatch env var into the next
    session. Trees = the hook scripts and the login-item directory.
    """
    files = list(_PROTECTED_FILES) + [f"~/{rc}" for rc in _SHELL_RC]
    return files, list(_PROTECTED_TREES)


def default_writable(cwd: str | None = None) -> list[str]:
    """Writable allowlist for --seal: trust paths, cwd, gate state, caches, temp."""
    paths: list[str] = []
    try:
        from quill.config import load_config

        cfg = load_config()
        paths += list(getattr(cfg.trust, "paths", []) or [])
    except Exception:
        pass
    if cwd:
        paths.append(cwd)
    paths += list(_ALWAYS_WRITABLE)
    paths += list(_DEV_CACHES)
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        paths.append(tmpdir)
    paths += ["/private/tmp", "/private/var/folders"]
    return paths


def build_spec(
    *,
    cwd: str | None = None,
    confine_writes: bool = False,
    seal_network: bool = False,
) -> SandboxSpec:
    """Assemble a SandboxSpec from config + defaults for the given cwd."""
    files, trees = default_protected()
    return SandboxSpec(
        writable=default_writable(cwd) if confine_writes else [],
        protected_files=files,
        protected_trees=trees,
        confine_writes=confine_writes,
        network="localhost" if seal_network else "all",
    )


def build_profile(spec: SandboxSpec) -> str:
    """Render a SandboxSpec to an SBPL profile string."""
    out: list[str] = [
        "(version 1)",
        ";; Quill Seatbelt floor - generated by `quill`, do not hand-edit.",
        ";; SBPL is last-match-wins; the protected denies below come LAST.",
        "(allow default)",
        "",
    ]

    if spec.confine_writes:
        writable = _dedupe([c for p in spec.writable if (c := _canonical(p))])
        out.append(";; --seal: deny all writes, then re-allow the allowlist")
        out.append("(deny file-write*)")
        allow = ["(allow file-write*"]
        for p in writable:
            allow.append(f'  (subpath "{_sbpl_str(p)}")')
        allow += [
            '  (literal "/dev/null")',
            '  (literal "/dev/stdout")',
            '  (literal "/dev/stderr")',
            '  (literal "/dev/dtracehelper")',
            '  (subpath "/dev/fd"))',
        ]
        out.append("\n".join(allow))
        out.append("")

    files = _dedupe([c for p in spec.protected_files if (c := _canonical(p))])
    trees = _dedupe([c for p in spec.protected_trees if (c := _canonical(p))])
    if files or trees:
        out.append(";; gate-disable + persistence surface: most-specific deny, LAST")
        deny = ["(deny file-write*"]
        for p in trees:
            deny.append(f'  (subpath "{_sbpl_str(p)}")')
        for p in files:
            deny.append(f'  (literal "{_sbpl_str(p)}")')
        deny[-1] = deny[-1] + ")"
        out.append("\n".join(deny))
        out.append("")

    if spec.network == "localhost":
        out += [
            ";; --seal: egress sealed to loopback only (blocks exfil).",
            ";; Seatbelt's network filter accepts only `*` or `localhost` as",
            ";; the host, not a numeric IP - `localhost` covers both loopback",
            ";; families at enforcement time.",
            "(deny network*)",
            '(allow network-outbound (remote ip "localhost:*"))',
            '(allow network-inbound (local ip "localhost:*"))',
            '(allow network-bind (local ip "localhost:*"))',
            "(allow network-outbound (remote unix-socket))",
            "",
        ]

    return "\n".join(out).rstrip() + "\n"


def profile_path() -> Path:
    """Where the generated profile is written (`<QUILL_HOME>/quill.sb`)."""
    from quill.paths import default_path

    return default_path("quill.sb", env_override="QUILL_SANDBOX_PROFILE")


def write_profile(spec: SandboxSpec) -> Path:
    """Render `spec` and write it to `profile_path()`. Returns the path."""
    p = profile_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(build_profile(spec))
    return p


def sandbox_exec_available() -> bool:
    """True if `sandbox-exec` is on PATH (macOS only; deprecated but present)."""
    return shutil.which("sandbox-exec") is not None


def launch_argv(profile: Path, command: list[str]) -> list[str]:
    """Build the `sandbox-exec -f <profile> -- <command>` argv."""
    return ["sandbox-exec", "-f", str(profile), "--", *command]
