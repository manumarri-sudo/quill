"""Compile Quill's protected-path policy into an Endpoint Security ruleset.

The Seatbelt floor (quill.sandbox) is opt-in per session: you launch the
agent via `quill shell` and the kernel confines that process tree. The
ESF extension is the always-on counterpart - once installed it gates file
syscalls system-wide, so the gate-disable surface (the hook scripts, the
gate config, the key) is protected even for an agent that was NOT launched
under `quill shell`.

The ES client must never call back into Python on the deadline-critical
auth path (a slow response gets the client killed by the kernel), so policy
is COMPILED here, ahead of time, into a flat JSON ruleset the Swift
extension reads and matches natively. This mirrors the Santa / Sinter
pattern surfaced by the research: rules delivered out-of-band, a thin fast
verdict engine in the extension, never an LLM or an interpreter in the hot
path.

The protected paths are the SAME source of truth the Seatbelt floor uses
(quill.sandbox.default_protected), so the two enforcement layers never
drift apart.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from quill import sandbox

RULESET_VERSION = 1

# Endpoint Security AUTH events the extension subscribes to for file
# protection. (Exec gating is a documented future extension; the v1 ruleset
# focuses on the file/unlink/rename surface, which is what ESF is genuinely
# good at and what complements the command-text classifier.)
WATCHED_EVENTS = ("AUTH_OPEN", "AUTH_UNLINK", "AUTH_RENAME", "AUTH_TRUNCATE")


def compile_ruleset() -> dict:
    """Build the flat ESF ruleset dict from the shared protected-path policy."""
    files, trees = sandbox.default_protected()
    protected_files = sorted({c for p in files if (c := sandbox._canonical(p))})
    protected_prefixes = sorted({c for p in trees if (c := sandbox._canonical(p))})
    return {
        "version": RULESET_VERSION,
        "fail_closed": True,
        "protected_files": protected_files,
        "protected_prefixes": protected_prefixes,
        "watched_events": list(WATCHED_EVENTS),
    }


def ruleset_path() -> Path:
    from quill.paths import default_path

    return default_path("esf-rules.json", env_override="QUILL_ESF_RULES")


def write_ruleset() -> Path:
    """Compile and write the ruleset to `<QUILL_HOME>/esf-rules.json`."""
    p = ruleset_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(compile_ruleset(), indent=2) + "\n")
    return p


def is_path_protected(path: str, ruleset: dict) -> bool:
    """Reference implementation of the verdict the Swift PolicyEngine makes.

    Kept in Python so the test suite can assert PARITY between the two
    enforcement layers - if this and PolicyEngine.isProtected ever diverge,
    the ESF extension would protect a different set of paths than the
    Seatbelt floor, and the tests catch it.
    """
    try:
        c = os.path.realpath(path)
    except (OSError, ValueError):
        return False
    if c in set(ruleset.get("protected_files", [])):
        return True
    for pre in ruleset.get("protected_prefixes", []):
        if c == pre or c.startswith(pre.rstrip("/") + "/"):
            return True
    return False
