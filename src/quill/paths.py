"""Resolve on-disk paths for Quill state.

A single QUILL_HOME env var scopes everything (config, audit log, key,
permissions, telemetry, sessions, watch pid). Individual per-file env
vars still override (QUILL_LOG, QUILL_KEY, etc.) for surgical control.
Default home is ~/.quill.
"""
from __future__ import annotations

import os
from pathlib import Path


def quill_home() -> Path:
    return Path(os.environ.get("QUILL_HOME", "~/.quill")).expanduser()


def default_path(filename: str, env_override: str | None = None) -> Path:
    """Resolve `<QUILL_HOME>/<filename>`, with optional per-file override.

    If env_override is set and that env var is non-empty, use it directly.
    Otherwise fall back to <QUILL_HOME>/<filename>.
    """
    if env_override:
        raw = os.environ.get(env_override, "").strip()
        if raw:
            return Path(raw).expanduser()
    return quill_home() / filename
