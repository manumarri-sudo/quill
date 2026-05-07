"""Session-journal writer.

Reads a Claude Code (or compatible) transcript JSONL and writes a
markdown session log into the user's AgentOS vault under
`ClaudeCode/Sessions/`.

Designed to run as a Claude Code SessionEnd hook so journaling is
zero-effort: every session ends with a journal entry, no human prompt.

Privacy: only writes to ClaudeCode/Sessions/ within the configured vault
root. Never writes to other vault subtrees (Lattice, AgentBrain, etc.).
Tool arguments are summarized at the namespace level only — never logs
full file paths from edits, never logs shell command bodies, never logs
intent text verbatim. The journal is a record of *what was attempted
and how it was gated*, not what was edited.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_VAULT_SESSIONS = Path(
    os.environ.get(
        "QUILL_VAULT_SESSIONS",
        "~/agentbrain/AgentOS-Vault/ClaudeCode/Sessions",
    ),
).expanduser()

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(s: str, max_words: int = 5) -> str:
    """Turn a free-text headline into a 3-5 word kebab slug."""
    words = _SLUG_RE.sub(" ", s.lower()).split()
    return "-".join(words[:max_words]) if words else "session"


@dataclass(slots=True)
class JournalSummary:
    """The data we extracted from the transcript, ready to render."""

    started_at: str
    ended_at: str
    n_user_turns: int = 0
    n_assistant_turns: int = 0
    tool_use_counts: Counter[str] = field(default_factory=Counter)
    files_touched: set[str] = field(default_factory=set)
    bash_commands_seen: int = 0
    headline: str = ""
    cwd: str | None = None


def _safe_str(x: Any) -> str:
    return x if isinstance(x, str) else str(x)


def summarize_transcript(events: Iterable[Mapping[str, Any]]) -> JournalSummary:
    """Reduce a transcript JSONL to the privacy-safe summary we render.

    The transcript shape isn't standardized across Claude Code versions;
    we accept anything that looks like a list of {role, content} objects
    and a list of tool_use entries. Best-effort: missing fields are fine.
    """
    s = JournalSummary(started_at="", ended_at="")
    first_ts = last_ts = None
    for evt in events:
        ts = evt.get("ts") or evt.get("timestamp")
        if isinstance(ts, str):
            first_ts = first_ts or ts
            last_ts = ts

        role = evt.get("role")
        if role == "user":
            s.n_user_turns += 1
            content = evt.get("content")
            if isinstance(content, str) and not s.headline and content.strip():
                # First user turn becomes the headline (truncated).
                s.headline = content.strip()[:80]
        elif role == "assistant":
            s.n_assistant_turns += 1

        # Tool-use entries can live inside content blocks or top-level.
        content = evt.get("content")
        blocks = content if isinstance(content, list) else []
        for b in blocks:
            if not isinstance(b, Mapping):
                continue
            if b.get("type") == "tool_use":
                tname = _safe_str(b.get("name", ""))
                if tname:
                    s.tool_use_counts[tname] += 1
                # Privacy: store namespace of the touched path, not full path.
                inp = b.get("input")
                if isinstance(inp, Mapping):
                    p = inp.get("file_path") or inp.get("path") or inp.get("notebook_path")
                    if isinstance(p, str):
                        # only the top-level dir, not the full path
                        head = Path(p).parts
                        if len(head) >= 2:
                            s.files_touched.add(f"{head[0]}/{head[1]}")
                        else:
                            s.files_touched.add(head[0] if head else "(root)")
                    if tname == "Bash":
                        s.bash_commands_seen += 1

        if evt.get("cwd") and not s.cwd:
            s.cwd = _safe_str(evt["cwd"])

    s.started_at = first_ts or datetime.now(timezone.utc).isoformat()
    s.ended_at = last_ts or datetime.now(timezone.utc).isoformat()
    return s


def render_markdown(summary: JournalSummary) -> str:
    """Render the JournalSummary as the markdown the skill writes."""
    date = (summary.ended_at or "")[:10]
    headline = summary.headline or "untitled session"
    slug = slugify(headline)
    name = f"Session journal {date} · {headline}"

    top_tools = ", ".join(f"{n}×{c}" for n, c in summary.tool_use_counts.most_common(8)) or "none"
    files = ", ".join(sorted(summary.files_touched)[:10]) or "none"

    # Yes — two YAML frontmatter blocks. The first carries the
    # basic-memory permalink; the second carries human-friendly metadata
    # the user keeps elsewhere in the vault. Mirrors existing convention.
    body = f"""---
permalink: agentos-vault/claude-code/sessions/{date}-{slug}
---

---
name: {name}
description: Auto-generated session journal. {summary.n_user_turns} user turns, {summary.n_assistant_turns} assistant turns. Top tools used: {top_tools}.
type: session
date: {date}
auto_generated: true
---

# Session journal — {date} · {headline}

> Written automatically by `quill journal save` at session end.
> Privacy contract: namespaces and counts only — no shell commands,
> no full file paths, no intent text verbatim.

## Counts

- user turns: {summary.n_user_turns}
- assistant turns: {summary.n_assistant_turns}
- shell commands attempted: {summary.bash_commands_seen}
- top-level file areas touched: {files}
- session start: {summary.started_at}
- session end:   {summary.ended_at}

## Tools used (top 8 by count)

{chr(10).join(f"- `{n}` × {c}" for n, c in summary.tool_use_counts.most_common(8)) or "- (no tool calls recorded in transcript)"}

## What to do next

(Auto-journaling does not infer next steps. If you want a substantive
session journal, ask me to write one explicitly — I'll use the
`quill-session-journal` skill which produces a richer log.)

"""
    return body


def write_journal(
    summary: JournalSummary,
    *,
    sessions_dir: Path | None = None,
) -> Path:
    """Write the rendered markdown to ClaudeCode/Sessions/ and return the path.

    The filename is `<date>-<slug>.md`. If a file with that exact name
    already exists, appends `-2`, `-3`, etc. — never overwrites.
    """
    out_dir = sessions_dir or DEFAULT_VAULT_SESSIONS
    out_dir.mkdir(parents=True, exist_ok=True)

    date = (summary.ended_at or "")[:10]
    slug = slugify(summary.headline or "untitled")
    base = f"{date}-{slug}"
    target = out_dir / f"{base}.md"
    n = 2
    while target.exists():
        target = out_dir / f"{base}-{n}.md"
        n += 1
    target.write_text(render_markdown(summary))
    return target


def save_from_transcript(transcript_path: Path) -> Path:
    """Read a Claude Code transcript JSONL and write a journal.

    The transcript path is what Claude Code's hooks pass on stdin
    (field `transcript_path`). Best-effort: if the file is missing or
    malformed, we still write a stub journal so the session is recorded.
    """
    events: list[dict[str, Any]] = []
    if transcript_path.exists():
        with transcript_path.open() as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        events.append(obj)
                except json.JSONDecodeError:
                    continue
    summary = summarize_transcript(events)
    if not summary.headline and events:
        summary.headline = "claude code session"
    return write_journal(summary)


def session_end_hook(stdin_text: str) -> dict[str, Any]:
    """Pure-function entry for the SessionEnd hook.

    Reads `{transcript_path: ...}` from stdin, writes the journal,
    returns a hookSpecificOutput-shaped response (Claude Code ignores
    SessionEnd output but we return one so it's symmetric with the
    PreToolUse adapter).
    """
    try:
        payload = json.loads(stdin_text or "{}")
    except json.JSONDecodeError:
        payload = {}
    tpath_raw = payload.get("transcript_path") if isinstance(payload, dict) else None
    if not isinstance(tpath_raw, str) or not tpath_raw:
        return {"ok": False, "reason": "no transcript_path"}
    try:
        path = save_from_transcript(Path(tpath_raw).expanduser())
        return {"ok": True, "path": str(path)}
    except Exception as e:  # noqa: BLE001 — never raise from a hook
        return {"ok": False, "reason": f"{type(e).__name__}: {e}"}
