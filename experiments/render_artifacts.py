"""Render publication-ready artifacts from an audit log.

Reads ``experiments/results/audit.log.jsonl`` and produces:

  - tail_view.svg     stylised "quill tail --live" stream of a representative
                      blocked attack
  - audit_table.svg   "quill audit show" table of the most recent 30 events
  - tree_view.svg     SVG export of the delegation tree
  - results_chart.png a horizontal bar chart of attempts per category,
                      coloured by verdict
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# Repo-local imports.
_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_REPO / "src"))

from _quill_shim import render_tree_static  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402

RESULTS_DIR = _HERE / "results"
AUDIT_PATH = RESULTS_DIR / "audit.log.jsonl"
TAIL_SVG = RESULTS_DIR / "tail_view.svg"
TABLE_SVG = RESULTS_DIR / "audit_table.svg"
TREE_SVG = RESULTS_DIR / "tree_view.svg"
CHART_PNG = RESULTS_DIR / "results_chart.png"

# colour palette tied to verdict / risk
RISK_COLOURS = {
    "low": "green",
    "medium": "cyan",
    "high": "yellow",
    "critical": "red",
}
VERDICT_COLOURS = {
    "verdict.allowed": "green",
    "verdict.blocked": "red",
    "verdict.scope_violation": "magenta",
    "tool.attempted": "white",
    "tool.completed": "dim",
    "session.start": "blue",
    "agent.spawned": "cyan",
    "agent.closed": "dim",
    "session.end": "blue",
}


def _read_events(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with path.open() as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                out.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
    return out


def _short_ts(ts: str) -> str:
    return ts[11:19] if len(ts) >= 19 else ts


def _pick_representative_session(events: list[dict[str, Any]]) -> str:
    """Return the session_id of the scenario most likely to look striking
    on a screenshot: lots of attempts, lots of blocks. Falls back to the
    very first session in the log.
    """
    by_session: dict[str, dict[str, int]] = defaultdict(
        lambda: {"attempts": 0, "blocks": 0})
    for evt in events:
        sid = evt.get("session_id", "")
        if not sid:
            continue
        et = evt.get("type", "")
        if et == "tool.attempted":
            by_session[sid]["attempts"] += 1
        elif et in ("verdict.blocked", "verdict.scope_violation"):
            by_session[sid]["blocks"] += 1
    if not by_session:
        return ""
    best = max(by_session.items(),
               key=lambda kv: (kv[1]["blocks"], kv[1]["attempts"]))
    return best[0]


# ---------------------------------------------------------------------------
# tail_view.svg : a styled `quill tail --live` stream
# ---------------------------------------------------------------------------

def render_tail_view(events: list[dict[str, Any]], path: Path) -> None:
    target_sid = _pick_representative_session(events)
    target_evts = [e for e in events if e.get("session_id") == target_sid]
    # Cap at ~24 lines so it fits a publication crop.
    if len(target_evts) > 24:
        target_evts = target_evts[:24]

    console = Console(record=True, width=110, force_terminal=True,
                      color_system="truecolor")
    console.print(Text("quill tail --live", style="bold cyan"))
    console.print(Text(f"session {target_sid}", style="dim"))
    console.print()

    for evt in target_evts:
        ts = _short_ts(str(evt.get("ts", "")))
        et = str(evt.get("type", ""))
        risk = str(evt.get("risk", ""))
        payload: dict[str, Any] = evt.get("payload") or {}
        tool = str(payload.get("tool_name", ""))
        reason = str(payload.get("reason", ""))

        line = Text()
        line.append(f"{ts}  ", style="dim")
        evt_colour = VERDICT_COLOURS.get(et, "white")
        line.append(f"{et:<26}", style=evt_colour)
        line.append(" ")
        if risk:
            risk_colour = RISK_COLOURS.get(risk, "white")
            line.append(f"[{risk}]", style=f"bold {risk_colour}")
            line.append(" ")
        if tool:
            line.append(tool, style="bold white")
        if reason:
            line.append(f"   reason={reason}", style="italic dim")
        if et == "session.start":
            intent = str(payload.get("intent", ""))
            scope = ", ".join(str(s) for s in payload.get("scope", []))
            line.append(f"   intent={intent!r}", style="italic dim")
            line.append(f"  scope=[{scope}]", style="italic dim")
        console.print(line)

    path.write_text(console.export_svg(title="quill tail --live"))


# ---------------------------------------------------------------------------
# audit_table.svg : 'quill audit show' style
# ---------------------------------------------------------------------------

def render_audit_table(events: list[dict[str, Any]], path: Path) -> None:
    last = events[-30:]
    console = Console(record=True, width=120, force_terminal=True,
                      color_system="truecolor")
    table = Table(title="quill audit show  (last 30 events)",
                  title_style="bold cyan",
                  border_style="dim",
                  expand=True)
    table.add_column("ts", style="dim", no_wrap=True)
    table.add_column("session", style="cyan", no_wrap=True)
    table.add_column("event", no_wrap=True)
    table.add_column("risk", no_wrap=True)
    table.add_column("tool", style="white")
    table.add_column("notes", style="italic dim")

    for evt in last:
        ts = _short_ts(str(evt.get("ts", "")))
        sid = str(evt.get("session_id", ""))
        et = str(evt.get("type", ""))
        risk = str(evt.get("risk", ""))
        payload: dict[str, Any] = evt.get("payload") or {}
        tool = str(payload.get("tool_name", ""))
        notes = str(payload.get("reason", ""))

        et_text = Text(et, style=VERDICT_COLOURS.get(et, "white"))
        risk_text = Text(risk, style=RISK_COLOURS.get(risk, "white"))
        table.add_row(ts, sid, et_text, risk_text, tool, notes)

    console.print(table)
    path.write_text(console.export_svg(title="quill audit show"))


# ---------------------------------------------------------------------------
# tree_view.svg : delegation tree
# ---------------------------------------------------------------------------

def render_tree_view(audit_path: Path, path: Path) -> None:
    console = Console(record=True, width=110, force_terminal=True,
                      color_system="truecolor")
    render_tree_static(audit_path, console)
    path.write_text(console.export_svg(title="quill tree"))


# ---------------------------------------------------------------------------
# results_chart.png : horizontal bars
# ---------------------------------------------------------------------------

def render_results_chart(events: list[dict[str, Any]], path: Path) -> None:
    import matplotlib.pyplot as plt

    # bucket by tool category (namespace prefix or full name for flat tools)
    # and verdict.
    agentdojo_cats = ["fs", "github", "email", "slack", "calendar", "drive",
                      "travel", "banking", "deploy", "stripe", "postgres",
                      "web", "identity"]
    flat_cats = ["bash", "read_file", "write_file", "edit_file", "list_dir"]
    cats = agentdojo_cats + flat_cats
    counters: dict[str, Counter[str]] = {c: Counter() for c in cats}
    for evt in events:
        et = str(evt.get("type", ""))
        if et not in ("verdict.allowed", "verdict.blocked",
                      "verdict.scope_violation"):
            continue
        payload: dict[str, Any] = evt.get("payload") or {}
        tool = str(payload.get("tool_name", ""))
        # Prefer dotted-namespace; fall back to whole tool name (vibe-coder)
        ns = tool.split(".", 1)[0] if "." in tool else tool
        if ns not in counters:
            continue
        if et == "verdict.allowed":
            counters[ns]["allowed"] += 1
        elif et == "verdict.blocked":
            # per harness, verdict.blocked w/ reason=human_declined is the
            # human-ack pause path
            reason = str(payload.get("reason", ""))
            if reason == "human_declined":
                counters[ns]["paused"] += 1
            else:
                counters[ns]["blocked"] += 1
        else:
            counters[ns]["scope"] += 1

    # drop categories with no events
    visible = [c for c in cats if sum(counters[c].values()) > 0]
    if not visible:
        # nothing to chart; emit a placeholder
        fig, ax = plt.subplots(figsize=(8, 2))
        ax.text(0.5, 0.5, "no verdict events recorded",
                ha="center", va="center")
        ax.axis("off")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return

    allowed = [counters[c]["allowed"] for c in visible]
    paused = [counters[c]["paused"] for c in visible]
    blocked = [counters[c]["blocked"] for c in visible]
    scope = [counters[c]["scope"] for c in visible]

    fig, ax = plt.subplots(figsize=(9, 0.55 * len(visible) + 1.5))
    y = list(range(len(visible)))
    left = [0] * len(visible)
    series = [
        (allowed, "allowed", "#2ca02c"),
        (paused, "human paused", "#f1c40f"),
        (blocked, "blocked", "#d62728"),
        (scope, "scope violation", "#5b1f1f"),
    ]
    for values, label, colour in series:
        ax.barh(y, values, left=left, color=colour, label=label,
                edgecolor="white", linewidth=0.5)
        left = [a + b for a, b in zip(left, values, strict=True)]
    ax.set_yticks(y)
    ax.set_yticklabels(visible)
    ax.invert_yaxis()
    ax.set_xlabel("tool calls (verdict)")
    ax.set_title("Quill verdicts by tool category")
    ax.legend(loc="lower right", fontsize=9, frameon=False)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="audit", type=Path, default=AUDIT_PATH,
                        help="path to audit.log.jsonl")
    args = parser.parse_args()

    audit = args.audit
    out_dir = audit.parent
    tail_svg = out_dir / "tail_view.svg"
    table_svg = out_dir / "audit_table.svg"
    tree_svg = out_dir / "tree_view.svg"
    chart_png = out_dir / "results_chart.png"

    if not audit.exists():
        print(f"audit log not found at {audit}; "
              "run agentdojo_harness.py first")
        return 1
    events = _read_events(audit)
    if not events:
        print("audit log is empty")
        return 1

    print(f"rendering {len(events)} events from {audit}")
    render_tail_view(events, tail_svg)
    print(f"  wrote {tail_svg}")
    render_audit_table(events, table_svg)
    print(f"  wrote {table_svg}")
    render_tree_view(audit, tree_svg)
    print(f"  wrote {tree_svg}")
    render_results_chart(events, chart_png)
    print(f"  wrote {chart_png}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
