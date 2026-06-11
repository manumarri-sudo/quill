"""Render the delegation tree as ASCII.

`quill tree --live` reads the audit log file and reconstructs the tree, then
renders it with rich. Every 250ms it re-reads any new lines and updates.
This is the "watch the agents work" view a vibe coder runs in a side
terminal while their MCP client is doing things through the proxy.

The audit log is the single source of truth: we never need to share memory
with the running quill serve process. Whoever has read access to the log
can render the tree.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree


@dataclass(slots=True)
class _Node:
    """Reconstructed view of a session node, derived from the audit log."""

    id: str
    name: str
    intent: str = ""
    scope: tuple[str, ...] = ()
    parent_id: str | None = None
    closed: bool = False
    actions_attempted: int = 0
    actions_blocked: int = 0
    spend_usd: float = 0.0
    pending_ack: list[str] = field(default_factory=list)
    started_at: str = ""

    @property
    def status_color(self) -> str:
        if self.closed:
            return "dim"
        if self.pending_ack:
            return "yellow"
        if self.actions_blocked:
            return "red"
        return "green"


@dataclass(slots=True)
class _State:
    nodes: dict[str, _Node] = field(default_factory=dict)
    root_id: str | None = None
    budget_usd: float | None = None
    total_spend: float = 0.0
    last_ts: str = ""

    def apply(self, evt: dict[str, object]) -> None:
        etype = evt.get("type", "")
        agent_id = evt.get("agent_id", "")
        raw_payload = evt.get("payload", {})
        payload: dict[str, object] = raw_payload if isinstance(raw_payload, dict) else {}
        ts = evt.get("ts", "")
        if isinstance(ts, str):
            self.last_ts = ts

        def _scope() -> tuple[str, ...]:
            raw_scope = payload.get("scope")
            return tuple(str(s) for s in raw_scope) if isinstance(raw_scope, list) else ()

        if etype == "session.start":
            node = _Node(
                id=str(agent_id),
                name=str(payload.get("name", "root")),
                intent=str(payload.get("intent", "")),
                scope=_scope(),
                parent_id=None,
                started_at=str(ts),
            )
            self.nodes[node.id] = node
            self.root_id = node.id
            b = payload.get("budget_usd")
            self.budget_usd = float(b) if isinstance(b, (int, float)) else None
        elif etype == "agent.spawned":
            node = _Node(
                id=str(agent_id),
                name=str(payload.get("name", "agent")),
                intent=str(payload.get("intent", "")),
                scope=_scope(),
                parent_id=str(payload.get("parent_id")) if payload.get("parent_id") else None,
                started_at=str(ts),
            )
            self.nodes[node.id] = node
        elif etype == "agent.closed":
            n = self.nodes.get(str(agent_id))
            if n is not None:
                n.closed = True
                spend = payload.get("spend_usd")
                if isinstance(spend, (int, float)):
                    n.spend_usd = float(spend)
                attempted = payload.get("actions_attempted")
                if isinstance(attempted, int):
                    n.actions_attempted = attempted
                blocked = payload.get("actions_blocked")
                if isinstance(blocked, int):
                    n.actions_blocked = blocked
        elif etype == "session.end":
            n = self.nodes.get(str(agent_id))
            if n is not None:
                n.closed = True
        elif etype == "tool.attempted":
            n = self.nodes.get(str(agent_id))
            if n is not None:
                n.actions_attempted += 1
                tool_name = payload.get("tool_name", "")
                risk = evt.get("risk", "")
                if isinstance(tool_name, str) and risk in ("high", "critical"):
                    n.pending_ack.append(tool_name)
        elif etype == "verdict.allowed":
            n = self.nodes.get(str(agent_id))
            if n is not None:
                tool_name = payload.get("tool_name", "")
                if isinstance(tool_name, str) and tool_name in n.pending_ack:
                    n.pending_ack.remove(tool_name)
        elif etype in ("verdict.blocked", "verdict.scope_violation"):
            n = self.nodes.get(str(agent_id))
            if n is not None:
                n.actions_blocked += 1
                tool_name = payload.get("tool_name", "")
                if isinstance(tool_name, str) and tool_name in n.pending_ack:
                    n.pending_ack.remove(tool_name)
        elif etype == "tool.completed":
            # spend tracking would happen here; v0.2 default has no cost data
            pass


def _render(state: _State) -> Panel:
    """Render the current state as a rich panel."""
    if state.root_id is None:
        return Panel(
            Text("waiting for quill session…", style="dim"),
            title="[bold]quill tree[/bold]",
            border_style="dim",
        )

    root = state.nodes.get(state.root_id)
    if root is None:
        return Panel(Text("audit log corrupted", style="red"))

    # Header table
    header = Table.grid(padding=(0, 2))
    header.add_column(style="dim", no_wrap=True)
    header.add_column()
    header.add_row("intent", root.intent)
    if root.scope:
        header.add_row("scope", ", ".join(root.scope))
    if state.budget_usd is not None:
        pct = (root.spend_usd / state.budget_usd * 100) if state.budget_usd > 0 else 0
        bar = "█" * int(min(20, pct / 5)) + "░" * (20 - int(min(20, pct / 5)))
        color = "red" if pct > 80 else "yellow" if pct > 50 else "green"
        header.add_row(
            "budget",
            f"[{color}]{bar}[/{color}]  ${root.spend_usd:.2f} / ${state.budget_usd:.2f}  ({pct:.0f}%)",
        )

    # Build the rich tree starting from root
    rich_tree = _build_rich_tree(state, root)

    # Compose
    body = Group(
        header,
        Text(""),
        rich_tree,
    )
    title = (
        f"[bold]quill[/bold]    [dim]session {root.id}[/dim]    [dim]@ {state.last_ts[11:19]}[/dim]"
    )
    return Panel(body, title=title, border_style="blue")


def _build_rich_tree(state: _State, node: _Node) -> Tree:
    label = _node_label(node)
    tree = Tree(label)
    children = [n for n in state.nodes.values() if n.parent_id == node.id]
    children.sort(key=lambda n: n.started_at)
    for child in children:
        sub = tree.add(_node_label(child))
        for grandchild in [n for n in state.nodes.values() if n.parent_id == child.id]:
            sub.add(_node_label(grandchild))
    return tree


def _node_label(node: _Node) -> Text:
    color = node.status_color
    parts = [
        Text(node.name, style=f"bold {color}"),
        Text(f"  {node.id}", style="dim"),
        Text(f"   {node.actions_attempted} actions", style="dim"),
    ]
    if node.actions_blocked:
        parts.append(Text(f", {node.actions_blocked} blocked", style="red"))
    if node.pending_ack:
        parts.append(Text(f"   ⏸ awaiting ack: {', '.join(node.pending_ack)}", style="yellow"))
    if node.closed:
        parts.append(Text("   (closed)", style="dim italic"))
    line = Text()
    for p in parts:
        line.append_text(p)
    return line


def _read_lines(path: Path, start_offset: int) -> tuple[list[dict[str, object]], int]:
    """Read new lines from path starting at start_offset. Returns (events, new_offset)."""
    events: list[dict[str, object]] = []
    if not path.exists():
        return events, start_offset
    with path.open("rb") as f:
        f.seek(start_offset)
        data = f.read()
        new_offset = f.tell()
    for raw in data.splitlines():
        if not raw.strip():
            continue
        try:
            evt = json.loads(raw)
            if isinstance(evt, dict):
                events.append(evt)
        except json.JSONDecodeError:
            continue
    return events, new_offset


def render_tree_static(log_path: Path, console: Console | None = None) -> None:
    """One-shot snapshot of the tree from an existing audit log."""
    c = console or Console()
    state = _State()
    events, _ = _read_lines(log_path, 0)
    for e in events:
        state.apply(e)
    c.print(_render(state))


def render_tree_live(log_path: Path, console: Console | None = None) -> None:
    """Live-update the tree as new audit log lines arrive."""
    c = console or Console()
    state = _State()
    offset = 0
    # Seed with whatever is already in the log
    events, offset = _read_lines(log_path, 0)
    for e in events:
        state.apply(e)

    with Live(_render(state), console=c, refresh_per_second=4, screen=False) as live:
        try:
            while True:
                events, offset = _read_lines(log_path, offset)
                for e in events:
                    state.apply(e)
                live.update(_render(state))
                time.sleep(0.25)
        except KeyboardInterrupt:
            pass
