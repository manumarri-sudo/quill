"""In-terminal TUI dashboard for Quill.

Replaces the browser dashboard for users who'd rather stay in the same
window. Cream-on-navy editorial palette per the project standing rules.
Built on Textual so we can re-use the Rich segments Quill already
emits, and so it integrates with `prefers-reduced-motion`-style refresh
discipline naturally.

Design brief is in this file's git history (see commit message). Key
points: sidebar with filter counts, main feed reverse-chrono, footer
hotbar, sub-agent rows decorated with `↳ sub·N`, modal peek on Enter.
No mouse required, no spinners, no splash screen.

Run with `quill watch` (the default) or `quill watch --browser` for
the old localhost HTTP dashboard.
"""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Static

# ---- palette (matches the landing page locked tokens) ---------------------

PALETTE = {
    "bg":    "#fafaf5",
    "ink":   "#1e3a5f",
    "muted": "#6b7a8f",
    "rule":  "#d8d4c4",
    "allow": "#3d6b4a",   # slate green, NOT matrix
    "ask":   "#b8862b",   # mustard, never pure yellow
    "block": "#c1442f",   # warm coral, brand-aligned
    "sub":   "#7a4a7a",   # plum for sub-agent decoration
    "spawn": "#7a4a7a",
    "hint":  "#5E81AC",   # steel-blue (delta convention) - the
                          # "try instead" / informational lane
}

CSS = f"""
Screen {{
    background: {PALETTE['bg']};
    color: {PALETTE['ink']};
}}

Header {{
    background: {PALETTE['ink']};
    color: {PALETTE['bg']};
    height: 3;
    border-bottom: solid {PALETTE['rule']};
    text-style: bold;
}}

Footer {{
    background: {PALETTE['ink']};
    color: {PALETTE['bg']};
}}

Footer > .footer--key {{
    background: {PALETTE['ink']};
    color: {PALETTE['bg']};
    text-style: bold;
}}

#sidebar {{
    width: 26;
    background: {PALETTE['bg']};
    border-right: solid {PALETTE['rule']};
    padding: 1 2;
}}

#sidebar .heading {{
    color: {PALETTE['muted']};
    text-style: bold;
    padding: 1 0 0 0;
}}

#sidebar .item {{
    color: {PALETTE['ink']};
    padding: 0 0 0 0;
}}

#sidebar .item.active {{
    text-style: bold;
}}

#main {{
    padding: 0 0 0 1;
}}

DataTable {{
    background: {PALETTE['bg']};
    color: {PALETTE['ink']};
}}

DataTable > .datatable--header {{
    background: {PALETTE['bg']};
    color: {PALETTE['muted']};
    text-style: bold;
}}

DataTable > .datatable--cursor {{
    background: {PALETTE['ink']};
    color: {PALETTE['bg']};
}}

DataTable > .datatable--hover {{
    background: {PALETTE['rule']};
}}

#empty {{
    color: {PALETTE['muted']};
    text-align: center;
    padding: 4 0;
}}

#empty .accent {{
    color: {PALETTE['block']};
    text-style: bold;
}}

PeekModal {{
    align: center middle;
}}

#peek-card {{
    background: {PALETTE['bg']};
    border: tall {PALETTE['ink']};
    padding: 2 4;
    width: 80%;
    height: 70%;
}}

#peek-card .title {{
    color: {PALETTE['ink']};
    text-style: bold;
}}

#peek-card .body {{
    color: {PALETTE['ink']};
    padding-top: 1;
}}
"""


# ---- model ----------------------------------------------------------------

@dataclass(slots=True)
class Event:
    """Parsed audit-log event, projected to what the TUI needs."""

    raw: dict[str, Any]

    @property
    def ts(self) -> str:
        return str(self.raw.get("ts", ""))

    @property
    def time_short(self) -> str:
        return self.ts[11:19]

    @property
    def type(self) -> str:
        return str(self.raw.get("type", ""))

    @property
    def risk(self) -> str:
        return str(self.raw.get("risk", "low"))

    @property
    def session_id(self) -> str:
        return str(self.raw.get("session_id", ""))

    @property
    def payload(self) -> dict[str, Any]:
        p = self.raw.get("payload") or {}
        return p if isinstance(p, dict) else {}

    @property
    def tool_name(self) -> str:
        return str(self.payload.get("tool_name", "") or "")

    @property
    def parent_session_id(self) -> str:
        return str(self.payload.get("parent_session_id", "") or "")

    @property
    def is_sub(self) -> bool:
        return bool(self.parent_session_id)

    @property
    def reason(self) -> str:
        return str(
            self.payload.get("reason")
            or self.payload.get("risk_reason")
            or "",
        )

    @property
    def what_was_tried(self) -> str:
        ap = self.payload.get("args_preview") or {}
        if not isinstance(ap, dict):
            return ""
        v = ap.get("command") or ap.get("path") or ap.get("file_path") or ""
        return str(v).replace("\n", " ")[:140]


@dataclass(slots=True)
class FilterState:
    """Active filter over the event list. Updated by hotkeys."""
    mode: str = "all"   # all | allowed | blocked | asked | scope


# ---- main app -------------------------------------------------------------


class PeekModal(ModalScreen[None]):
    """Full-event JSON peek on Enter."""

    BINDINGS = [Binding("escape", "dismiss", "close"),
                Binding("enter", "dismiss", "close")]

    def __init__(self, evt: Event) -> None:
        super().__init__()
        self.evt = evt

    def compose(self) -> ComposeResult:
        body = json.dumps(self.evt.raw, indent=2)
        with Vertical(id="peek-card"):
            yield Static(f"[b]{self.evt.type}[/b]   [dim]{self.evt.ts}[/dim]",
                         classes="title")
            yield Static(body, classes="body")

    def action_dismiss(self) -> None:  # type: ignore[override]
        self.app.pop_screen()


class QuillCommands(Provider):
    """Textual CommandPalette provider - fuzzy-searchable actions.

    Reachable via `Ctrl+P` or `:` (Textual's built-in palette opens both).
    Maps Quill's existing keymap operations to a discoverable surface so
    new users don't have to memorize 14 shortcuts. Zero new dependencies -
    Textual ships the palette natively (MIT).
    """

    async def discover(self) -> Hits:
        """Show this list when the palette opens with an empty query."""
        app = self.app
        for cmd in self._commands(app):
            yield DiscoveryHit(cmd[0], cmd[1], help=cmd[2])

    async def search(self, query: str) -> Hits:
        """Standard fuzzy match against command names + help text."""
        matcher = self.matcher(query)
        for name, runnable, help_text in self._commands(self.app):
            score = matcher.match(f"{name} {help_text}")
            if score > 0:
                yield Hit(score, matcher.highlight(name), runnable, help=help_text)

    @staticmethod
    def _commands(app: App[None]) -> list[tuple[str, Callable[[], None], str]]:
        """The canonical command set. Add new entries here, not in BINDINGS."""
        return [
            ("filter: all",         app.action_filter_all,     "show every audit event"),
            ("filter: allowed",     app.action_filter_allowed, "only verdict.allowed events"),
            ("filter: blocked",     app.action_filter_blocked, "only verdict.blocked events (critical denies)"),
            ("filter: asked",       app.action_filter_asked,   "only verdict.ask events (waiting on human)"),
            ("filter: scope",       app.action_filter_scope,   "only verdict.scope_violation events"),
            ("pause / resume tail", app.action_toggle_pause,   "freeze the live tail to inspect a row"),
            ("clear screen",        app.action_clear,          "clear the table (keeps the audit log intact)"),
            ("scroll: top",         app.action_scroll_top,     "jump to oldest event"),
            ("scroll: bottom",      app.action_scroll_bottom,  "jump to newest event"),
            ("peek event",          app.action_peek,           "open the JSON peek panel for the selected row"),
            ("yank command",        app.action_yank,           "copy the selected event's command to clipboard"),
            ("help",                app.action_help,           "show keyboard shortcuts"),
            ("quit",                app.action_quit,           "exit the dashboard"),
        ]


class QuillWatchTUI(App[None]):
    """`quill watch` - TUI dashboard."""

    CSS = CSS

    # Plug the QuillCommands provider into the built-in CommandPalette.
    # Users press Ctrl+P (or :) to fuzzy-search every action.
    COMMANDS = App.COMMANDS | {QuillCommands}

    BINDINGS = [
        Binding("q", "quit", "quit"),
        Binding("question_mark", "help", "help"),
        Binding("slash", "search", "search", show=False),
        Binding("p", "toggle_pause", "pause"),
        Binding("a", "filter_all", "all"),
        Binding("1", "filter_allowed", "allowed"),
        Binding("2", "filter_blocked", "blocked"),
        Binding("3", "filter_asked", "asked"),
        Binding("4", "filter_scope", "scope"),
        Binding("c", "clear", "clear"),
        Binding("g", "scroll_top", "top", show=False),
        Binding("G", "scroll_bottom", "bottom", show=False),
        Binding("y", "yank", "yank"),
        Binding("enter", "peek", "peek"),
    ]

    paused: reactive[bool] = reactive(False)
    filter_mode: reactive[str] = reactive("all")
    follow_tail: reactive[bool] = reactive(True)

    def __init__(self, log_path: Path) -> None:
        super().__init__()
        self.log_path = log_path
        self.events: list[Event] = []
        self._tail_offset = 0
        self._sub_labels: dict[str, str] = {}     # session_id -> "sub·N"
        self._sub_counter = 0
        self.title = "quill watch"
        self.sub_title = str(log_path)

    # ---- layout ----------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("[b]filters[/b]", classes="heading")
                yield Static("a  all       [dim](0)[/dim]", id="filt-all",
                             classes="item active")
                yield Static("1  allowed   [dim](0)[/dim]", id="filt-allow",
                             classes="item")
                yield Static("2  blocked   [dim](0)[/dim]", id="filt-block",
                             classes="item")
                yield Static("3  asked     [dim](0)[/dim]", id="filt-ask",
                             classes="item")
                yield Static("4  scope     [dim](0)[/dim]", id="filt-scope",
                             classes="item")
                yield Static("[b]agents[/b]", classes="heading")
                yield Static("(none yet)", id="agent-list", classes="item")
                yield Static("[b]projects[/b]", classes="heading")
                yield Static("(none yet)", id="project-list", classes="item")
                yield Static("[b]legend[/b]", classes="heading")
                yield Static(
                    f"[#{PALETTE['allow'][1:]}]✓ allow[/]   "
                    f"[#{PALETTE['ask'][1:]}]? ask[/]\n"
                    f"[#{PALETTE['block'][1:]}]✗ block[/]   "
                    f"[#{PALETTE['sub'][1:]}]✗ scope[/]\n"
                    f"[#{PALETTE['hint'][1:]}]↪ try[/]   "
                    f"[#{PALETTE['sub'][1:]}]↳ sub-agent[/]",
                    classes="item",
                )
            with Vertical(id="main"):
                table: DataTable[str] = DataTable(
                    id="events", zebra_stripes=False,
                    cursor_type="row", header_height=1,
                )
                table.add_columns(
                    "time", "verdict", "risk", "tool", "what was tried", "why",
                )
                yield table
                yield Static(
                    f"[b][#{PALETTE['block'][1:]}]▍[/] Quill is live.[/b] "
                    f"Waiting for tool calls.\n"
                    f"[#{PALETTE['muted'][1:]}]Run an agent that goes through Quill's hook "
                    "and events will appear here. Press [b]?[/b] for keys.[/]",
                    id="empty",
                )
        yield Footer()

    def on_mount(self) -> None:
        self._table = self.query_one("#events", DataTable)
        self._empty = self.query_one("#empty", Static)
        self._table.display = False  # show empty state until first event
        # initial drain
        self._drain_log()
        # render sidebar counts immediately so counts are populated by
        # screenshot-time / first-frame, not 1s after load.
        self._refresh_sidebar()
        # poll for new events ~10 Hz; cheap because we just stat the file
        self.set_interval(0.1, self._drain_log)
        # refresh sidebar counts ~1 Hz
        self.set_interval(1.0, self._refresh_sidebar)

    # ---- log tail --------------------------------------------------------

    def _drain_log(self) -> None:
        if self.paused:
            return
        if not self.log_path.exists():
            return
        try:
            sz = self.log_path.stat().st_size
        except OSError:
            return
        if sz < self._tail_offset:
            self._tail_offset = 0  # log rotated/truncated
        if sz == self._tail_offset:
            return
        new_events: list[Event] = []
        with self.log_path.open() as f:
            f.seek(self._tail_offset)
            for line in f:
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                evt = Event(raw=raw)
                # assign sub-agent labels eagerly from agent.spawned events
                if evt.type == "agent.spawned":
                    sid = evt.session_id
                    if sid and sid not in self._sub_labels:
                        self._sub_counter += 1
                        self._sub_labels[sid] = f"sub·{self._sub_counter}"
                new_events.append(evt)
            self._tail_offset = f.tell()

        if not new_events:
            return

        self.events.extend(new_events)
        self._render_new(new_events)

    def _render_new(self, evts: Iterable[Event]) -> None:
        # filter to what the user wants to see
        for e in evts:
            if not self._passes_filter(e):
                continue
            self._add_row(e)

        # show table once we have something
        if self.events and self._table.display is False:
            self._table.display = True
            self._empty.display = False

        if self.follow_tail:
            self._table.action_scroll_end()

    def _passes_filter(self, e: Event) -> bool:
        m = self.filter_mode
        if m == "all":
            return True
        if m == "allowed" and e.type == "verdict.allowed": return True
        if m == "blocked" and e.type == "verdict.blocked": return True
        if m == "asked" and e.type == "verdict.ask": return True
        if m == "scope" and e.type == "verdict.scope_violation": return True
        # always show spawn events regardless of filter (context for subs)
        if e.type == "agent.spawned": return True
        return False

    def _add_row(self, e: Event) -> None:
        # cell colors via rich markup
        risk_color = {
            "low": PALETTE["allow"],
            "medium": PALETTE["muted"],
            "high": PALETTE["ask"],
            "critical": PALETTE["block"],
        }.get(e.risk, PALETTE["muted"])

        type_glyph = {
            "verdict.allowed":         (PALETTE["allow"], "✓ allow"),
            "verdict.blocked":         (PALETTE["block"], "✗ block"),
            "verdict.ask":             (PALETTE["ask"],   "? ask"),
            "verdict.scope_violation": (PALETTE["sub"],   "✗ scope"),
            "tool.attempted":          (PALETTE["muted"], "· attempt"),
            "tool.completed":          (PALETTE["allow"], "✓ done"),
            "agent.spawned":           (PALETTE["sub"],   "▸ spawn"),
            "session.start":           (PALETTE["muted"], "▸ start"),
            "session.end":             (PALETTE["muted"], "◂ end"),
        }
        tcolor, tlabel = type_glyph.get(e.type, (PALETTE["muted"], e.type))

        # sub-agent decoration on the tool cell
        sub_tag = ""
        if e.is_sub:
            label = self._sub_labels.get(e.session_id, "sub")
            sub_tag = f"[#{PALETTE['sub'][1:]}]↳ {label}[/]  "

        tool = e.tool_name or ""
        what = e.what_was_tried
        if e.type == "agent.spawned":
            cwd = e.payload.get("cwd", "") or ""
            short_cwd = ".../" + str(cwd).rsplit("/", 2)[-1] if cwd else ""
            label = self._sub_labels.get(e.session_id, "sub")
            tool = label
            what = f"spawned by [{e.parent_session_id[:12]}…] {short_cwd}"

        # Split the "<reason> · try instead: <suggestion>" format so the
        # suggestion can render on its own steel-blue row beneath this one.
        full_reason = e.reason
        suggestion = ""
        if " · try instead: " in full_reason:
            short_reason, suggestion = full_reason.split(" · try instead: ", 1)
        else:
            short_reason = full_reason

        self._table.add_row(
            f"[#{PALETTE['muted'][1:]}]{e.time_short}[/]",
            f"[#{tcolor[1:]}]{tlabel}[/]",
            f"[#{risk_color[1:]}]{e.risk}[/]",
            f"{sub_tag}{tool}",
            what,
            f"[#{PALETTE['muted'][1:]}][i]{short_reason[:80]}[/i][/]",
        )
        # Hint-lane row, only when there's an actionable suggestion.
        # Steel-blue, no clutter, scannable.
        if suggestion:
            self._table.add_row(
                "", "", "", "",
                f"[#{PALETTE['hint'][1:]}]↪ try[/]",
                f"[#{PALETTE['hint'][1:]}]{suggestion[:90]}[/]",
            )

    def _refresh_sidebar(self) -> None:
        c: Counter[str] = Counter()
        agents: Counter[str] = Counter()
        projects: Counter[str] = Counter()
        for e in self.events:
            t = e.type
            if t == "verdict.allowed": c["allow"] += 1
            elif t == "verdict.blocked": c["block"] += 1
            elif t == "verdict.ask": c["ask"] += 1
            elif t == "verdict.scope_violation": c["scope"] += 1
            if e.is_sub:
                lbl = self._sub_labels.get(e.session_id, "sub")
                agents[lbl] += 1
            elif e.type.startswith("verdict.") or e.type == "tool.attempted":
                agents["root"] += 1
            cwd = e.payload.get("cwd")
            if isinstance(cwd, str) and cwd:
                projects[cwd.rsplit("/", 1)[-1]] += 1

        total = sum(c.values())

        def _label(text: str, n: int, target: str) -> str:
            active = " [b]" if self.filter_mode == target else " "
            close = "[/b]" if self.filter_mode == target else ""
            return f"{active}{text} [#{PALETTE['muted'][1:]}]({n})[/]{close}"

        self.query_one("#filt-all", Static).update(_label("a  all      ", total, "all"))
        self.query_one("#filt-allow", Static).update(_label("1  allowed  ", c["allow"], "allowed"))
        self.query_one("#filt-block", Static).update(_label("2  blocked  ", c["block"], "blocked"))
        self.query_one("#filt-ask", Static).update(_label("3  asked    ", c["ask"], "asked"))
        self.query_one("#filt-scope", Static).update(_label("4  scope    ", c["scope"], "scope"))

        if agents:
            text = "\n".join(
                f"  {n}  [#{PALETTE['muted'][1:]}]({k})[/]"
                for n, k in agents.most_common(8)
            )
            self.query_one("#agent-list", Static).update(text)
        if projects:
            text = "\n".join(
                f"  {n}  [#{PALETTE['muted'][1:]}]({k})[/]"
                for n, k in projects.most_common(8)
            )
            self.query_one("#project-list", Static).update(text)

    def _rebuild_table(self) -> None:
        self._table.clear()
        for e in self.events:
            if self._passes_filter(e):
                self._add_row(e)

    # ---- bindings --------------------------------------------------------

    def action_toggle_pause(self) -> None:
        self.paused = not self.paused

    def action_filter_all(self) -> None:     self.filter_mode = "all";     self._rebuild_table()
    def action_filter_allowed(self) -> None: self.filter_mode = "allowed"; self._rebuild_table()
    def action_filter_blocked(self) -> None: self.filter_mode = "blocked"; self._rebuild_table()
    def action_filter_asked(self) -> None:   self.filter_mode = "asked";   self._rebuild_table()
    def action_filter_scope(self) -> None:   self.filter_mode = "scope";   self._rebuild_table()

    def action_clear(self) -> None:
        self._table.clear()

    def action_scroll_top(self) -> None: self._table.action_scroll_home()
    def action_scroll_bottom(self) -> None: self._table.action_scroll_end()

    def action_peek(self) -> None:
        try:
            row = self._table.cursor_row
        except Exception:
            return
        if row < 0:
            return
        # Map the table row to the event in self.events that's currently
        # shown; with filter active we walk through filtered events.
        visible = [e for e in self.events if self._passes_filter(e)]
        if 0 <= row < len(visible):
            self.push_screen(PeekModal(visible[row]))

    def action_yank(self) -> None:
        try:
            row = self._table.cursor_row
        except Exception:
            return
        if row < 0:
            return
        visible = [e for e in self.events if self._passes_filter(e)]
        if 0 <= row < len(visible):
            self.copy_to_clipboard(json.dumps(visible[row].raw))

    def action_help(self) -> None:
        # Footer already shows binding hints; pop a help modal with the full set.
        evt = Event(raw={
            "type": "quill.help",
            "ts": datetime.now().isoformat(),
            "payload": {
                "tool_name": "help",
                "reason": (
                    "q: quit · ?: this help · 1-4: filter · a: all · "
                    "p: pause · c: clear · g/G: top/bottom · y: yank · "
                    "enter: peek event · esc: dismiss"
                ),
            },
        })
        self.push_screen(PeekModal(evt))


def run_tui(log_path: Path) -> None:
    """Public entry - `quill watch` calls this."""
    QuillWatchTUI(log_path).run()
