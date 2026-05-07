"""quill CLI.

  quill init           write a starter ~/.quill/config.toml
  quill serve          run the MCP proxy (this is what Claude Code points to)
  quill tail           live-stream the audit log in a separate terminal
  quill tree           render the multi-agent delegation tree (snapshot or live)
  quill audit verify   walk the HMAC chain on an existing log file
  quill audit show     pretty-print the log

The CLI is deliberately thin. Logic lives in the library; this module is wiring.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path
from typing import Annotated

import anyio
import typer
from rich.console import Console
from rich.table import Table

from quill._version import __version__
from quill.adapters import claude_code as cc_adapter
from quill.audit import AuditLog, verify_chain
from quill.doctor import run_doctor
from quill import journal as journal_mod
from quill import telemetry as tel
from quill import watch as watch_mod
from quill.config import (
    QuillConfig,
    default_audit_path,
    default_config_path,
    load_config,
    render_starter_config,
)
from quill.errors import ConfigError, QuillError
from quill.policy import SessionIntent
from quill.prompt import Prompter
from quill.proxy import QuillProxy, build_proxy_server, run_stdio
from quill.tree import render_tree_live, render_tree_static

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,  # `quill` with no args runs `start`
    help="quill: the pause button between AI agents and the things you can't undo.\n\n"
         "  quill start    set up + watch live (this is the only command most users need)\n"
         "  quill audit    see what got blocked/allowed\n"
         "  quill doctor   diagnose the install\n",
)


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    """When called with no subcommand, run `start`."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(start)
audit_app = typer.Typer(
    no_args_is_help=True,
    help="see what got blocked / allowed / asked.",
)
app.add_typer(audit_app, name="audit")
journal_app = typer.Typer(no_args_is_help=True, help="session-journal subcommands.")
app.add_typer(journal_app, name="journal", hidden=True)
telemetry_app = typer.Typer(
    no_args_is_help=True,
    help="opt-in anonymous usage telemetry.",
)
app.add_typer(telemetry_app, name="telemetry", hidden=True)

console = Console(stderr=True)


def _maybe_emit_telemetry(audit_path: Path) -> None:
    """Best-effort send of a session.summary if the user has opted in.

    Reads the audit log we just wrote, derives the aggregate, fires off the
    POST. Never raises — telemetry must not affect proxy correctness.
    """
    state = tel.TelemetryState.load()
    if not state.opted_in:
        return
    if not audit_path.exists():
        return
    try:
        events = []
        with audit_path.open() as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        aggregate = tel.aggregate_events(events)
        tel.emit_session_summary(aggregate, state=state)
    except Exception:  # noqa: BLE001 — never block on telemetry
        pass


def _hmac_key() -> bytes:
    """Load the HMAC signing key from ~/.quill/key, or generate on first run.

    File is mode 0o600. Document key rotation in SECURITY.md.
    """
    p = Path(os.environ.get("QUILL_KEY", "~/.quill/key")).expanduser()
    if p.exists():
        return p.read_bytes()
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    p.write_bytes(key)
    p.chmod(0o600)
    return key


# --------------------------------------------------------------------------
# start — the front door. one command, sets up + opens dashboard.
# --------------------------------------------------------------------------

@app.command()
def start(
    no_browser: Annotated[
        bool,
        typer.Option("--no-browser", help="don't auto-open the dashboard"),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes", "-y",
            help="don't prompt for the telemetry decision (leaves it as-is)",
        ),
    ] = False,
) -> None:
    """Install the hook, optionally enable telemetry, open the dashboard.

    This is the only command most users will ever run. Idempotent — safe
    to re-run; nothing gets duplicated. After this finishes, every Bash /
    Edit / Write / NotebookEdit call in your Claude Code session is gated
    by quill, signed into ~/.quill/audit.log.jsonl, and visible live in
    the dashboard.
    """
    out = Console()

    out.print()
    out.print("[bold]quill[/bold] [dim]· the pause button between AI agents "
              "and the things you can't undo[/dim]")
    out.print()

    # 1. Install the Claude Code PreToolUse hook (idempotent)
    settings_path, was_installed = cc_adapter.install_into_settings()
    if was_installed:
        out.print(f"  [green]✓[/green] hook already installed in [dim]{settings_path}[/dim]")
    else:
        out.print(f"  [green]✓[/green] hook installed in [dim]{settings_path}[/dim]")
        out.print(f"        [yellow]→ restart Claude Code to pick up the new hook[/yellow]")

    # 2. Telemetry one-time prompt
    state = tel.TelemetryState.load()
    if not state.asked and not yes:
        out.print()
        out.print("  [bold]help shape quill v0.2?[/bold]  share anonymous "
                  "aggregate stats — counts, risk distribution, namespaces.")
        out.print("  [dim]nothing personally identifiable. inspect what would "
                  "ship: [bold]quill telemetry show[/bold][/dim]")
        try:
            ans = typer.prompt(
                "  share? (y/N)", default="N", show_default=False,
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            ans = "n"
        if ans == "y":
            tel.opt_in()
            out.print(f"  [green]✓[/green] telemetry on   [dim]install_id "
                      f"{tel.TelemetryState.load().install_id}[/dim]")
        else:
            tel.opt_out()
            out.print("  [dim]✓ telemetry off (default). turn on later: "
                      "quill telemetry on[/dim]")
    else:
        on = state.opted_in
        out.print(f"  [green]✓[/green] telemetry: "
                  f"[{'green' if on else 'dim'}]{'on' if on else 'off'}[/]")

    # 3. Doctor sanity-check (silent unless something's wrong)
    report = run_doctor()
    if report.has_failures:
        out.print()
        out.print("  [red]✗ install has failures. run [bold]quill doctor[/bold] "
                  "to see them.[/red]")
        return
    if report.has_warnings:
        warns = [r for r in report.results if r.status == "[yellow]WARN[/yellow]"]
        out.print(f"  [yellow]⚠[/yellow] {len(warns)} warning(s)  "
                  f"[dim](quill doctor for details)[/dim]")
    else:
        out.print("  [green]✓[/green] install looks clean")

    # 4. Start the live dashboard as a background daemon.
    # The daemon survives Ctrl-C, terminal close, and Claude Code exit.
    # The hook re-checks on every tool call and respawns if it died.
    out.print()
    log = default_audit_path()
    n_events = 0
    if log.exists():
        with log.open() as f:
            n_events = sum(1 for _ in f)

    pid, bound_port = watch_mod.ensure_daemon(
        log, port=watch_mod.DEFAULT_PORT, open_browser=False,
    )
    url = f"http://127.0.0.1:{bound_port}/"

    out.print(f"  [bold cyan]quill is live.[/bold cyan]  "
              f"dashboard: [bold]{url}[/bold]  [dim](pid {pid})[/dim]")
    out.print(f"  [dim]audit log: {log} · {n_events} entries[/dim]")
    out.print()
    out.print("  [green]you're done.[/green] open Claude Code in any project; "
              "every Bash / Edit / Write goes through the gate.")
    out.print("  [dim]bookmark the dashboard URL — daemon survives terminal "
              "close. stop with: quill stop[/dim]")

    if not no_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------
# init
# --------------------------------------------------------------------------

@app.command(hidden=True)
def init(
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="where to write the starter config"),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="overwrite an existing config"),
    ] = False,
) -> None:
    """Write a starter quill config to ~/.quill/config.toml."""
    p = config_path or default_config_path()
    if p.exists() and not force:
        console.print(f"[yellow]exists:[/yellow] {p}  (--force to overwrite)")
        raise typer.Exit(code=1)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_starter_config())
    p.chmod(0o600)
    console.print(f"[green]wrote[/green] {p}")
    console.print("edit it to declare your session intent, scope, and upstreams.")
    console.print("then: [bold]quill serve[/bold]")


# --------------------------------------------------------------------------
# serve
# --------------------------------------------------------------------------

@app.command(hidden=True)
def serve(
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c"),
    ] = None,
) -> None:
    """Run the MCP proxy server. Point Claude Code's mcpServers config here."""

    async def _run() -> None:
        try:
            cfg = load_config(config_path)
        except ConfigError as e:
            console.print(f"[red]config error:[/red] {e}")
            raise typer.Exit(code=1) from e

        intent = SessionIntent(
            session_id="ses_" + secrets.token_hex(4),
            intent=cfg.session.intent,
            scope=cfg.session.parsed_scope(),
            budget_usd=cfg.session.budget_usd,
        )

        with AuditLog(path=cfg.audit.resolved_path(), hmac_key=_hmac_key()) as audit:
            audit.emit(
                event_type="session.start",
                session_id=intent.session_id,
                payload={
                    "intent": intent.intent,
                    "scope": [str(s) for s in intent.scope],
                    "budget_usd": intent.budget_usd,
                    "upstreams": [u.name for u in cfg.upstream],
                },
                force_fsync=True,
            )
            prompter = Prompter()
            proxy = QuillProxy(
                config=cfg, audit=audit, prompter=prompter, intent=intent,
            )
            async with proxy:
                console.print(
                    f"[green]quill[/green] running. session={intent.session_id}, "
                    f"upstreams={[u.name for u in cfg.upstream]}",
                )
                console.print(f"[dim]audit log: {cfg.audit.resolved_path()}[/dim]")
                # Run the MCP server over stdio so Claude Code can connect.
                server = build_proxy_server(proxy)
                try:
                    await run_stdio(server)
                finally:
                    _maybe_emit_telemetry(cfg.audit.resolved_path())

    try:
        anyio.run(_run)
    except QuillError as e:
        console.print(f"[red]quill error:[/red] {e}")
        raise typer.Exit(code=1) from e


# --------------------------------------------------------------------------
# tail
# --------------------------------------------------------------------------

@app.command(hidden=True)
def tail(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l"),
    ] = None,
    follow: Annotated[
        bool,
        typer.Option("--follow/--no-follow", "-f"),
    ] = True,
) -> None:
    """Live-stream the audit log. Run this in a side terminal while Quill serves."""
    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log yet:[/yellow] {p}")
        raise typer.Exit(code=1)

    risk_color = {
        "low": "green",
        "medium": "cyan",
        "high": "yellow",
        "critical": "bold red",
    }
    type_glyph = {
        "session.start": ("cyan", "▸ session start"),
        "session.end":   ("cyan", "◂ session end"),
        "agent.spawned": ("cyan", "▸ agent spawned"),
        "agent.closed":  ("cyan", "◂ agent closed"),
        "tool.attempted": ("dim",  "·  attempt"),
        "tool.completed": ("green","✓  completed"),
        "tool.errored":   ("red",  "✗  errored"),
        "verdict.allowed":         ("green",   "✓  allowed"),
        "verdict.blocked":         ("bold red","✗  BLOCKED"),
        "verdict.scope_violation": ("magenta", "✗  scope_violation"),
        "verdict.ask":             ("yellow",  "?  ask human"),
    }

    def _summarise(evt: dict[str, object]) -> str:
        """One-line plain-English summary of what's interesting in this event."""
        p = evt.get("payload", {}) or {}
        if not isinstance(p, dict):
            return ""
        tool = str(p.get("tool_name") or "")
        ap = p.get("args_preview") or {}
        snippet = ""
        if isinstance(ap, dict):
            v = ap.get("command") or ap.get("path") or ap.get("file_path") or ""
            if isinstance(v, str) and v:
                snippet = v.replace("\n", " ")[:90]
        reason = p.get("reason") or p.get("risk_reason") or ""
        bits: list[str] = []
        if tool:
            bits.append(f"[bold]{tool}[/bold]")
        if snippet:
            bits.append(f"[dim]{snippet}[/dim]")
        if reason:
            bits.append(f"[dim italic]— {reason}[/dim italic]")
        return "  ".join(bits)

    # session_id → short label so sub-agents are visually identifiable
    sub_labels: dict[str, str] = {}
    sub_counter = [0]

    def _label(evt: dict[str, object]) -> str:
        if str(evt.get("type")) == "agent.spawned":
            sid = str(evt.get("session_id", ""))
            if sid not in sub_labels:
                sub_counter[0] += 1
                sub_labels[sid] = f"sub·{sub_counter[0]}"
        return ""

    def _print(line: str) -> None:
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            return
        _label(evt)
        ts = str(evt.get("ts", ""))[11:19]
        risk = str(evt.get("risk", "low"))
        rcolor = risk_color.get(risk, "white")
        tcolor, tlabel = type_glyph.get(str(evt.get("type", "")), ("dim", str(evt.get("type", ""))))
        line_summary = _summarise(evt)

        # if this event came from a sub-agent, indent + tag with ↳ sub·N
        payload = evt.get("payload") or {}
        parent = ""
        if isinstance(payload, dict):
            parent = str(payload.get("parent_session_id") or "")
        sid = str(evt.get("session_id", ""))
        sub_tag = ""
        indent = ""
        if parent:
            tag = sub_labels.get(sid, "sub")
            sub_tag = f" [magenta]↳ {tag}[/magenta]"
            indent = "  "

        console.print(
            f"{indent}  [dim]{ts}[/dim]  "
            f"[{rcolor}]{risk:<8}[/{rcolor}]  "
            f"[{tcolor}]{tlabel:<22}[/{tcolor}]"
            f"{sub_tag}  "
            f"{line_summary}",
        )

    # legend printed once before the stream starts
    legend = (
        "[dim]legend:[/dim]  "
        "[green]✓ allowed[/green]   "
        "[yellow]? ask[/yellow]   "
        "[bold red]✗ BLOCKED[/bold red]   "
        "[magenta]✗ scope[/magenta]   "
        "[magenta]↳ sub-agent[/magenta]"
    )
    console.print(legend)
    console.print()

    # Initial drain
    with p.open() as f:
        for line in f:
            _print(line.strip())

    if not follow:
        return

    # Tail: re-open and seek to end, poll for new lines.
    import time
    with p.open() as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            _print(line.strip())


# --------------------------------------------------------------------------
# audit verify / show
# --------------------------------------------------------------------------

@audit_app.command("verify")
def audit_verify(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l"),
    ] = None,
) -> None:
    """Walk the HMAC chain. Reports any tampered or missing entries."""
    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log:[/yellow] {p}")
        raise typer.Exit(code=1)
    total, failures = verify_chain(p, _hmac_key())
    if failures:
        console.print(f"[red]chain BROKEN[/red]: {len(failures)} of {total} entries fail")
        console.print(f"  failed line numbers: {failures[:20]}")
        raise typer.Exit(code=2)
    console.print(f"[green]chain intact[/green]: {total} entries verified.")


@audit_app.command("show")
def audit_show(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l"),
    ] = None,
    last: Annotated[
        int,
        typer.Option("--last", "-n", help="how many tool calls to show"),
    ] = 30,
    only: Annotated[
        str | None,
        typer.Option(
            "--only",
            help="filter by verdict: 'blocked', 'allowed', 'ask', 'scope'",
        ),
    ] = None,
    raw: Annotated[
        bool,
        typer.Option(
            "--raw",
            help="show every audit event separately instead of pairing "
                 "tool.attempted with its verdict",
        ),
    ] = False,
    project: Annotated[
        Path | None,
        typer.Option(
            "--project", "-P",
            help="filter to events whose cwd is inside this directory "
                 "(uses the cwd recorded by the Claude Code hook adapter)",
        ),
    ] = None,
    sub_only: Annotated[
        bool,
        typer.Option(
            "--sub", help="show only events from spawned sub-agents",
        ),
    ] = False,
) -> None:
    """Pretty-print recent gate decisions.

    By default each tool call is rendered as ONE row: the command/path
    that was attempted, the risk, the verdict, the plain-English reason.
    Use --raw to see every audit event separately (for debugging).
    Use --project <dir> to scope to a single repo. Use --sub to show
    only sub-agent (Task-spawned) events.
    """
    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log:[/yellow] {p}")
        raise typer.Exit(code=1)
    with p.open() as f:
        events = [json.loads(line) for line in f if line.strip()]

    # filters at the event level (applied before pairing)
    if project is not None:
        proj = str(project.expanduser().resolve())
        def _in_project(e: dict[str, Any]) -> bool:
            cwd = (e.get("payload") or {}).get("cwd") or ""
            return isinstance(cwd, str) and (
                cwd == proj or cwd.startswith(proj + "/") or cwd.startswith(proj + "\\")
            )
        events = [e for e in events if _in_project(e)]
    if sub_only:
        def _is_sub(e: dict[str, Any]) -> bool:
            p_ = (e.get("payload") or {}).get("parent_session_id")
            return bool(p_)
        events = [e for e in events if _is_sub(e)]

    risk_style = {
        "low": "green",
        "medium": "cyan",
        "high": "yellow",
        "critical": "bold red",
    }
    verdict_glyph = {
        "verdict.allowed":         ("green",    "✓ allow"),
        "verdict.blocked":         ("bold red", "✗ block"),
        "verdict.scope_violation": ("magenta",  "✗ scope"),
        "verdict.ask":             ("yellow",   "? ask "),
    }

    out = Console()
    table = Table(
        show_header=True, header_style="dim",
        box=None, pad_edge=False, show_lines=False,
    )

    if raw:
        # Per-event view (legacy / debug)
        type_label = {
            "session.start":          ("cyan",     "▸ session start"),
            "session.end":            ("cyan",     "◂ session end"),
            "agent.spawned":          ("cyan",     "▸ spawn"),
            "agent.closed":           ("cyan",     "◂ close"),
            "tool.attempted":         ("dim",      "· attempt"),
            "tool.completed":         ("green",    "✓ completed"),
            "tool.errored":           ("red",      "✗ errored"),
            **{k: v for k, v in verdict_glyph.items()},
        }
        table.add_column("time", style="dim", no_wrap=True, width=8)
        table.add_column("risk", no_wrap=True, width=8)
        table.add_column("event", no_wrap=True, width=18)
        table.add_column("tool", no_wrap=True, max_width=14)
        table.add_column("what / reason", no_wrap=False)
        for evt in events[-last:]:
            etype = str(evt.get("type", ""))
            if only and only not in etype:
                continue
            payload = evt.get("payload") or {}
            tool = str(payload.get("tool_name") or "—")
            risk = str(evt.get("risk", "low"))
            rcolor = risk_style.get(risk, "white")
            tcolor, tlabel = type_label.get(etype, ("dim", etype))
            ap = payload.get("args_preview") or {}
            piece = ""
            if isinstance(ap, dict):
                v = ap.get("command") or ap.get("path") or ap.get("file_path") or ""
                if isinstance(v, str):
                    piece = v.replace("\n", " ")[:80]
            reason = payload.get("reason") or payload.get("risk_reason") or ""
            text = piece + (f"  [dim italic]— {reason}[/dim italic]" if reason else "")
            table.add_row(
                str(evt.get("ts", ""))[11:19],
                f"[{rcolor}]{risk}[/{rcolor}]",
                f"[{tcolor}]{tlabel}[/{tcolor}]",
                tool, text,
            )
        out.print(table)
        return

    # Paired view (default): one row per tool call, attempt + verdict joined.
    table.add_column("time", style="dim", no_wrap=True, width=8)
    table.add_column("verdict", no_wrap=True, width=8)
    table.add_column("risk", no_wrap=True, width=8)
    table.add_column("tool", no_wrap=True, max_width=18)
    table.add_column("what was tried", no_wrap=False, ratio=2)
    table.add_column("why", style="dim italic", no_wrap=False, ratio=2)

    # Build a session_id → short label map so sub-agents have a readable
    # identity in the rendered table. ses-foo-1234 → "sub·1234".
    session_labels: dict[str, str] = {}
    spawn_count = 0
    for evt in events:
        if evt.get("type") == "agent.spawned":
            sid = str(evt.get("session_id", ""))
            spawn_count += 1
            session_labels[sid] = f"sub·{spawn_count}"

    pairs: list[dict[str, Any]] = []
    pending: dict[str, Any] | None = None
    for evt in events:
        etype = str(evt.get("type", ""))
        if etype == "tool.attempted":
            pending = evt
            continue
        if etype.startswith("verdict."):
            row = {
                "ts": evt.get("ts", ""),
                "verdict": etype,
                "risk": evt.get("risk", "low"),
                "session_id": evt.get("session_id", ""),
                "agent_id": evt.get("agent_id", ""),
                "payload_attempt": (pending or {}).get("payload") or {},
                "payload_verdict": evt.get("payload") or {},
            }
            pairs.append(row)
            pending = None

    if only:
        pairs = [r for r in pairs if only in r["verdict"]]

    rows = pairs[-last:]
    if not rows:
        out.print(f"[dim]no tool calls match.[/dim] log: {p}")
        return

    has_subs = any(
        (r["payload_verdict"].get("parent_session_id")
         or r["payload_attempt"].get("parent_session_id"))
        for r in rows
    )

    for r in rows:
        risk = str(r["risk"])
        rcolor = risk_style.get(risk, "white")
        vcolor, vlabel = verdict_glyph.get(str(r["verdict"]), ("white", str(r["verdict"])))
        attempt = r["payload_attempt"] or {}
        verdict = r["payload_verdict"] or {}
        tool = str(attempt.get("tool_name") or verdict.get("tool_name") or "—")
        ap = attempt.get("args_preview") or {}
        what = ""
        if isinstance(ap, dict):
            v = ap.get("command") or ap.get("path") or ap.get("file_path") or ""
            if isinstance(v, str):
                what = v.replace("\n", " ")[:120]
        reason = (verdict.get("reason") or verdict.get("risk_reason")
                  or attempt.get("risk_reason") or "")
        if isinstance(reason, str):
            reason = reason[:140]

        # sub-agent decoration — visible by default
        parent = (verdict.get("parent_session_id")
                  or attempt.get("parent_session_id") or "")
        sub_label = session_labels.get(str(r["session_id"]), "")
        if parent and sub_label:
            tool_cell = f"  [magenta]↳ {sub_label}[/magenta]  [dim]{tool}[/dim]"
        elif parent:
            tool_cell = f"  [magenta]↳ sub[/magenta]  [dim]{tool}[/dim]"
        else:
            tool_cell = tool

        table.add_row(
            str(r["ts"])[11:19],
            f"[{vcolor}]{vlabel}[/{vcolor}]",
            f"[{rcolor}]{risk}[/{rcolor}]",
            tool_cell, what, str(reason),
        )

    # legend printed ABOVE the table so the symbols are obvious
    legend_bits = [
        "[green]✓ allow[/green]",
        "[yellow]? ask[/yellow]",
        "[bold red]✗ block[/bold red]",
        "[magenta]✗ scope[/magenta]",
    ]
    if has_subs:
        legend_bits.append("[magenta]↳[/magenta] sub-agent (Task)")
    out.print("[dim]legend:[/dim]  " + "   ".join(legend_bits))
    out.print()
    out.print(table)

    counts = {"allow": 0, "block": 0, "ask  ": 0, "scope": 0}
    for r in rows:
        v = str(r["verdict"])
        if v == "verdict.allowed": counts["allow"] += 1
        elif v == "verdict.blocked": counts["block"] += 1
        elif v == "verdict.ask": counts["ask  "] += 1
        elif v == "verdict.scope_violation": counts["scope"] += 1
    sub_n = sum(
        1 for r in rows
        if (r["payload_verdict"].get("parent_session_id")
            or r["payload_attempt"].get("parent_session_id"))
    )
    parts = [f"{k.strip()}={v}" for k, v in counts.items() if v]
    if sub_n:
        parts.append(f"sub-agent={sub_n}")
    summary = "  ".join(parts)
    out.print(f"[dim]{len(rows)} tool call(s) · {summary} · log: {p}[/dim]")


# --------------------------------------------------------------------------
# tree
# --------------------------------------------------------------------------

@app.command(hidden=True)
def tree(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l", help="path to the audit log"),
    ] = None,
    snapshot: Annotated[
        bool,
        typer.Option("--snapshot", help="one-shot render of the current tree"),
    ] = False,
    live: Annotated[
        bool,
        typer.Option("--live", help="live-update the tree as new audit events arrive"),
    ] = False,
) -> None:
    """Render the delegation tree from an audit log (snapshot or live)."""
    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log:[/yellow] {p}")
        raise typer.Exit(code=1)
    if live and snapshot:
        console.print("[red]choose one of --snapshot or --live[/red]")
        raise typer.Exit(code=1)
    # Default to snapshot when neither flag is given.
    if live:
        render_tree_live(p)
    else:
        render_tree_static(p)


# --------------------------------------------------------------------------
# doctor — install diagnostic
# --------------------------------------------------------------------------

@app.command()
def doctor(
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="path to quill config"),
    ] = None,
) -> None:
    """Verify the install: config, audit log, key, hook, upstreams.

    Prints one line per check (PASS / WARN / FAIL) with a remediation
    hint for anything that needs attention. Exits 1 if any FAIL was hit
    so this can be used in scripts.
    """
    out = Console()  # use stdout, not stderr — script-friendly
    report = run_doctor(config_path=config_path)
    out.print()
    out.print("[bold]quill doctor[/bold]")
    out.print()
    name_width = max(len(r.name) for r in report.results) + 2
    for r in report.results:
        out.print(f"  {r.status}  [bold]{r.name:<{name_width}}[/bold] {r.detail}")
        if r.fix and r.status != "[green]PASS[/green]":
            out.print(f"        [dim]→ {r.fix}[/dim]")
    out.print()
    if report.has_failures:
        out.print("[red]some checks failed.[/red]  fix the FAILs above and re-run.")
        raise typer.Exit(code=1)
    if report.has_warnings:
        out.print("[yellow]all checks passed (with warnings).[/yellow]  see hints above.")
    else:
        out.print("[green]all checks passed.[/green]")


# --------------------------------------------------------------------------
# claude-hook  (Claude Code PreToolUse adapter)
# --------------------------------------------------------------------------

@app.command("claude-hook", hidden=True)
def claude_hook() -> None:
    """Run as Claude Code's PreToolUse hook.

    Wired into ~/.claude/settings.json so every Claude Code tool call
    (Bash, Edit, Write, ...) is gated by Quill before it executes.
    Reads JSON on stdin, writes JSON on stdout, exits 0.

    Install with:  quill claude-hook-install
    """
    raise typer.Exit(code=cc_adapter.main())


@app.command("claude-hook-install", hidden=True)
def claude_hook_install(
    settings_path: Annotated[
        Path | None,
        typer.Option(
            "--settings",
            help="path to Claude Code settings.json (default: ~/.claude/settings.json)",
        ),
    ] = None,
    matcher: Annotated[
        str,
        typer.Option(
            "--matcher",
            help="which built-in tools to gate (Claude Code matcher syntax)",
        ),
    ] = "Bash|Edit|Write|NotebookEdit",
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="hook timeout in seconds"),
    ] = 10,
) -> None:
    """Idempotently merge the Quill hook into Claude Code's settings.json.

    Safe to re-run; if Quill is already installed at this matcher, it does
    nothing.
    """
    p, already = cc_adapter.install_into_settings(
        settings_path, matcher=matcher, timeout=timeout,
    )
    if already:
        console.print(f"[dim]already installed in[/dim] {p}")
    else:
        console.print(f"[green]installed[/green] in {p}")
        console.print("  Restart Claude Code to pick up the new hook.")
    console.print(f"  matcher: [bold]{matcher}[/bold]")
    console.print(f"  audit log: {default_audit_path()}")


# --------------------------------------------------------------------------
# telemetry — opt-in anonymous aggregate usage
# --------------------------------------------------------------------------

@telemetry_app.command("status")
def telemetry_status() -> None:
    """Show whether telemetry is opted-in, and where state lives."""
    s = tel.TelemetryState.load()
    out = Console()
    out.print(f"  install_id : [dim]{s.install_id}[/dim]")
    out.print(f"  opted_in   : [{'green' if s.opted_in else 'yellow'}]"
              f"{s.opted_in}[/]")
    out.print(f"  asked      : {s.asked} {('@ ' + s.asked_at) if s.asked_at else ''}")
    out.print(f"  endpoint   : {s.endpoint}")
    out.print(f"  state file : {tel._state_path()}")


@telemetry_app.command("on")
def telemetry_on() -> None:
    """Opt in to anonymous aggregate telemetry."""
    s = tel.opt_in()
    Console().print(
        f"[green]telemetry on[/green]. install_id: [dim]{s.install_id}[/dim]\n"
        "  Inspect what gets sent at any time:  quill telemetry show\n"
        "  Turn off:                            quill telemetry off",
    )


@telemetry_app.command("off")
def telemetry_off() -> None:
    """Opt out of telemetry (or stay opted-out)."""
    tel.opt_out()
    Console().print("[yellow]telemetry off.[/yellow]  no events will be sent.")


@telemetry_app.command("show")
def telemetry_show(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l", help="audit log to summarise"),
    ] = None,
) -> None:
    """Print the JSON Quill *would* send.

    This is the only thing that ever leaves your machine. Inspect it
    before opting in if you want to verify the privacy contract holds.
    """
    s = tel.TelemetryState.load()
    p = log_path or default_audit_path()
    aggregate: dict[str, object] = {}
    if p.exists():
        events = []
        with p.open() as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        aggregate = tel.aggregate_events(events)
    out = Console()
    out.print(tel.preview_event_for_user(s, aggregate))


# --------------------------------------------------------------------------
# journal — write a session log to the AgentOS vault
# --------------------------------------------------------------------------

@journal_app.command("save")
def journal_save(
    transcript: Annotated[
        Path | None,
        typer.Option(
            "--transcript",
            help="path to the Claude Code transcript JSONL (read from "
                 "stdin's transcript_path if not given)",
        ),
    ] = None,
    sessions_dir: Annotated[
        Path | None,
        typer.Option(
            "--out", help="vault Sessions/ directory (default: "
                          "~/agentbrain/AgentOS-Vault/ClaudeCode/Sessions/)",
        ),
    ] = None,
) -> None:
    """Render an auto-summary of a Claude Code transcript to the vault.

    Designed to be called from a SessionEnd hook. When called by the
    hook, Claude Code passes the transcript path on stdin as JSON.
    """
    if transcript is None:
        try:
            payload = json.loads(sys.stdin.read() or "{}")
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            tp = payload.get("transcript_path")
            if isinstance(tp, str) and tp:
                transcript = Path(tp).expanduser()
    if transcript is None:
        Console(stderr=True).print(
            "[red]quill journal save[/red]: no --transcript and no "
            "transcript_path on stdin.",
        )
        raise typer.Exit(code=1)

    out = sessions_dir or journal_mod.DEFAULT_VAULT_SESSIONS
    written = journal_mod.save_from_transcript(transcript)
    Console().print(f"[green]wrote[/green] {written}")


# --------------------------------------------------------------------------
# watch — live observability dashboard
# --------------------------------------------------------------------------

@app.command("watch")
def watch(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l", help="audit log to stream"),
    ] = None,
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="local HTTP port (default: 9099)"),
    ] = watch_mod.DEFAULT_PORT,
    no_browser: Annotated[
        bool,
        typer.Option("--no-browser", help="don't auto-open the browser"),
    ] = False,
    terminal: Annotated[
        bool,
        typer.Option(
            "--terminal", "-t",
            help="spawn a Terminal window running `quill tree --live` "
                 "instead of the browser dashboard (macOS only)",
        ),
    ] = False,
    once: Annotated[
        bool,
        typer.Option(
            "--once",
            help="if a Quill watcher is already running, exit silently. "
                 "Useful in SessionStart hooks so windows don't stack.",
        ),
    ] = False,
    daemon: Annotated[
        bool,
        typer.Option(
            "--daemon",
            help="start the BROWSER dashboard as a detached background "
                 "process and return immediately. Idempotent.",
        ),
    ] = False,
    daemon_child: Annotated[
        bool,
        typer.Option(
            "--daemon-child",
            help="(internal) the actual daemon process — runs the server "
                 "and writes the PID file. Spawned by --daemon.",
            hidden=True,
        ),
    ] = False,
    browser: Annotated[
        bool,
        typer.Option(
            "--browser",
            help="use the localhost browser dashboard instead of the "
                 "in-terminal TUI. Default is now the TUI.",
        ),
    ] = False,
) -> None:
    """In-terminal live dashboard of every audit event as it's signed.

    By default `quill watch` opens a beautiful TUI in the same terminal —
    no separate browser tab, no port to remember. Use --browser for the
    old localhost HTTP dashboard, --daemon to run that browser dashboard
    in the background.
    """
    p = log_path or default_audit_path()

    if terminal:
        _spawn_terminal_tree(p, once=once)
        return

    if daemon_child:
        # We ARE the browser-dashboard daemon. Run with PID-file management.
        watch_mod.serve(p, port=port, open_browser=False, write_pid_file=True)
        return

    if daemon:
        pid, bound_port = watch_mod.ensure_daemon(
            p, port=port, open_browser=False,
        )
        url = f"http://127.0.0.1:{bound_port}/"
        Console().print(
            f"  [green]quill watch (browser) is running[/green] at [bold]{url}[/bold]"
            f"  [dim](pid {pid})[/dim]\n"
            "  daemon survives terminal close. stop with: [bold]quill stop[/bold]",
        )
        if not no_browser:
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:  # noqa: BLE001
                pass
        return

    if browser:
        if once and _watcher_already_running(port):
            return
        watch_mod.serve(p, port=port, open_browser=not no_browser)
        return

    # Default: in-terminal TUI. Lives in this terminal until `q`.
    from quill.tui import run_tui
    run_tui(p)


@app.command("stop")
def stop_daemon() -> None:
    """Stop the background watch daemon if one is running."""
    ok, msg = watch_mod.stop_daemon()
    Console().print(("[green]" if ok else "[dim]") + msg + ("[/green]" if ok else "[/dim]"))


def _watcher_already_running(port: int) -> bool:
    """Cheap probe: bind-check the port. If something is listening, assume
    it's a prior `quill watch` so the SessionStart hook doesn't stack."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except OSError:
        return False


def _spawn_terminal_tree(log_path: Path, *, once: bool) -> None:
    """Open a new Terminal.app window running `quill tree --live <log>`.

    macOS-only via osascript. If `once` is set, the SessionStart hook
    semantics: don't stack. We tag the window title with a sentinel so a
    second invocation can detect-and-skip.
    """
    if sys.platform != "darwin":
        Console().print(
            "  [yellow]--terminal currently macOS-only.[/yellow]\n"
            f"  Run this in a side terminal: [bold]quill tree --live --log {log_path}[/bold]",
        )
        return

    import subprocess
    sentinel = "QUILL_TREE_LIVE"
    if once:
        # Already-open detection: AppleScript looks for a window with the sentinel.
        check = subprocess.run(
            ["osascript", "-e",
             'tell application "Terminal" to '
             'get count of (windows whose name contains "' + sentinel + '")'],
            capture_output=True, text=True, check=False,
        )
        if (check.stdout or "").strip().isdigit() and int(check.stdout.strip()) > 0:
            return  # already showing

    cmd = (
        f'echo "[{sentinel}]"; export PS1="" ; '
        f'quill tree --live --log {log_path}'
    )
    osa = (
        f'tell application "Terminal" to do script "{cmd}"\n'
        f'tell application "Terminal" to set custom title of front window to '
        f'"{sentinel} · quill tree"\n'
    )
    try:
        subprocess.run(["osascript", "-e", osa], check=False, capture_output=True)
        Console().print(f"  [green]opened[/green] Terminal window: quill tree --live")
    except Exception as e:  # noqa: BLE001
        Console().print(f"  [yellow]could not spawn Terminal:[/yellow] {e}")


# --------------------------------------------------------------------------
# version
# --------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Print the quill version."""
    console.print(f"quill {__version__}")


def main() -> None:  # entry point for the [project.scripts] hook
    app()


if __name__ == "__main__":
    main()
