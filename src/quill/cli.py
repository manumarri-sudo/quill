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
from quill.audit import AuditLog, verify_chain
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
from quill.proxy import QuillProxy, build_proxy_server
from quill.tree import render_tree_live, render_tree_static

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="quill: the pause button between AI agents and the things you can't undo.",
)
audit_app = typer.Typer(no_args_is_help=True, help="audit-log subcommands.")
app.add_typer(audit_app, name="audit")

console = Console(stderr=True)


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
# init
# --------------------------------------------------------------------------

@app.command()
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

@app.command()
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
                # Run the FastMCP server over stdio so Claude Code can connect.
                server = build_proxy_server(proxy)
                await server.run_stdio_async()

    try:
        anyio.run(_run)
    except QuillError as e:
        console.print(f"[red]quill error:[/red] {e}")
        raise typer.Exit(code=1) from e


# --------------------------------------------------------------------------
# tail
# --------------------------------------------------------------------------

@app.command()
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

    glyph = {
        "session.start": ("cyan", "▸"),
        "tool.attempted": ("dim", "·"),
        "tool.completed": ("green", "✓"),
        "tool.errored": ("red", "✗"),
        "verdict.allowed": ("green", "·"),
        "verdict.blocked": ("red", "✗"),
        "verdict.scope_violation": ("red", "✗"),
    }

    def _print(line: str) -> None:
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            return
        color, g = glyph.get(evt.get("type", ""), ("dim", "·"))
        ts = evt.get("ts", "")[11:19]
        action = evt.get("payload", {}).get("tool_name") or evt.get("payload", {}).get("intent", "")
        risk = evt.get("risk", "")
        console.print(
            f"  [dim]{ts}[/dim]  [{color}]{g} {evt.get('type', ''):24}[/{color}]  "
            f"[dim]{risk:9}[/dim]  {action}",
        )

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
    last: Annotated[int, typer.Option("--last", "-n")] = 50,
) -> None:
    """Pretty-print the most recent audit entries."""
    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log:[/yellow] {p}")
        raise typer.Exit(code=1)
    with p.open() as f:
        lines = f.readlines()[-last:]
    table = Table(show_header=True, header_style="dim")
    table.add_column("ts", style="dim", no_wrap=True)
    table.add_column("type")
    table.add_column("risk", style="dim")
    table.add_column("action")
    for raw in lines:
        try:
            evt = json.loads(raw)
        except json.JSONDecodeError:
            continue
        action = evt.get("payload", {}).get("tool_name") or evt.get("payload", {}).get("intent", "")
        table.add_row(
            evt.get("ts", "")[11:19],
            evt.get("type", ""),
            evt.get("risk", ""),
            str(action),
        )
    console.print(table)


# --------------------------------------------------------------------------
# tree
# --------------------------------------------------------------------------

@app.command()
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
