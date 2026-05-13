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

import contextlib
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

import anyio
import typer
from rich.console import Console
from rich.table import Table

from quill import decay as decay_mod
from quill import journal as journal_mod
from quill import telemetry as tel
from quill import watch as watch_mod
from quill._version import __version__
from quill.adapters import claude_code as cc_adapter
from quill.audit import AuditLog, verify_chain
from quill.config import (
    default_audit_path,
    default_config_path,
    load_config,
    render_starter_config,
)
from quill.doctor import run_doctor
from quill.errors import ConfigError, QuillError
from quill.policy import SessionIntent
from quill.prompt import Prompter
from quill.proxy import QuillProxy, build_proxy_server, run_stdio
from quill.tree import render_tree_live, render_tree_static

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,  # `quill` with no args runs `start`
    help="quill: the pause button between AI agents and the things you can't undo.\n\n"
         "  quill start      set up + open the dashboard (this is the only command most users need)\n"
         "  quill approve    go-ahead a blocked call (run from a notification)\n"
         "  quill watch      in-terminal live dashboard\n"
         "  quill audit      review what got blocked / allowed / asked\n"
         "  quill receipts   per-session did / changed / uncertain / to-verify\n"
         "  quill bridge     A2A handoff edges between agents\n"
         "  quill trifecta   exposure tracking (untrusted input + private data + exfil)\n"
         "  quill pins       tool description pins (anti-poisoning, anti-rug-pull)\n"
         "  quill approvals  list / revoke pending approval tokens\n"
         "  quill decay      permissions that erode without reinforcement\n"
         "  quill doctor     diagnose the install\n",
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
decay_app = typer.Typer(
    no_args_is_help=True,
    help="track permissions that erode without reinforcement (Permission Decay framework).",
)
app.add_typer(decay_app, name="decay")
journal_app = typer.Typer(no_args_is_help=True, help="session-journal subcommands.")
app.add_typer(journal_app, name="journal", hidden=True)
telemetry_app = typer.Typer(
    no_args_is_help=True,
    help="opt-in anonymous usage telemetry.",
)
app.add_typer(telemetry_app, name="telemetry", hidden=True)

receipts_app = typer.Typer(
    no_args_is_help=True,
    help="agent receipts: did / changed / uncertain / to-verify per session.",
)
app.add_typer(receipts_app, name="receipts")

bridge_app = typer.Typer(
    no_args_is_help=True,
    help="A2A bridge: handoff edges between agents (sub-agent spawns).",
)
app.add_typer(bridge_app, name="bridge")

trifecta_app = typer.Typer(
    no_args_is_help=True,
    help="exposure tracking: did this session see untrusted input + private data + an exfil vector?",
)
app.add_typer(trifecta_app, name="trifecta")

pins_app = typer.Typer(
    no_args_is_help=True,
    help="tool description pins: detect rug-pulls and tool-poisoning attacks.",
)
app.add_typer(pins_app, name="pins")

approvals_app = typer.Typer(
    no_args_is_help=True,
    help="one-shot approvals - list / revoke pending tokens.",
)
app.add_typer(approvals_app, name="approvals")

notify_app = typer.Typer(
    no_args_is_help=True,
    help="notification channels - test that your wiring actually delivers.",
)
app.add_typer(notify_app, name="notify")

trust_app = typer.Typer(
    no_args_is_help=True,
    help="trusted directories - downshift default Edit/Write risk to auto-allow inside listed paths. The fix for approval fatigue.",
)
app.add_typer(trust_app, name="trust")

suggestions_app = typer.Typer(
    no_args_is_help=True,
    help="review and promote learner-surfaced suggestions. Auto-tightenings already applied; loosenings stay pending until the operator promotes.",
)
app.add_typer(suggestions_app, name="suggestions")


@app.command("learn")
def learn_cmd(
    since_days: Annotated[
        int,
        typer.Option(
            "--since-days", "-d",
            help="window to analyse (0 = full history)",
        ),
    ] = 7,
    json_out: Annotated[
        bool,
        typer.Option("--json", help="emit suggestions as JSON for tooling"),
    ] = False,
) -> None:
    """Read the audit log and surface self-improvement suggestions.

    The audit log is the source of truth; this command turns it into
    prioritised, paste-able actions. Operator decides whether to apply
    each one. Quill never auto-applies learning to its own gate.

    Categories surfaced:
      - trust_scope candidates (the 991-asks-per-week problem)
      - decayed permissions (reaffirm or forget)
      - false_positive_override (repeat operator bypasses)
      - heavy_bash_pattern (frequent classifier hits)
      - silent_failure (e.g. stub journals from a broken parser)
    """
    from quill.learn import analyze
    suggestions, _ = analyze(since_days=since_days)

    if json_out:
        import json as _json
        out = [
            {
                "severity": s.severity, "category": s.category,
                "title": s.title, "rationale": s.rationale,
                "paste_command": s.paste_command,
                "evidence": list(s.evidence),
            }
            for s in suggestions
        ]
        print(_json.dumps(out, indent=2))
        return

    if not suggestions:
        console.print(
            f"[dim]no suggestions for the last {since_days}d.[/dim] "
            "Run with [bold]--since-days 0[/bold] for full history.",
        )
        return

    sev_color = {"high": "red", "medium": "yellow", "low": "dim"}
    console.print(
        f"[bold]quill learn[/bold] [dim]· "
        f"{len(suggestions)} suggestion(s) from the last "
        f"{since_days}d of audit data[/dim]\n",
    )
    for s in suggestions:
        color = sev_color.get(s.severity, "white")
        console.print(
            f"  [{color}]{s.severity:>6}[/{color}]  [bold]{s.title}[/bold]",
        )
        console.print(f"          [dim]{s.rationale}[/dim]")
        console.print(f"          [bold]apply:[/bold] {s.paste_command}")
        if s.evidence:
            console.print(
                f"          [dim]evidence: {', '.join(s.evidence)}[/dim]",
            )
        console.print()


@app.command("kpis")
def kpis_cmd(
    since_days: Annotated[
        int,
        typer.Option("--since-days", "-d", help="window (0 = full history)"),
    ] = 7,
) -> None:
    """Three KPIs that genuinely measure whether the gate is healthy.

    These are NOT framework name-drops. Each one was picked because
    your actual audit log can answer it concretely and because the
    optimisation direction is right (a quieter gate does NOT score
    higher; a gate that catches real things does).

      noise_ratio    = asks / max(real_blocks, 1)
                       How many friction prompts per real catch.
                       Healthy < 5. Loud 5-20. Broken > 20.

      taint_closures = absolute count of sessions that closed the
                       lethal trifecta (untrusted + private + exfil).
                       Normally 0. Non-zero = real exposure event.

      cascade_events = absolute count of one-parent-spawned-3+-subs
                       fan-out incidents. Each one is a blast-radius
                       review candidate.

    Plus context: the top blocked patterns (which classifier rules
    fired most), and the operator-bypass count (sparse data; reported
    as count, not ratio, until volume grows).
    """
    from quill.learn import analyze
    _, kpis = analyze(since_days=since_days)

    if kpis.n_events == 0:
        console.print(
            f"[dim]no audit data for the last {since_days}d.[/dim]",
        )
        return

    health_color = {
        "healthy": "green", "loud": "yellow", "broken": "red",
    }[kpis.health]

    window_label = "full history" if since_days == 0 else f"last {since_days}d"
    console.print(
        f"\n[bold]quill kpis[/bold] [dim]({window_label}, {kpis.n_events} events)[/dim]\n",
    )

    # Headline KPI
    console.print(
        f"  [bold]noise_ratio[/bold]    "
        f"[{health_color}]{kpis.noise_ratio:.1f}[/{health_color}]  "
        f"[dim]({kpis.n_asks} asks / max({kpis.n_blocks},1) real blocks  "
        f"->  {kpis.health})[/dim]",
    )

    closure_style = "red" if kpis.n_taint_closures > 0 else "dim"
    console.print(
        f"  [bold]taint_closures[/bold] "
        f"[{closure_style}]{kpis.n_taint_closures}[/{closure_style}]  "
        f"[dim]sessions that closed the lethal trifecta[/dim]",
    )

    cascade_style = "yellow" if kpis.n_cascade_events > 0 else "dim"
    console.print(
        f"  [bold]cascade_events[/bold] "
        f"[{cascade_style}]{kpis.n_cascade_events}[/{cascade_style}]  "
        f"[dim]one-parent -> 3+ sub-agents fan-outs[/dim]",
    )

    console.print(
        f"  [dim]operator_bypasses[/dim]  "
        f"{kpis.n_overrides}  [dim](approved one-shot via quill approve)[/dim]",
    )
    console.print()

    if kpis.top_blocked_patterns:
        table = Table(title="top blocked patterns", show_header=True)
        table.add_column("pattern", overflow="fold")
        table.add_column("hits", justify="right", style="red")
        for pat, n in kpis.top_blocked_patterns:
            table.add_row(pat[:60], str(n))
        console.print(table)

console = Console(stderr=True)


def _maybe_emit_telemetry(audit_path: Path) -> None:
    """Best-effort send of a session.summary if the user has opted in.

    Reads the audit log we just wrote, derives the aggregate, fires off the
    POST. Never raises - telemetry must not affect proxy correctness.
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
    except Exception:
        pass


def _hmac_key() -> bytes:
    """Load the HMAC signing key from ~/.quill/key, or generate on first run.

    File is mode 0o600. Document key rotation in SECURITY.md.

    First-run is race-safe: two concurrent hook subprocesses (which is the
    common case on a cold Claude Code start) used to both enter the
    else-branch, both `secrets.token_bytes(32)`, both write the file. The
    second writer overwrote the first, invalidating events the first had
    already signed and breaking the chain. We now use `O_CREAT | O_EXCL`:
    exactly one writer wins; the loser sees FileExistsError, falls back
    to read.
    """
    from quill.paths import default_path
    p = default_path("key", env_override="QUILL_KEY")
    # Fast path: key already exists.
    if p.exists():
        return p.read_bytes()
    p.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    try:
        # O_EXCL: fails if the file already exists. Only one process can
        # win this open() across concurrent invocations.
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Lost the race - read the winner's key.
        return p.read_bytes()
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


# --------------------------------------------------------------------------
# start - the front door. one command, sets up + opens dashboard.
# --------------------------------------------------------------------------

def _wizard_notifications(out: Console) -> None:
    """Interactive prompt: enable + test out-of-band notifications.

    Idempotent. If [notify] already exists in config.toml, just reports
    status. Non-TTY contexts skip silently. KeyboardInterrupt-safe.
    """
    import platform
    import tomllib

    cfg_path = default_config_path()
    if not cfg_path.exists():
        return  # quill init wasn't run yet; nothing to extend

    try:
        with cfg_path.open("rb") as f:
            raw = tomllib.load(f)
    except Exception:
        return

    if not sys.stdin.isatty():
        return  # non-interactive context (CI, piped input)

    if isinstance(raw.get("notify"), dict):
        out.print("  [green]✓[/green] notifications: configured "
                  "[dim](edit config.toml + run [bold]quill notify test[/bold] "
                  "to verify)[/dim]")
        return

    out.print()
    out.print("  [bold]want a heads-up when something gets blocked?[/bold]")
    out.print("  [dim]quill can fan a structured WHAT/WHY/TRY/APPROVE message "
              "out of the terminal.[/dim]")
    try:
        ans = typer.prompt(
            "  enable notifications? (Y/n)",
            default="Y", show_default=False,
        ).strip().lower()
    except (KeyboardInterrupt, EOFError):
        ans = "n"
    if ans == "n":
        return

    is_mac = platform.system() == "Darwin"
    enable_macos = is_mac
    notify_block = ["", "[notify]"]
    if is_mac:
        notify_block.append('macos = true                          # macOS '
                            "Notification Center")
        notify_block.append('sound = "Glass"')
    notify_block.append("on_blocked = true                     # critical-risk "
                        "denials fire")
    notify_block.append("on_ask = false                        # high-risk "
                        "ask-the-human events stay quiet")
    notify_block.append("# slack_webhook_url = \"https://hooks.slack.com/...\"")
    notify_block.append('# webhook_url = "https://your.endpoint/quill"')
    notify_block.append("")
    notify_block.append("# [notify.email]")
    notify_block.append('# smtp_host = "smtp.gmail.com"')
    notify_block.append('# smtp_port = 587')
    notify_block.append('# smtp_user = "you@example.com"')
    notify_block.append('# smtp_password_env = "QUILL_SMTP_PASS"')

    try:
        with cfg_path.open("a") as f:
            f.write("\n".join(notify_block) + "\n")
    except OSError:
        out.print("  [yellow]⚠[/yellow] could not write notify config; skipping")
        return

    if enable_macos:
        out.print("  [green]✓[/green] notifications: macOS Notification Center "
                  "[dim](Slack / email / webhook stubs commented in config.toml)[/dim]")
    else:
        out.print("  [green]✓[/green] notification stubs written "
                  "[dim](edit config.toml to enable Slack / email / webhook)[/dim]")

    # Step 3 in the researcher's flow: send a test notification immediately
    # so the user closes the "did it actually fire?" loop on first install.
    if not enable_macos:
        return
    try:
        ans = typer.prompt(
            "  send a test notification now? (Y/n)",
            default="Y", show_default=False,
        ).strip().lower()
    except (KeyboardInterrupt, EOFError):
        ans = "n"
    if ans == "n":
        return

    # Inline-fire the macOS channel synchronously (don't shell out to
    # `quill notify test` - that re-reads config; we're already in-process).
    from quill.notify import BlockMessage, NotifyConfig, _send_macos
    test_cfg = NotifyConfig(enabled=True, macos=True, sound="Glass", on_blocked=True)
    test_msg = BlockMessage(
        risk="critical", decision="blocked",
        tool_name="quill.start_wizard_test",
        args_preview={},
        what="quill is wired up",
        why="this is a self-test from quill start",
        try_instead="",
        approve_token="WIZARD",  # noqa: S106 - synthetic stub, never persisted
    )
    if _send_macos(test_cfg, test_msg):
        out.print("  [green]✓[/green] test banner fired "
                  "[dim](check Notification Center; Focus mode can suppress)[/dim]")
    else:
        out.print("  [yellow]⚠[/yellow] osascript reported failure "
                  "[dim](check System Settings → Notifications → Script Editor)[/dim]")


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

    This is the only command most users will ever run. Idempotent - safe
    to re-run; nothing gets duplicated. After this finishes, every Bash /
    Edit / Write / NotebookEdit call in your Claude Code session is gated
    by quill, signed into ~/.quill/audit.log.jsonl, and visible live in
    the dashboard.
    """
    out = Console()

    # Sweep orphan daemons/tree procs before doing setup. Common case:
    # smoke tests under /tmp left detached daemons; old sessions left
    # duplicate --daemon-child processes fighting for port 9099.
    reaped = watch_mod.reap_orphans()
    if reaped:
        for pid, reason in reaped:
            out.print(f"  [dim]reaped pid {pid}: {reason}[/dim]")

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
        out.print("        [yellow]→ restart Claude Code to pick up the new hook[/yellow]")

    # 2. Notifications wizard: pick channels + offer a self-test.
    # Idempotent - re-running detects an existing [notify] block and
    # prints status instead of re-asking.
    if not yes:
        _wizard_notifications(out)

    # 3. Telemetry one-time prompt
    state = tel.TelemetryState.load()
    if not state.asked and not yes:
        out.print()
        out.print("  [bold]help shape quill v0.2?[/bold]  share anonymous "
                  "aggregate stats - counts, risk distribution, namespaces.")
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
    out.print("  [dim]bookmark the dashboard URL - daemon survives terminal "
              "close. stop with: quill stop[/dim]")

    if not no_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass


# --------------------------------------------------------------------------
# night / day - overnight auto-approval for unattended agents
# --------------------------------------------------------------------------

@app.command("night")
def night_cmd(
    state_arg: Annotated[
        str,
        typer.Argument(
            help="on | off | status (default: on)",
            metavar="[on|off|status]",
        ),
    ] = "on",
    hours: Annotated[
        float,
        typer.Option(
            "--hours",
            "-H",
            help="auto-expiry in hours (default 12). only applies to `on`.",
        ),
    ] = 12.0,
) -> None:
    """toggle overnight mode - auto-approve HIGH-risk actions so unattended agents do not stall.

    CRITICAL actions (rm -rf, DROP TABLE, vercel --prod, git push --force,
    sudo, etc.) STILL gate. overnight mode trades attended HIGH-risk
    friction for sleep, never safety.

    flip on before bed:    quill night
    flip on for 4 hours:   quill night on --hours 4
    flip off in morning:   quill day
    check current state:   quill night status
    """
    from quill import overnight as ovn

    console = Console()
    cmd = (state_arg or "on").strip().lower()

    if cmd in ("on", ""):
        if hours <= 0 or hours > 24:
            console.print(
                "[red]--hours must be in (0, 24]. refusing to set a multi-day toggle - "
                "safety contract requires a bounded window.[/red]"
            )
            raise typer.Exit(2)
        state = ovn.turn_on(duration_hours=hours)
        console.print("[bold green]overnight mode ON[/bold green]")
        console.print(
            f"HIGH-risk Edit / Write / Bash etc. will auto-approve until [bold]{state.expires_at}[/bold]."
        )
        console.print(
            "CRITICAL actions (rm -rf, DROP TABLE, vercel --prod, sudo, force-push) "
            "still gate. sleep well."
        )
        console.print("[dim]run `quill day` to flip off sooner, or `quill night status` to check.[/dim]")
        return

    if cmd == "off":
        state = ovn.turn_off()
        still_active, still_reason = ovn.is_active_from_config()
        if still_active:
            console.print(
                f"[bold yellow]manual toggle off, but overnight is STILL active "
                f"({still_reason}).[/bold yellow]"
            )
            console.print(
                "[dim]edit ~/.quill/config.toml `[overnight] enabled = false` to fully disable, "
                "or wait for the window to close.[/dim]"
            )
        else:
            console.print("[bold yellow]overnight mode OFF[/bold yellow]. all gates restored.")
        if state.high_approved or state.critical_blocked:
            console.print(
                f"overnight recap: [bold]{state.high_approved}[/bold] HIGH auto-approved, "
                f"[bold]{state.critical_blocked}[/bold] CRITICAL still blocked."
            )
            console.print("[dim]run `quill audit show --since 12h` to review what was auto-approved.[/dim]")
        return

    if cmd == "status":
        state = ovn.load_state()
        active, reason = ovn.is_active_from_config()
        if active:
            console.print(f"[bold green]overnight mode ACTIVE[/bold green] ({reason})")
        else:
            console.print("[dim]overnight mode inactive[/dim]")
        console.print(
            f"counters this session: [bold]{state.high_approved}[/bold] HIGH auto-approved, "
            f"[bold]{state.critical_blocked}[/bold] CRITICAL blocked"
        )
        if state.expires_at:
            console.print(f"toggle auto-expires: {state.expires_at}")
        return

    console.print(
        f"[red]unknown: {state_arg!r}.[/red] use: [bold]on[/bold] | [bold]off[/bold] | [bold]status[/bold]"
    )
    raise typer.Exit(2)


@app.command("day")
def day_cmd() -> None:
    """flip overnight mode off. alias for `quill night off`."""
    from quill import overnight as ovn

    console = Console()
    state = ovn.turn_off()
    still_active, still_reason = ovn.is_active_from_config()
    if still_active:
        console.print(
            f"[bold yellow]manual toggle off, but overnight is STILL active "
            f"({still_reason}).[/bold yellow]"
        )
        console.print(
            "[dim]edit ~/.quill/config.toml `[overnight] enabled = false` to fully disable, "
            "or wait for the window to close.[/dim]"
        )
    else:
        console.print("[bold yellow]overnight mode OFF[/bold yellow]. all gates restored.")
    if state.high_approved or state.critical_blocked:
        console.print(
            f"overnight recap: [bold]{state.high_approved}[/bold] HIGH auto-approved, "
            f"[bold]{state.critical_blocked}[/bold] CRITICAL still blocked."
        )
        console.print("[dim]run `quill audit show --since 12h` to review what was auto-approved.[/dim]")


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
    console.print("then: [bold]quill start[/bold]")


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

    # Canonical vocabulary - must match audit_show + TUI + dashboard.
    # Five labels: allow / ask / block / scope / sub-agent; six glyphs:
    # ✓ ✗ ? ↳ ▸ · - that's the lexicon every Quill surface uses.
    risk_color = {
        "low": "green",
        "medium": "cyan",
        "high": "yellow",
        "critical": "bold red",
    }
    type_glyph = {
        "session.start": ("cyan",     "▸ session"),
        "session.end":   ("cyan",     "◂ session"),
        "agent.spawned": ("magenta",  "▸ spawn"),
        "agent.closed":  ("magenta",  "◂ close"),
        "tool.attempted": ("dim",     "· attempt"),
        "tool.completed": ("green",   "✓ done"),
        "tool.errored":   ("red",     "✗ error"),
        "verdict.allowed":         ("green",    "✓ allow"),
        "verdict.blocked":         ("bold red", "✗ block"),
        "verdict.scope_violation": ("magenta",  "✗ scope"),
        "verdict.ask":             ("yellow",   "? ask"),
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
            bits.append(f"[dim italic]- {reason}[/dim italic]")
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

        out.print(
            f"{indent}  [dim]{ts}[/dim]  "
            f"[{rcolor}]{risk:<8}[/{rcolor}]  "
            f"[{tcolor}]{tlabel:<14}[/{tcolor}]"
            f"{sub_tag}  "
            f"{line_summary}",
        )

    # Tail's output IS data - write to stdout so users can pipe.
    # The module-level `console` is stderr-only (for warnings); for
    # tail we want a fresh stdout console.
    out = Console()
    legend = (
        "[dim]legend:[/dim]  "
        "[green]✓ allow[/green]   "
        "[yellow]? ask[/yellow]   "
        "[bold red]✗ block[/bold red]   "
        "[magenta]✗ scope[/magenta]   "
        "[magenta]↳ sub-agent[/magenta]"
    )
    out.print(legend)
    out.print()

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
        console.print(
            "  if these failures pre-date quill 0.1.1, they may be from "
            "concurrent-write breaks fixed in 0.1.1.\n"
            "  to re-chain those entries: [bold]quill audit repair --legacy --yes[/bold]"
        )
        raise typer.Exit(code=2)
    console.print(f"[green]chain intact[/green]: {total} entries verified.")


@audit_app.command("export")
def audit_export(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l", help="audit log to export from"),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--out", "-o", help="output directory (default: ./quill-evidence-pack)"),
    ] = None,
    aiuc_1: Annotated[
        bool,
        typer.Option("--aiuc-1/--no-aiuc-1", help="include AIUC-1 controls"),
    ] = True,
    eu_ai_act: Annotated[
        bool,
        typer.Option(
            "--eu-ai-act-art-14/--no-eu-ai-act-art-14",
            help="include EU AI Act Art. 14 + Art. 12 controls",
        ),
    ] = True,
    fmt: Annotated[
        str,
        typer.Option(
            "--format", "-f",
            help="emit format: html | md | both (default: both)",
        ),
    ] = "both",
) -> None:
    """Export the audit log as a customer-shareable evidence pack.

    Maps Quill's audit-event taxonomy to AIUC-1 + EU AI Act Article 14
    (human oversight) + EU AI Act Article 12 (record-keeping). Emits
    Markdown + HTML; print the HTML to PDF via your browser (Cmd+P) for
    the executive deliverable. Zero new dependencies.

    The deliverable for the "AI Agent Risk Audit" SKU on Loomiq.
    """
    from quill.exports import aggregate, render_html, render_markdown

    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log:[/yellow] {p}")
        raise typer.Exit(code=1)

    standards: list[str] = []
    if eu_ai_act:
        standards += ["EU AI Act Art. 14", "EU AI Act Art. 12"]
    if aiuc_1:
        standards.append("AIUC-1")
    if not standards:
        console.print("[red]no standards selected - pass --aiuc-1 or "
                      "--eu-ai-act-art-14[/red]")
        raise typer.Exit(code=1)

    # Verify the chain so the export reports tamper-evidence status honestly.
    chain_failures: list[int] = []
    chain_total = 0
    try:
        chain_total, chain_failures = verify_chain(p, _hmac_key())
    except Exception:
        pass

    events: list[dict[str, Any]] = []
    with p.open() as f:
        for line in f:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
            except json.JSONDecodeError:
                continue

    report = aggregate(
        events,
        log_path=p,
        standards=standards,
        chain_total=chain_total,
        chain_failures=chain_failures,
    )

    out_dir = output_dir or Path.cwd() / "quill-evidence-pack"
    out_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    if fmt in ("md", "both"):
        md_path = out_dir / "audit-evidence.md"
        md_path.write_text(render_markdown(report))
        written.append(md_path)
    if fmt in ("html", "both"):
        html_path = out_dir / "audit-evidence.html"
        html_path.write_text(render_html(report))
        written.append(html_path)

    console.print(
        f"[green]exported[/green] {report.total_events} events · "
        f"{len(report.by_control)} controls · chain: {report.chain_status}",
    )
    for w in written:
        console.print(f"  [dim]wrote[/dim] {w}")
    if written and "html" in str(written[-1]):
        console.print(
            "  [dim]print the HTML to PDF via your browser (Cmd+P) for "
            "the executive deliverable.[/dim]",
        )


@audit_app.command("repair")
def audit_repair(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l"),
    ] = None,
    legacy: Annotated[
        bool,
        typer.Option(
            "--legacy",
            help="acknowledge this is for pre-0.1.1 concurrent-write breaks, not tampering.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="confirm rewrite of audit history."),
    ] = False,
) -> None:
    """Re-chain a log file whose chain was broken by a known-cause defect.

    This rewrites historical audit entries. It is the only quill command that
    modifies on-disk audit history. Refuses to run without --legacy --yes.
    Appends a chain.repaired event documenting the operation.
    """
    if not (legacy and yes):
        console.print(
            "[red]refusing to rewrite audit history.[/red]\n"
            "  this command modifies historical entries to recover from the "
            "concurrent-write defect fixed in 0.1.1.\n"
            "  pass [bold]--legacy --yes[/bold] to confirm you understand."
        )
        raise typer.Exit(code=2)

    import hashlib
    import hmac as hmac_mod

    from quill.audit import _canon

    p = log_path or default_audit_path()
    if not p.exists():
        console.print(f"[yellow]no log:[/yellow] {p}")
        raise typer.Exit(code=1)
    key = _hmac_key()
    total, failures = verify_chain(p, key)
    if not failures:
        console.print(f"[green]chain already intact[/green]: {total} entries.")
        return

    repaired_lines: list[int] = []
    new_lines: list[bytes] = []
    prev_mac_hex = ""
    with p.open("rb") as f:
        for i, raw in enumerate(f, start=1):
            try:
                evt = json.loads(raw)
            except json.JSONDecodeError:
                console.print(f"[red]line {i}: malformed JSON, leaving as-is[/red]")
                new_lines.append(raw)
                continue
            old_mac = evt.get("mac", "")
            evt["prev_mac"] = prev_mac_hex
            evt.pop("mac", None)
            new_mac = hmac_mod.new(key, _canon(evt), hashlib.sha256).hexdigest()
            evt["mac"] = new_mac
            new_lines.append(
                (json.dumps(evt, separators=(",", ":")) + "\n").encode("utf-8"),
            )
            if new_mac != old_mac:
                repaired_lines.append(i)
            prev_mac_hex = new_mac

    tmp = p.with_suffix(p.suffix + ".repair")
    tmp.write_bytes(b"".join(new_lines))
    tmp.chmod(0o600)
    tmp.replace(p)

    # Append a chain.repaired event so the operation itself is audited.
    with AuditLog(path=p, hmac_key=key) as log:
        log.emit(
            event_type="chain.repaired",
            session_id="quill-audit-repair",
            risk="high",
            payload={
                "by": "quill audit repair",
                "reason": "legacy-concurrent-write-break (pre-0.1.1)",
                "repaired_count": len(repaired_lines),
                "repaired_lines": repaired_lines[:50],
                "total_entries_before": total,
            },
        )
    console.print(
        f"[green]repaired[/green] {len(repaired_lines)} entries; "
        f"chain.repaired event appended.",
    )


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
    full: Annotated[
        bool,
        typer.Option(
            "--full",
            help="show full reason text wrapped across multiple lines. "
                 "Default is one-line-per-row with truncation.",
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
        # Per-event view (one row per audit event, no pairing).
        # Same vocabulary as the paired view + tail: ✓ allow / ? ask /
        # ✗ block / ✗ scope / ▸ spawn / ↳ sub.
        type_label = {
            "session.start":          ("cyan",     "▸ session"),
            "session.end":            ("cyan",     "◂ session"),
            "agent.spawned":          ("magenta",  "▸ spawn"),
            "agent.closed":           ("magenta",  "◂ close"),
            "tool.attempted":         ("dim",      "· attempt"),
            "tool.completed":         ("green",    "✓ done"),
            "tool.errored":           ("red",      "✗ error"),
            **{k: v for k, v in verdict_glyph.items()},
        }

        # Pre-pass to assign stable sub·N labels in spawn order.
        sub_labels: dict[str, str] = {}
        n = 0
        for evt in events:
            if evt.get("type") == "agent.spawned":
                sid = str(evt.get("session_id", ""))
                if sid and sid not in sub_labels:
                    n += 1
                    sub_labels[sid] = f"sub·{n}"

        table.add_column("time", style="dim", no_wrap=True, width=8)
        table.add_column("risk", no_wrap=True, width=8)
        table.add_column("event", no_wrap=True, width=14)
        table.add_column("tool", no_wrap=True, max_width=18)
        table.add_column("what / reason", no_wrap=False)
        for evt in events[-last:]:
            etype = str(evt.get("type", ""))
            if only and only not in etype:
                continue
            payload = evt.get("payload") or {}
            tool = str(payload.get("tool_name") or "-")
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
            text = piece + (f"  [dim italic]- {reason}[/dim italic]" if reason else "")

            # sub-agent decoration - same as the paired view
            parent = payload.get("parent_session_id") if isinstance(payload, dict) else ""
            sid = str(evt.get("session_id", ""))
            if parent and sid in sub_labels:
                tool_cell = f"[magenta]↳ {sub_labels[sid]}[/magenta]  [dim]{tool}[/dim]"
            elif parent:
                tool_cell = f"[magenta]↳ sub[/magenta]  [dim]{tool}[/dim]"
            else:
                tool_cell = tool

            table.add_row(
                str(evt.get("ts", ""))[11:19],
                f"[{rcolor}]{risk}[/{rcolor}]",
                f"[{tcolor}]{tlabel}[/{tcolor}]",
                tool_cell, text,
            )
        legend_bits = [
            "[green]✓ allow[/green]",
            "[yellow]? ask[/yellow]",
            "[bold red]✗ block[/bold red]",
            "[magenta]✗ scope[/magenta]",
            "[magenta]↳ sub-agent[/magenta]",
        ]
        out.print("[dim]legend:[/dim]  " + "   ".join(legend_bits))
        out.print()
        out.print(table)
        return

    # Paired view (default): one row per tool call, attempt + verdict joined.
    # Compact mode by default - single line per row, truncate. Use --full
    # for the wrapped multi-line view if you actually want all the prose.
    table.add_column("time", style="dim", no_wrap=True, width=8)
    table.add_column("verdict", no_wrap=True, width=8)
    table.add_column("risk", no_wrap=True, width=8)
    table.add_column("tool", no_wrap=True, max_width=18)
    if full:
        table.add_column("what was tried", no_wrap=False, ratio=2)
        table.add_column("why", style="dim italic", no_wrap=False, ratio=2)
    else:
        table.add_column("what was tried", no_wrap=True, max_width=44, overflow="ellipsis")
        table.add_column("why", style="dim italic", no_wrap=True, max_width=60, overflow="ellipsis")

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

    # Steel-blue accent for the "try instead" hint lane (delta convention,
    # matches every popular delta theme: Arctic Fox / Mantis Shrimp /
    # Tangara-chilensis). Distinct from coral block + amber ask.
    HINT = "#5E81AC"

    for r in rows:
        risk = str(r["risk"])
        rcolor = risk_style.get(risk, "white")
        vcolor, vlabel = verdict_glyph.get(str(r["verdict"]), ("white", str(r["verdict"])))
        attempt = r["payload_attempt"] or {}
        verdict = r["payload_verdict"] or {}
        tool = str(attempt.get("tool_name") or verdict.get("tool_name") or "-")
        ap = attempt.get("args_preview") or {}
        what = ""
        if isinstance(ap, dict):
            v = ap.get("command") or ap.get("path") or ap.get("file_path") or ""
            if isinstance(v, str):
                what = v.replace("\n", " ")
                if not full:
                    what = what[:80]

        # Split the new "<reason> · try instead: <suggestion>" format so the
        # suggestion can render on its own row underneath, in steel-blue.
        raw_reason = str(verdict.get("reason") or verdict.get("risk_reason")
                          or attempt.get("risk_reason") or "")
        suggestion = ""
        if " · try instead: " in raw_reason:
            short_reason, suggestion = raw_reason.split(" · try instead: ", 1)
        else:
            short_reason = raw_reason
        if not full:
            short_reason = short_reason[:60]

        # sub-agent decoration - visible by default
        parent = (verdict.get("parent_session_id")
                  or attempt.get("parent_session_id") or "")
        sub_label = session_labels.get(str(r["session_id"]), "")
        if parent and sub_label:
            tool_cell = f"[magenta]↳ {sub_label}[/magenta]  [dim]{tool}[/dim]"
        elif parent:
            tool_cell = f"[magenta]↳ sub[/magenta]  [dim]{tool}[/dim]"
        else:
            tool_cell = tool

        table.add_row(
            str(r["ts"])[11:19],
            f"[{vcolor}]{vlabel}[/{vcolor}]",
            f"[{rcolor}]{risk}[/{rcolor}]",
            tool_cell, what, short_reason,
        )
        # Conditional hint-lane row underneath. Only renders for blocked /
        # ask events that carry a paste-able suggestion. Steel-blue accent
        # (delta convention) makes the action visually distinct from the
        # event row's verdict color.
        if suggestion:
            sugg_text = suggestion if full else suggestion[:90]
            table.add_row(
                "", "", "", "",
                f"[#{HINT[1:]}]↪ try[/]",
                f"[#{HINT[1:]}]{sugg_text}[/]",
            )

    # legend printed ABOVE the table so the symbols are obvious
    legend_bits = [
        "[green]✓ allow[/green]",
        "[yellow]? ask[/yellow]",
        "[bold red]✗ block[/bold red]",
        "[magenta]✗ scope[/magenta]",
        f"[#{HINT[1:]}]↪ try[/]",
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
# doctor - install diagnostic
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
    out = Console()  # use stdout, not stderr - script-friendly

    # Sweep orphan daemons/tree procs as part of every doctor invocation.
    # This is the most reliable cleanup hook because users run doctor
    # when something feels off.
    reaped = watch_mod.reap_orphans()

    report = run_doctor(config_path=config_path)
    out.print()
    out.print("[bold]quill doctor[/bold]")
    out.print()
    name_width = max(len(r.name) for r in report.results) + 2
    for r in report.results:
        out.print(f"  {r.status}  [bold]{r.name:<{name_width}}[/bold] {r.detail}")
        if r.fix and r.status != "[green]PASS[/green]":
            out.print(f"        [dim]→ {r.fix}[/dim]")
    if reaped:
        out.print()
        out.print(f"  [dim]reaped {len(reaped)} orphan quill process(es):[/dim]")
        for pid, reason in reaped:
            out.print(f"    [dim]pid {pid}: {reason}[/dim]")
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


# --------------------------------------------------------------------------
# cursor-hook  (Cursor 1.7+ pre-tool-call adapter)
# --------------------------------------------------------------------------

@app.command("cursor-hook", hidden=True)
def cursor_hook() -> None:
    """Run as Cursor's pre-tool-call hook.

    Wired into ~/.cursor/hooks.json so every Cursor shell / MCP / file-read
    call is gated by Quill before it executes. Reads JSON on stdin, writes
    JSON on stdout (Cursor's `permission` shape, NOT Claude Code's).

    Install with:  quill cursor-hook-install
    """
    from quill.adapters import cursor as cursor_adapter
    raise typer.Exit(code=cursor_adapter.main())


@app.command("cursor-hook-install", hidden=True)
def cursor_hook_install(
    settings_path: Annotated[
        Path | None,
        typer.Option(
            "--settings",
            help="path to Cursor hooks.json (default: ~/.cursor/hooks.json)",
        ),
    ] = None,
) -> None:
    """Idempotently merge the Quill hook into Cursor's hooks.json.

    Wires beforeShellExecution + beforeMCPExecution + beforeReadFile to
    `quill cursor-hook`. Safe to re-run; if Quill is already wired, no-op.
    Requires Cursor 1.7+.
    """
    from quill.adapters import cursor as cursor_adapter
    p, already = cursor_adapter.install_into_settings(settings_path)
    if already:
        console.print(f"[dim]already installed in[/dim] {p}")
    else:
        console.print(f"[green]installed[/green] in {p}")
        console.print("  Restart Cursor to pick up the new hook.")


# --------------------------------------------------------------------------
# telemetry - opt-in anonymous aggregate usage
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
# journal - write a session log to the AgentOS vault
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

    written = journal_mod.save_from_transcript(transcript, sessions_dir=sessions_dir)
    Console().print(f"[green]wrote[/green] {written}")


# --------------------------------------------------------------------------
# watch - live observability dashboard
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
            help="(internal) the actual daemon process - runs the server "
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

    By default `quill watch` opens a beautiful TUI in the same terminal -
    no separate browser tab, no port to remember. Use --browser for the
    old localhost HTTP dashboard, --daemon to run that browser dashboard
    in the background.
    """
    p = log_path or default_audit_path()

    # The daemon-child path is the actual server process; never reap from
    # inside it (we'd kill ourselves) and never reap before serving.
    if daemon_child:
        # We ARE the browser-dashboard daemon. Run with PID-file management.
        watch_mod.serve(p, port=port, open_browser=False, write_pid_file=True)
        return

    # All other entry points sweep up orphans before doing anything. Keeps
    # the long-tail of stale --daemon-child and --tree procs from piling
    # up across sessions/smoke tests. Idempotent and silent on no-ops.
    reaped = watch_mod.reap_orphans()
    if reaped:
        for pid, reason in reaped:
            Console().print(f"  [dim]reaped pid {pid}: {reason}[/dim]")

    if terminal:
        _spawn_terminal_tree(p, once=once)
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
            except Exception:
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

    # The shell command runs inside Terminal's `do script` AppleScript
    # string, so every `"` in it has to be backslash-escaped or AppleScript
    # bombs with `syntax error: A “[” can’t go after this “"”`. That bug
    # made --terminal silently no-op for months; capture_output hid it.
    # We also `activate` Terminal so the new window comes to the foreground
    # - otherwise the spawned window opens behind the current app and the
    # user thinks nothing happened.
    # Trailing `; read` keeps the tab visible if quill tree crashes so the
    # error is debuggable instead of silently closing.
    cmd = (
        f'echo \\"[{sentinel}]\\"; export PS1=\\"\\" ; '
        f'quill tree --live --log {log_path}; '
        f'ec=$?; echo \\"\\"; echo \\"quill tree exited (code $ec). '
        f'press enter to close.\\"; read'
    )
    osa = (
        f'tell application "Terminal"\n'
        f'  activate\n'
        f'  set newTab to do script "{cmd}"\n'
        f'  set custom title of newTab to "{sentinel} · quill tree"\n'
        f'  set frontmost of (first window whose tabs contains newTab) to true\n'
        f'end tell\n'
    )
    try:
        r = subprocess.run(
            ["osascript", "-e", osa],
            check=False, capture_output=True, text=True,
        )
        if r.returncode == 0:
            Console().print("  [green]opened[/green] Terminal window: quill tree --live")
        else:
            err = (r.stderr or "").strip() or f"osascript exit {r.returncode}"
            Console().print(f"  [yellow]could not spawn Terminal:[/yellow] {err}")
    except Exception as e:
        Console().print(f"  [yellow]could not spawn Terminal:[/yellow] {e}")


# --------------------------------------------------------------------------
# decay - Permission Decay framework
# --------------------------------------------------------------------------

@decay_app.command("show")
def decay_show(
    all_: Annotated[
        bool,
        typer.Option("--all", help="show healthy permissions too, not just decayed/approaching"),
    ] = False,
) -> None:
    """List tracked permissions with decay status.

    A permission decays when it has not been used in
    `decay_after_days`. Decayed permissions are ignored at the gate
    (the default risk fires) until you run `quill decay reaffirm`.
    """
    out = Console()
    store = decay_mod.DecayStore.load()
    perms = store.all()
    if not perms:
        out.print("[dim]no tracked permissions yet.[/dim]")
        out.print("  permissions register the first time a config policy "
                  "override fires; check back after running Claude Code.")
        return

    decayed = sorted(store.decayed(), key=lambda p: p.age_days, reverse=True)
    approaching = sorted(store.approaching(), key=lambda p: p.days_left)
    healthy = [p for p in perms if not p.is_decayed
               and p not in approaching]

    if decayed:
        out.print(f"[bold red]decayed ({len(decayed)})[/bold red] "
                  "[dim]- action required[/dim]")
        t = Table(box=None, pad_edge=False, show_header=True, header_style="dim")
        t.add_column("kind", style="dim")
        t.add_column("pattern")
        t.add_column("age (d)", justify="right")
        t.add_column("window", justify="right")
        t.add_column("uses", justify="right")
        t.add_column("decay_action")
        for p in decayed:
            t.add_row(p.kind, p.pattern,
                      f"[red]{p.age_days}[/red]",
                      str(p.decay_after_days),
                      str(p.use_count), p.decay_action)
        out.print(t)
        out.print()

    if approaching:
        out.print(f"[yellow]approaching decay ({len(approaching)})[/yellow]")
        t = Table(box=None, pad_edge=False, show_header=True, header_style="dim")
        t.add_column("kind", style="dim")
        t.add_column("pattern")
        t.add_column("days left", justify="right")
        t.add_column("uses", justify="right")
        for p in approaching:
            t.add_row(p.kind, p.pattern,
                      f"[yellow]{p.days_left}[/yellow]",
                      str(p.use_count))
        out.print(t)
        out.print()

    if all_ and healthy:
        out.print(f"[green]healthy ({len(healthy)})[/green]")
        t = Table(box=None, pad_edge=False, show_header=True, header_style="dim")
        t.add_column("kind", style="dim")
        t.add_column("pattern")
        t.add_column("days left", justify="right")
        t.add_column("uses", justify="right")
        t.add_column("last use", style="dim")
        for p in healthy:
            t.add_row(p.kind, p.pattern,
                      f"[green]{p.days_left}[/green]",
                      str(p.use_count),
                      str(p.last_use)[:19])
        out.print(t)
    elif healthy and not all_:
        out.print(f"[dim]+ {len(healthy)} healthy permission(s) "
                  "(quill decay show --all to see)[/dim]")


@decay_app.command("reaffirm")
def decay_reaffirm(
    pattern: Annotated[str, typer.Argument(help="tool pattern to reaffirm")],
    kind: Annotated[
        str,
        typer.Option("--kind", help="permission kind (default: best-match policy)"),
    ] = "",
) -> None:
    """Bump a permission's last_reaffirmed timestamp without using it."""
    store = decay_mod.DecayStore.load()
    out = Console()
    if kind:
        p = store.reaffirm(kind, pattern)
        if p is None:
            out.print(f"[yellow]no permission found at {kind}:{pattern}[/yellow]")
            raise typer.Exit(code=1)
        out.print(f"[green]reaffirmed[/green] {p.key}  "
                  f"[dim](age 0d, {p.decay_after_days}d window)[/dim]")
        return
    # best-match: any kind matching the pattern
    matches = [p for p in store.all() if p.pattern == pattern]
    if not matches:
        out.print(f"[yellow]no permission found for pattern '{pattern}'[/yellow]")
        raise typer.Exit(code=1)
    for m in matches:
        store.reaffirm(m.kind, m.pattern)
    out.print(f"[green]reaffirmed[/green] {len(matches)} permission(s) "
              f"matching pattern '{pattern}'")


@decay_app.command("forget")
def decay_forget(
    pattern: Annotated[str, typer.Argument(help="tool pattern to drop")],
    kind: Annotated[str, typer.Option("--kind")] = "",
) -> None:
    """Drop a tracked permission entirely (re-registers on next use)."""
    store = decay_mod.DecayStore.load()
    out = Console()
    if kind:
        if store.forget(kind, pattern):
            out.print(f"[green]dropped[/green] {kind}:{pattern}")
        else:
            out.print(f"[yellow]no permission at {kind}:{pattern}[/yellow]")
            raise typer.Exit(code=1)
        return
    matches = [p for p in store.all() if p.pattern == pattern]
    for m in matches:
        store.forget(m.kind, m.pattern)
    out.print(f"[green]dropped[/green] {len(matches)} permission(s)")


# --------------------------------------------------------------------------
# version
# --------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Print the quill version."""
    console.print(f"quill {__version__}")


# --------------------------------------------------------------------------
# receipts - derive Agent Receipts from the audit log


@receipts_app.command("list")
def receipts_list(
    log_path: Annotated[
        Path | None,
        typer.Option("--log", "-l", help="audit log to derive from"),
    ] = None,
    last: Annotated[int, typer.Option("--last", help="show only last N sessions")] = 10,
) -> None:
    """List one Receipt per session in reverse chronological order."""
    from quill.receipt import derive_from_events, load_audit_events

    events = load_audit_events(log_path)
    if not events:
        console.print("[yellow]no audit events yet[/yellow]")
        raise typer.Exit(code=1)
    receipts = derive_from_events(events)
    ordered = sorted(
        receipts.values(),
        key=lambda r: r.opened_at or r.closed_at or "",
        reverse=True,
    )[:last]

    table = Table(title="agent receipts", show_lines=False)
    table.add_column("session", style="dim", no_wrap=True, width=10)
    table.add_column("opened", style="dim", no_wrap=True, width=20)
    table.add_column("calls", justify="right", width=6)
    table.add_column("interv.", justify="right", width=7)
    table.add_column("TDR", justify="right", width=5)
    table.add_column("intent / first did", overflow="fold")
    for r in ordered:
        first_did = r.intent or (r.did[0] if r.did else "")
        table.add_row(
            r.session_id[:8],
            (r.opened_at or "")[:19],
            str(r.tool_call_count),
            str(r.intervention_count),
            f"{r.tdr_contribution:.2f}",
            first_did[:60],
        )
    Console().print(table)


@receipts_app.command("show")
def receipts_show(
    session_id: Annotated[str, typer.Argument(help="session_id (or first 8 chars)")],
    log_path: Annotated[Path | None, typer.Option("--log", "-l")] = None,
) -> None:
    """Print one full Receipt as did / changed / uncertain / to_verify."""
    from quill.receipt import derive_from_events, load_audit_events

    events = load_audit_events(log_path)
    receipts = derive_from_events(events)
    matches = [r for r in receipts.values() if r.session_id.startswith(session_id)]
    if not matches:
        console.print(f"[red]no session matching[/red] {session_id}")
        raise typer.Exit(code=1)
    r = matches[0]
    out = Console()
    out.print(f"[bold]session[/bold] {r.session_id}")
    out.print(f"  opened: {r.opened_at or '(unknown)'}")
    out.print(f"  closed: {r.closed_at or '(open)'}")
    if r.intent:
        out.print(f"  intent: {r.intent}")
    out.print(f"  TDR={r.tdr_contribution:.2f}  trust_delta={r.trust_delta:+.2f}  "
              f"calls={r.tool_call_count}  interventions={r.intervention_count}")
    if r.did:
        out.print(f"\n[bold]did[/bold] ({len(r.did)})")
        for d in r.did:
            out.print(f"  ✓ {d}")
    if r.changed:
        out.print(f"\n[bold]changed[/bold] ({len(r.changed)})")
        for c in r.changed:
            out.print(f"  · {c}")
    if r.uncertain:
        out.print(f"\n[bold yellow]uncertain[/bold yellow] ({len(r.uncertain)})")
        for u in r.uncertain:
            out.print(f"  ? {u}")
    if r.to_verify:
        out.print(f"\n[bold red]to verify[/bold red] ({len(r.to_verify)})")
        for v in r.to_verify:
            out.print(f"  ! {v}")


# --------------------------------------------------------------------------
# bridge - A2A handoff edges


@bridge_app.command("show")
def bridge_show(
    log_path: Annotated[Path | None, typer.Option("--log", "-l")] = None,
    orphans_only: Annotated[bool, typer.Option("--orphans", help="show only unmatched handoffs")] = False,
) -> None:
    """List A2A handoff edges (out, in, orphan, cascade)."""
    from quill.bridge import fold_handoffs
    from quill.receipt import load_audit_events

    events = load_audit_events(log_path)
    handoffs = fold_handoffs(events)
    if not handoffs:
        console.print("[dim]no handoff events yet[/dim]")
        return
    table = Table(title="A2A bridge")
    table.add_column("payload_hash", style="dim", no_wrap=True, width=12)
    table.add_column("out → in", width=10)
    table.add_column("status", width=10)
    table.add_column("contract", overflow="fold")
    for h in handoffs.values():
        if orphans_only and not h.is_orphan:
            continue
        out_seen = "✓" if h.out_event else "·"
        in_count = len(h.in_events)
        status = "orphan" if h.is_orphan else ("cascade" if h.is_cascade else "ok")
        contract = ""
        if h.out_event:
            contract = str((h.out_event.get("payload") or {}).get("contract") or "")
        table.add_row(
            h.payload_hash[:12],
            f"{out_seen} → {in_count}",
            status,
            contract,
        )
    Console().print(table)


# --------------------------------------------------------------------------
# trifecta - has this session seen untrusted input + private data + an exfil
# vector all together? Internally called "taint" (security term-of-art); the
# public surface uses plain English.


@trifecta_app.command("show")
def trifecta_show(
    log_path: Annotated[Path | None, typer.Option("--log", "-l")] = None,
    closed_only: Annotated[bool, typer.Option("--closed", help="only sessions that crossed all three lines")] = False,
) -> None:
    """Per-session exposure: did the agent see untrusted input + private data
    + an exfiltration vector all in the same session? That's the worst-case
    prompt-injection scenario; two of three is recoverable.
    """
    from quill.receipt import load_audit_events
    from quill.taint import fold_audit_events

    events = load_audit_events(log_path)
    states = fold_audit_events(events)
    if not states:
        console.print("[dim]no exposure observations yet[/dim]")
        return
    table = Table(title="session exposure (untrusted input · private data · exfil vector)")
    table.add_column("session", style="dim", no_wrap=True, width=10)
    table.add_column("untrusted input", justify="center", width=15)
    table.add_column("private data", justify="center", width=14)
    table.add_column("exfil vector", justify="center", width=14)
    table.add_column("verdict")
    for sid, state in states.items():
        if closed_only and not state.trifecta_closed:
            continue
        flag_count = sum([
            state.has_seen_untrusted, state.has_accessed_private, state.can_exfiltrate,
        ])
        verdict = (
            "[red]all three[/red]" if state.trifecta_closed
            else f"[yellow]{flag_count}-of-3[/yellow]" if flag_count == 2
            else "[green]safe[/green]"
        )
        table.add_row(
            sid[:8],
            "yes" if state.has_seen_untrusted else "-",
            "yes" if state.has_accessed_private else "-",
            "yes" if state.can_exfiltrate else "-",
            verdict,
        )
    Console().print(table)


# --------------------------------------------------------------------------
# pins - tool description pinning (anti-tool-poisoning, anti-rug-pull)


@pins_app.command("list")
def pins_list(
    upstream: Annotated[str | None, typer.Option("--upstream", "-u")] = None,
) -> None:
    """List pinned tools. Pins are auto-recorded on first sight; new digests
    require explicit approval before the tool is re-advertised to the client.
    """
    from quill.pinning import PinStore

    store = PinStore.load()
    if not store.pins:
        console.print("[dim]no pins yet - pins are recorded on first sight of each tool[/dim]")
        return
    table = Table(title="tool pins")
    table.add_column("upstream", style="dim", no_wrap=True, width=14)
    table.add_column("tool", no_wrap=True, width=24)
    table.add_column("digest", style="dim", width=14)
    table.add_column("first seen", style="dim", width=20)
    table.add_column("approved by", width=16)
    table.add_column("status")
    for (up, name), pin in sorted(store.pins.items()):
        if upstream and up != upstream:
            continue
        status = "[red]revoked[/red]" if pin.revoked_at else "[green]active[/green]"
        table.add_row(
            up, name, pin.digest[:12] + "…",
            pin.first_seen[:19], pin.approved_by, status,
        )
    Console().print(table)


@pins_app.command("approve")
def pins_approve(
    upstream: Annotated[str, typer.Argument(help="upstream name (e.g. filesystem)")],
    tool_name: Annotated[str, typer.Argument(help="tool name (e.g. read_file)")],
    digest: Annotated[str, typer.Argument(help="full SHA-256 digest from the refusal message")],
) -> None:
    """Approve a new digest for a tool. Use after a legitimate upstream update
    or after manually inspecting a description change.
    """
    from quill.pinning import PinStore

    store = PinStore.load()
    store.approve(upstream, tool_name, digest, by=f"user:{os.environ.get('USER', 'cli')}")
    console.print(
        f"[green]approved[/green] {upstream}.{tool_name} digest={digest[:12]}…",
    )


@pins_app.command("revoke")
def pins_revoke(
    upstream: Annotated[str, typer.Argument()],
    tool_name: Annotated[str, typer.Argument()],
) -> None:
    """Revoke a pinned tool. Future verify() refuses; tool is hidden from the
    client until re-approved with a new digest.
    """
    from quill.pinning import PinStore

    store = PinStore.load()
    store.revoke(upstream, tool_name)
    console.print(f"[yellow]revoked[/yellow] {upstream}.{tool_name}")


# --------------------------------------------------------------------------
# approve - the "go ahead" path, called from a notification


@app.command("approve")
def approve_token(
    token: Annotated[str, typer.Argument(help="approval token from a Quill notification")],
    no_biometric: Annotated[
        bool,
        typer.Option(
            "--no-biometric",
            help="skip the Touch ID prompt even if available (typed-token-only)",
        ),
    ] = False,
    require_biometric: Annotated[
        bool,
        typer.Option(
            "--require-biometric",
            help="refuse to approve if Touch ID is unavailable",
        ),
    ] = False,
) -> None:
    """Confirm a pending one-shot approval token.

    When Quill blocks a tool call, the user gets a notification with a
    short token. Running `quill approve <token>` marks that exact
    (tool_name, args) pair as approved for the next ~10 minutes; the
    next time the agent retries that exact call, the gate consumes the
    approval and lets it through.

    On macOS with Touch ID available, this command requires a fingerprint
    match before persisting the approval - so a compromised terminal that
    can type the token still can't release the call. Pass --no-biometric
    to skip the prompt (useful in headless / SSH sessions); pass
    --require-biometric to refuse approval when Touch ID isn't available.

    One-shot by design: an attacker who hijacks the agent mid-session
    can't reuse the token for a different command.
    """
    from quill import events as ev
    from quill.approvals import ApprovalStore

    store = ApprovalStore.load()
    ap = store.approve(token)
    if ap is None:
        console.print(
            f"[red]no active approval matching[/red] [bold]{token}[/bold]\n"
            "  it may have expired (TTL is 10 minutes), already been "
            "consumed, or never existed.",
        )
        raise typer.Exit(code=1)

    biometric_reason = ""
    biometric_event: str | None = None
    if not no_biometric:
        from quill import touchid
        if touchid.is_available():
            console.print(
                f"  [dim]Touch ID required to approve "
                f"[bold]{ap.tool_name}[/bold] · check the sensor[/dim]",
            )
            res = touchid.authenticate(
                f"approve {ap.tool_name} (token {token[:8]})",
            )
            if res.success:
                biometric_event = ev.APPROVE_BIOMETRIC_OK
                biometric_reason = "ok"
            else:
                # Failure: revoke the just-issued approval state and refuse.
                store.revoke(token)
                biometric_event = ev.APPROVE_BIOMETRIC_DENY
                biometric_reason = res.reason
                console.print(
                    f"[red]biometric refused[/red]: {res.reason}\n"
                    "  approval REVOKED. agent retry will not be allowed.",
                )
                _emit_approve_audit(
                    biometric_event, token, ap.tool_name, biometric_reason,
                )
                raise typer.Exit(code=2)
        elif require_biometric:
            store.revoke(token)
            console.print(
                "[red]Touch ID is required (--require-biometric) but "
                "not available on this machine/session.[/red]\n"
                "  approval REVOKED.",
            )
            _emit_approve_audit(
                ev.APPROVE_BIOMETRIC_DENY, token, ap.tool_name, "not_available",
            )
            raise typer.Exit(code=2)
        else:
            biometric_event = ev.APPROVE_BIOMETRIC_SKIPPED
            biometric_reason = "not_available"
    else:
        biometric_event = ev.APPROVE_BIOMETRIC_SKIPPED
        biometric_reason = "user_opted_out"

    if biometric_event is not None:
        _emit_approve_audit(biometric_event, token, ap.tool_name, biometric_reason)

    console.print(
        f"[green]approved[/green] [bold]{ap.tool_name}[/bold] for one call · "
        f"expires {ap.expires_at[:19]}",
    )
    if ap.reason:
        console.print(f"  reason: [dim]{ap.reason}[/dim]")
    if biometric_reason == "ok":
        console.print("  [dim]Touch ID confirmed[/dim]")
    console.print(
        "  the agent's next attempt of this exact call will go through.",
    )


def _emit_approve_audit(
    event_type: str, token: str, tool_name: str, reason: str,
) -> None:
    """Best-effort emit a Touch ID outcome to the chained audit log."""
    from quill.audit import AuditLog
    try:
        key = _hmac_key()
        with AuditLog(path=default_audit_path(), hmac_key=key) as audit:
            audit.emit(
                event_type=event_type,
                session_id="quill-approve-cli",
                agent_id="quill.approve",
                risk="high",
                payload={
                    "token_prefix": token[:8],
                    "tool_name": tool_name,
                    "reason": reason,
                },
                force_fsync=True,
            )
    except Exception:
        # Approve must succeed even if audit-emit fails; the approval
        # itself is already persisted to approvals.json.
        pass


@approvals_app.command("list")
def approvals_list() -> None:
    """List pending one-shot approval tokens (issued, unconsumed, unexpired)."""
    from quill.approvals import ApprovalStore

    store = ApprovalStore.load()
    active = store.active()
    if not active:
        console.print("[dim]no pending approvals[/dim]")
        return
    table = Table(title="pending approvals")
    table.add_column("token", no_wrap=True, width=12)
    table.add_column("tool", no_wrap=True, width=18)
    table.add_column("issued", style="dim", width=20)
    table.add_column("expires", style="dim", width=20)
    table.add_column("reason", overflow="fold")
    for ap in active:
        table.add_row(
            ap.token, ap.tool_name,
            ap.issued_at[:19], ap.expires_at[:19],
            ap.reason[:80],
        )
    Console().print(table)


@approvals_app.command("revoke")
def approvals_revoke(
    token: Annotated[str, typer.Argument()],
) -> None:
    """Drop a token without consuming it. Useful if the notification was
    surprising and you DON'T want the agent to retry."""
    from quill.approvals import ApprovalStore

    store = ApprovalStore.load()
    if store.revoke(token):
        console.print(f"[yellow]revoked[/yellow] {token}")
    else:
        console.print(f"[dim]no token[/dim] {token}")
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------
# trust - per-directory trust scopes. The fix for approval fatigue.
# Edit/Write inside a trusted path auto-allows; everything else still gates.


def _load_or_init_config_toml() -> tuple[Path, dict[str, object]]:
    """Read ~/.quill/config.toml as a mutable dict; init a minimal one if missing.

    Returns (path, data). Caller mutates data and writes it back. Keeps the
    starter `[session] intent = "..."` line so future `load_config()` calls
    still pass Pydantic validation - QuillConfig requires SessionConfig.
    """
    import sys as _sys
    if _sys.version_info >= (3, 11):
        import tomllib as _tomllib
    else:
        import tomli as _tomllib  # type: ignore[no-redef]
    from quill.config import default_config_path

    p = default_config_path()
    data: dict[str, object] = {}
    if p.exists():
        with contextlib.suppress(OSError, _tomllib.TOMLDecodeError):
            with p.open("rb") as f:
                data = _tomllib.load(f) or {}
    if "session" not in data:
        # Minimum viable session block so load_config() validation passes
        # after our write. Operator can edit the intent later.
        data["session"] = {"intent": "(autocreated by quill trust)", "scope": []}
    return p, data


def _write_config_toml(path: Path, data: dict[str, object]) -> None:
    """Write the config dict back as TOML. Stdlib has no toml writer, so we
    hand-format - simple key/value, [section], [[upstream]] arrays. Good
    enough for the small surface quill writes (trust / policy / [session])."""
    out: list[str] = []
    # Order: session, audit, trust, policy, telemetry, upstream, then anything else
    section_order = ["session", "audit", "trust", "policy", "telemetry"]
    written: set[str] = set()

    def fmt_value(v: object) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, str):
            # TOML basic string with backslash + dquote escaping
            return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
        if isinstance(v, list):
            return "[" + ", ".join(fmt_value(x) for x in v) + "]"
        return '"' + str(v).replace('"', '\\"') + '"'

    def emit_section(name: str, body: object) -> None:
        if not isinstance(body, dict):
            return
        out.append(f"[{name}]")
        for k, v in body.items():
            out.append(f"{k} = {fmt_value(v)}")
        out.append("")

    for name in section_order:
        if name in data:
            emit_section(name, data[name])
            written.add(name)
    # Pass through any other top-level dict sections (e.g. [bash], [notify]).
    for name, body in data.items():
        if name in written:
            continue
        if name == "upstream" and isinstance(body, list):
            for item in body:
                if isinstance(item, dict):
                    out.append("[[upstream]]")
                    for k, v in item.items():
                        out.append(f"{k} = {fmt_value(v)}")
                    out.append("")
            written.add(name)
            continue
        if isinstance(body, dict):
            emit_section(name, body)
        written.add(name)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out).rstrip() + "\n")
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def _normalize_trust_path(raw: str) -> str:
    """Operator-facing: take a path, return its resolved absolute form.

    `~/foo` -> `/Users/.../foo`. Non-existent paths are still returned
    (operator might be pre-adding a path they're about to create).
    """
    return str(Path(raw).expanduser().resolve(strict=False))


@trust_app.command("add")
def trust_add(
    path: Annotated[
        str,
        typer.Argument(help="directory to trust. Edit/Write inside it auto-allows."),
    ],
) -> None:
    """Add a directory to the trust list.

    After this runs, every default-HIGH-risk Edit/Write/MultiEdit/NotebookEdit
    inside that directory (or any subdirectory) auto-allows instead of
    asking for approval. Pattern-matched HIGHs (vercel --prod, curl, rm -rf)
    and CRITICAL events still fire regardless of trust.
    """
    resolved = _normalize_trust_path(path)
    cfg_path, data = _load_or_init_config_toml()
    trust_block = data.get("trust") or {}
    if not isinstance(trust_block, dict):
        trust_block = {}
    paths = list(trust_block.get("paths") or [])
    if not isinstance(paths, list):
        paths = []
    if resolved in paths:
        console.print(f"  [dim]already trusted:[/dim] {resolved}")
        return
    paths.append(resolved)
    trust_block["paths"] = paths
    data["trust"] = trust_block
    _write_config_toml(cfg_path, data)
    console.print(f"  [green]trusted[/green] {resolved}")
    console.print(f"  [dim]config:[/dim] {cfg_path}")


@trust_app.command("remove")
def trust_remove(
    path: Annotated[
        str,
        typer.Argument(help="directory to untrust. Future Edit/Write will gate again."),
    ],
) -> None:
    """Remove a directory from the trust list."""
    resolved = _normalize_trust_path(path)
    cfg_path, data = _load_or_init_config_toml()
    trust_block = data.get("trust") or {}
    if not isinstance(trust_block, dict):
        trust_block = {}
    paths = list(trust_block.get("paths") or [])
    if resolved not in paths:
        console.print(f"  [yellow]not in trust list:[/yellow] {resolved}")
        raise typer.Exit(code=1)
    paths = [p for p in paths if p != resolved]
    trust_block["paths"] = paths
    data["trust"] = trust_block
    _write_config_toml(cfg_path, data)
    console.print(f"  [red]untrusted[/red] {resolved}")


@trust_app.command("list")
def trust_list() -> None:
    """Show every trusted directory."""
    cfg_path, data = _load_or_init_config_toml()
    trust_block = data.get("trust") or {}
    if not isinstance(trust_block, dict):
        trust_block = {}
    paths = list(trust_block.get("paths") or [])
    if not paths:
        console.print("[dim]no trusted directories yet.[/dim]")
        console.print(f"[dim]add with: quill trust add <path>  ({cfg_path})[/dim]")
        return
    console.print(f"[bold]trusted directories[/bold]  ({cfg_path})")
    for p in paths:
        exists_tag = "" if Path(p).exists() else "  [yellow](missing on disk)[/yellow]"
        console.print(f"  {p}{exists_tag}")


@trust_app.command("check")
def trust_check(
    cwd: Annotated[
        str | None,
        typer.Argument(help="directory to test (defaults to current cwd)"),
    ] = None,
) -> None:
    """Test whether a given directory is currently trusted."""
    from quill.paths import is_trusted_cwd
    target = cwd or str(Path.cwd())
    resolved = str(Path(target).expanduser().resolve(strict=False))
    if is_trusted_cwd(resolved):
        console.print(f"  [green]trusted[/green] {resolved}")
    else:
        console.print(f"  [dim]not trusted[/dim] {resolved}")
        console.print(f"  [dim]add with: quill trust add {resolved}[/dim]")
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------
# notify - synchronously fire every configured channel + report which
# delivered. Closes the "did my [notify] config actually work?" loop without
# waiting for a real block to fire.


@notify_app.command("test")
def notify_test(
    channel: Annotated[
        str | None,
        typer.Option(
            "--channel", "-c",
            help="only fire one channel (macos|email|slack|webhook); default is all",
        ),
    ] = None,
) -> None:
    """Fire a synthetic notification through every configured channel and
    print which ones actually delivered.

    Each channel runs SYNCHRONOUSLY (not the daemon-thread fire-and-forget
    of the live block path) so the user gets per-channel ✓/✗ feedback in
    real time. Audit-log entry: tool_name="quill.notify_test" so live-fire
    can be distinguished from real blocks in `quill audit show`.
    """
    import tomllib

    from quill.config import default_config_path
    from quill.notify import (
        BlockMessage,
        NotifyConfig,
        _send_email,
        _send_macos,
        _send_slack,
        _send_webhook,
    )

    cfg_path = default_config_path()
    raw_notify: dict[str, Any] | None = None
    if cfg_path.exists():
        with cfg_path.open("rb") as f:
            raw = tomllib.load(f)
        if isinstance(raw, dict):
            raw_notify = raw.get("notify")
    if not raw_notify:
        console.print(
            "[yellow]no [notify] section in config[/yellow] "
            f"({cfg_path})\n"
            "  add a [notify] block to enable channels - see "
            "https://github.com/manumarri-sudo/quill#notifications",
        )
        raise typer.Exit(code=1)

    notify_cfg = NotifyConfig.from_dict(raw_notify)
    msg = BlockMessage(
        risk="critical",
        decision="blocked",
        tool_name="quill.notify_test",
        args_preview={"command": "self-test"},
        what="quill notify test (synthetic)",
        why="this is a self-test - no real call was blocked",
        try_instead="ignore - verifying your notification wiring",
        approve_token="TEST" + secrets.token_urlsafe(6),
    )

    senders = {
        "macos": _send_macos,
        "email": _send_email,
        "slack": _send_slack,
        "webhook": _send_webhook,
    }
    if channel:
        if channel not in senders:
            console.print(
                f"[red]unknown channel[/red] {channel!r} - "
                f"valid: {', '.join(senders)}",
            )
            raise typer.Exit(code=1)
        senders = {channel: senders[channel]}

    table = Table(title="quill notify test")
    table.add_column("channel", no_wrap=True, width=10)
    table.add_column("configured?", width=12)
    table.add_column("delivered?", width=12)
    table.add_column("notes", overflow="fold")

    results: dict[str, bool] = {}
    for name, sender in senders.items():
        configured = _channel_configured(notify_cfg, name)
        if not configured:
            table.add_row(name, "[dim]no[/dim]", "-",
                          "(not in [notify] section)")
            results[name] = False
            continue
        try:
            ok = bool(sender(notify_cfg, msg))
        except Exception as e:
            table.add_row(name, "[green]yes[/green]", "[red]✗ error[/red]",
                          f"{type(e).__name__}: {e}")
            results[name] = False
            continue
        results[name] = ok
        if ok:
            table.add_row(name, "[green]yes[/green]", "[green]✓[/green]",
                          "channel reports success")
        else:
            table.add_row(name, "[green]yes[/green]", "[yellow]✗[/yellow]",
                          "channel returned False (check creds / focus mode / network)")

    Console().print(table)

    # Audit-log the test so it appears in `quill audit show`.
    try:
        with AuditLog(path=default_audit_path(), hmac_key=_hmac_key()) as audit:
            audit.emit(
                event_type="notify.dispatched",
                session_id="quill-notify-test",
                agent_id="quill.notify_test",
                risk="low",
                payload={
                    "tool_name": "quill.notify_test",
                    "decision": "test",
                    "risk": "critical",
                    "channels": results,
                    "approve_token": msg.approve_token,
                },
            )
    except Exception:
        pass

    if not any(results.values()):
        console.print(
            "[red]nothing delivered.[/red] "
            "verify channel creds / Focus mode / network reachability.",
        )
        raise typer.Exit(code=2)
    console.print(
        "[dim]audit-logged as[/dim] notify.dispatched "
        "[dim](tool_name=quill.notify_test)[/dim]",
    )


def _channel_configured(cfg: Any, name: str) -> bool:
    """True iff the user supplied enough config for this channel to even try."""
    if name == "macos":
        return bool(getattr(cfg, "macos", False))
    if name == "email":
        return bool(getattr(cfg, "email_to", "") and getattr(cfg, "smtp_host", ""))
    if name == "slack":
        return bool(getattr(cfg, "slack_webhook_url", ""))
    if name == "webhook":
        return bool(getattr(cfg, "webhook_url", ""))
    return False


# --------------------------------------------------------------------------
# suggestions - the operator-facing surface for the learner's
# loosening candidates + drift detections + operator-anomaly events.
# Auto-tightenings are recorded too (for transparency) but already
# applied.


def _suggestion_key(s: dict[str, Any]) -> str:
    """Stable key for a suggestion: pattern_id + type. Used to dedup
    multiple firings of the same suggestion across days."""
    pid = s.get("pattern_id") or s.get("session_id") or "(global)"
    return f"{s.get('type', '?')}:{pid}"


@suggestions_app.command("list")
def suggestions_list(
    only: Annotated[
        str | None,
        typer.Option("--only", help="filter by type: tightening_auto_applied | loosening_candidate | operator_anomaly | drift_detected"),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="max suggestions to show"),
    ] = 50,
) -> None:
    """List learner-surfaced suggestions, newest first. Dedup by
    (type, pattern_id) so a streak of the same suggestion shows once."""
    from quill.learning import read_suggestions
    raw = read_suggestions(limit=limit * 5)
    raw.sort(key=lambda s: s.get("ts", 0), reverse=True)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for s in raw:
        if only and s.get("type") != only:
            continue
        key = _suggestion_key(s)
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
        if len(out) >= limit:
            break
    if not out:
        console.print("[dim]no suggestions in the queue.[/dim]")
        return
    sev_color = {
        "tightening_auto_applied": "yellow",
        "loosening_candidate": "cyan",
        "operator_anomaly": "red",
        "drift_detected": "magenta",
    }
    for s in out:
        color = sev_color.get(s.get("type", ""), "white")
        ts = s.get("ts", 0)
        try:
            ts_label = datetime.fromtimestamp(float(ts)).strftime("%m-%d %H:%M")
        except (ValueError, TypeError):
            ts_label = "?"
        console.print(
            f"  [dim]{ts_label}[/dim]  [{color}]{s.get('type', '?')}[/{color}]  "
            f"[bold]{s.get('pattern_id') or s.get('session_id') or ''}[/bold]"
        )
        ev = s.get("evidence", "")
        if ev:
            console.print(f"          [dim]{ev[:140]}[/dim]")
        if s.get("type") == "loosening_candidate":
            console.print(
                f"          [bold]apply:[/bold] quill suggestions promote "
                f"\"{_suggestion_key(s)}\""
            )


@suggestions_app.command("show")
def suggestions_show(
    key: Annotated[
        str,
        typer.Argument(help="suggestion key from `quill suggestions list` (type:pattern)"),
    ],
) -> None:
    """Show full detail for one suggestion."""
    from quill.learning import read_suggestions
    raw = read_suggestions(limit=1000)
    matching = [s for s in raw if _suggestion_key(s) == key]
    if not matching:
        console.print(f"[yellow]no suggestion matching key:[/yellow] {key}")
        raise typer.Exit(code=1)
    s = matching[-1]
    console.print(json.dumps(s, indent=2))


@suggestions_app.command("promote")
def suggestions_promote(
    key: Annotated[
        str,
        typer.Argument(help="suggestion key (type:pattern)"),
    ],
    ttl_days: Annotated[
        int,
        typer.Option("--ttl-days", help="how long the override lives"),
    ] = 30,
) -> None:
    """Promote a loosening_candidate to a real override. Writes to
    `~/.quill/overrides.toml` with the given TTL. The operator's
    explicit approval lives here - the learner never wrote it itself.
    """
    from quill.learning import read_suggestions
    raw = read_suggestions(limit=1000)
    matching = [s for s in raw if _suggestion_key(s) == key
                and s.get("type") == "loosening_candidate"]
    if not matching:
        console.print(
            f"[yellow]no loosening_candidate matching key:[/yellow] {key}"
        )
        raise typer.Exit(code=1)
    s = matching[-1]

    overrides_path = Path(os.environ.get(
        "QUILL_OVERRIDES",
        str(Path.home() / ".quill" / "overrides.toml"),
    )).expanduser()
    overrides_path.parent.mkdir(parents=True, exist_ok=True)

    pattern_id = str(s.get("pattern_id") or "")
    # Make a TOML-safe section name
    section = "".join(
        c if c.isalnum() or c in "_-" else "_" for c in pattern_id
    )[:60]
    existing = overrides_path.read_text() if overrides_path.exists() else ""
    block = (
        f"\n[overrides.{section}]\n"
        f'pattern_id = "{pattern_id}"\n'
        f'promoted_at = "{datetime.now(timezone.utc).isoformat()}"\n'
        f"ttl_days = {ttl_days}\n"
        f'evidence = "{s.get("evidence", "")[:200].replace(chr(34), chr(39))}"\n'
    )
    overrides_path.write_text(existing + block)
    with contextlib.suppress(OSError):
        overrides_path.chmod(0o600)

    # Append a tracking entry to suggestions.jsonl
    from quill.learning import append_suggestion, log_event
    promo = {
        "ts": time.time(),
        "type": "loosening_promoted",
        "pattern_id": pattern_id,
        "ttl_days": ttl_days,
        "promoted_via": "quill suggestions promote",
        "evidence_source": s.get("evidence", ""),
    }
    append_suggestion(promo)
    log_event(f"promoted pattern={pattern_id} ttl_days={ttl_days}")
    console.print(
        f"  [green]promoted[/green] {pattern_id}  "
        f"[dim](ttl {ttl_days}d, written to {overrides_path})[/dim]"
    )


@suggestions_app.command("cleanup")
def suggestions_cleanup(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="show what would be removed, don't change anything"),
    ] = False,
) -> None:
    """Remove stale per-token pattern rows from pattern_stats.json.

    A pre-rc5 bug derived the pattern_id from the FLIPPED decision
    reason after a token consume, producing one dead row per token
    (e.g. `Bash:approved one-shot via quill approve aBc12`). This
    command cleans those up. Real patterns are untouched.

    Idempotent: a second invocation after the first removes nothing.
    """
    from quill.learning import cleanup_stale_patterns, find_stale_patterns
    if dry_run:
        stale = find_stale_patterns()
        if not stale:
            console.print("[dim]no stale rows to clean up.[/dim]")
            return
        console.print(f"would remove [yellow]{len(stale)}[/yellow] stale row(s):")
        for pid in stale[:20]:
            console.print(f"  [dim]{pid}[/dim]")
        if len(stale) > 20:
            console.print(f"  [dim]... and {len(stale) - 20} more[/dim]")
        return
    n, removed = cleanup_stale_patterns()
    if n == 0:
        console.print("[dim]nothing to clean up.[/dim]")
        return
    console.print(f"[green]removed[/green] {n} stale pattern row(s).")
    for pid in removed[:10]:
        console.print(f"  [dim]{pid}[/dim]")
    if len(removed) > 10:
        console.print(f"  [dim]... and {len(removed) - 10} more[/dim]")


@suggestions_app.command("dismiss")
def suggestions_dismiss(
    key: Annotated[
        str,
        typer.Argument(help="suggestion key to dismiss"),
    ],
) -> None:
    """Dismiss a suggestion. Appends a `dismissed` entry to
    suggestions.jsonl so subsequent `list` calls hide it. Append-only;
    no in-place edits."""
    from quill.learning import append_suggestion, log_event
    entry = {
        "ts": time.time(),
        "type": "dismissed",
        "dismissed_key": key,
    }
    append_suggestion(entry)
    log_event(f"dismissed key={key}")
    console.print(f"  [red]dismissed[/red] {key}")


# --------------------------------------------------------------------------
# log - tail the learner's append-only logs in real time so the
# operator can SEE what Quill is doing as it does it.

import time as _time  # noqa: E402 - placement next to its sole user


@app.command("log")
def log_cmd(
    follow: Annotated[
        bool,
        typer.Option("--follow", "-f", help="stream new entries as they arrive"),
    ] = False,
    n: Annotated[
        int,
        typer.Option("--lines", "-n", help="how many trailing lines to show"),
    ] = 30,
    show_suggestions: Annotated[
        bool,
        typer.Option(
            "--suggestions/--no-suggestions",
            help="also tail ~/.quill/suggestions.jsonl",
        ),
    ] = True,
) -> None:
    """Show the learner's recent activity. With --follow, streams new
    entries in real time so you can watch Quill update itself.
    """
    from quill.learning import _log_path, _suggestions_path

    log_path = _log_path()
    sug_path = _suggestions_path()

    if not log_path.exists() and not sug_path.exists():
        console.print(
            "[dim]no learner activity yet. The log lives at "
            f"{log_path}.[/dim]"
        )
        return

    def _print_recent() -> None:
        if log_path.exists():
            lines = log_path.read_text().splitlines()[-n:]
            for line in lines:
                console.print(line)
        if show_suggestions and sug_path.exists():
            sugs = sug_path.read_text().splitlines()[-n:]
            for raw in sugs:
                try:
                    s = json.loads(raw)
                    console.print(
                        f"[dim](suggestion)[/dim] "
                        f"[cyan]{s.get('type')}[/cyan] "
                        f"{s.get('pattern_id') or s.get('session_id') or ''} "
                        f"[dim]{s.get('evidence', '')[:100]}[/dim]"
                    )
                except json.JSONDecodeError:
                    continue

    _print_recent()
    if not follow:
        return

    # Follow mode: poll for size changes. Sub-second granularity.
    last_log_size = log_path.stat().st_size if log_path.exists() else 0
    last_sug_size = sug_path.stat().st_size if sug_path.exists() else 0
    try:
        while True:
            _time.sleep(0.4)
            if log_path.exists():
                sz = log_path.stat().st_size
                if sz > last_log_size:
                    with log_path.open() as f:
                        f.seek(last_log_size)
                        new = f.read()
                    last_log_size = sz
                    for line in new.splitlines():
                        if line.strip():
                            console.print(line)
            if show_suggestions and sug_path.exists():
                sz = sug_path.stat().st_size
                if sz > last_sug_size:
                    with sug_path.open() as f:
                        f.seek(last_sug_size)
                        new = f.read()
                    last_sug_size = sz
                    for raw in new.splitlines():
                        if not raw.strip():
                            continue
                        try:
                            s = json.loads(raw)
                            console.print(
                                f"[dim](suggestion)[/dim] "
                                f"[cyan]{s.get('type')}[/cyan] "
                                f"{s.get('pattern_id') or s.get('session_id') or ''}"
                            )
                        except json.JSONDecodeError:
                            continue
    except KeyboardInterrupt:
        console.print("[dim]\n(stopped)[/dim]")


def main() -> None:  # entry point for the [project.scripts] hook
    app()


if __name__ == "__main__":
    main()
