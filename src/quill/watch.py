"""Live browser dashboard.

`quill watch` starts a tiny local HTTP server that streams audit-log
events to a single-page dashboard via Server-Sent Events. Auto-opens
the user's default browser. Stays running until Ctrl-C.

`quill watch --daemon` detaches the server from the terminal so it
survives Ctrl-C, terminal close, and Claude Code exit. The PID is
written to ~/.quill/watch.pid; subsequent invocations reuse the
running daemon instead of spawning a duplicate. The hook adapter
calls this lazily on every tool call so the dashboard self-heals
after a laptop reboot — no user action required.

No external dependencies — stdlib http.server + threading + a self-
contained HTML page. Cross-platform.

Privacy: the dashboard never leaves localhost. The HTML page is served
from the same process; nothing is fetched from the public internet.
"""
from __future__ import annotations

import http.server
import json
import os
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

DEFAULT_PORT = 9099


# ---- daemon helpers --------------------------------------------------------


def _pid_file() -> Path:
    return Path(
        os.environ.get("QUILL_WATCH_PID", "~/.quill/watch.pid"),
    ).expanduser()


def _is_alive(pid: int) -> bool:
    """True if a process with this PID is alive on this machine."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def daemon_status() -> tuple[int | None, int | None]:
    """Return (pid, port) if a watcher is running, else (None, None).

    The PID file's first line is the PID, the second is the bound port.
    """
    p = _pid_file()
    if not p.exists():
        return None, None
    try:
        lines = p.read_text().splitlines()
        pid = int(lines[0])
        port = int(lines[1]) if len(lines) > 1 else DEFAULT_PORT
    except (OSError, ValueError, IndexError):
        return None, None
    if not _is_alive(pid):
        # Stale PID file — clean it up
        with _quiet_oserror():
            p.unlink()
        return None, None
    # Confirm something is actually listening on the port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect(("127.0.0.1", port))
        s.close()
        return pid, port
    except OSError:
        s.close()
        return None, None


class _quiet_oserror:
    def __enter__(self): return self
    def __exit__(self, *exc): return exc[0] is OSError or exc[0] is None


def write_pid(pid: int, port: int) -> None:
    p = _pid_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"{pid}\n{port}\n")
    with _quiet_oserror():
        p.chmod(0o600)


def stop_daemon() -> tuple[bool, str]:
    """Send SIGTERM to the running daemon. Returns (was_running, message)."""
    pid, port = daemon_status()
    if pid is None:
        return False, "no daemon running"
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as e:
        return False, f"could not signal pid {pid}: {e}"
    # wait briefly for it to die
    for _ in range(20):
        if not _is_alive(pid):
            break
        time.sleep(0.1)
    with _quiet_oserror():
        _pid_file().unlink()
    return True, f"stopped pid {pid} (port {port})"


def ensure_daemon(
    log_path: Path,
    *,
    port: int = DEFAULT_PORT,
    open_browser: bool = False,
) -> tuple[int, int]:
    """Start the watch daemon if it isn't already running.

    Returns (pid, port). Idempotent — calling repeatedly is cheap if a
    daemon is already alive (just probes the PID file + connects to the
    port). Designed to be called from the Claude Code hook adapter so
    the dashboard self-heals across reboots without user intervention.
    """
    pid, p = daemon_status()
    if pid is not None and p is not None:
        return pid, p

    # Spawn a detached child running `quill watch --daemon-child`.
    cmd = [
        sys.executable, "-m", "quill", "watch",
        "--daemon-child",
        "--port", str(port),
        "--log", str(log_path),
    ]
    if not open_browser:
        cmd.append("--no-browser")
    devnull = open(os.devnull, "wb")  # noqa: SIM115
    proc = subprocess.Popen(  # noqa: S603 — controlled args
        cmd,
        stdin=devnull,
        stdout=devnull,
        stderr=devnull,
        start_new_session=True,  # POSIX: detach from current session
        close_fds=True,
    )
    # poll briefly for the port to come up
    deadline = time.time() + 6.0
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect(("127.0.0.1", port))
            s.close()
            write_pid(proc.pid, port)
            return proc.pid, port
        except OSError:
            time.sleep(0.15)
    # Could not bring up on the requested port — leave the child to its
    # own port-finder logic; record what we know.
    write_pid(proc.pid, port)
    return proc.pid, port


# A self-contained HTML page; one file, no external assets.
_DASHBOARD_HTML = r"""<!doctype html>
<html lang=en>
<head>
<meta charset=utf-8>
<title>quill watch</title>
<style>
:root {
  --bg: #0c0e12; --panel: #14171c; --line: #1f242c;
  --fg: #e8eaed; --dim: #8a92a0;
  --low: #2ec27e; --med: #6a9bf4; --high: #f5c451; --crit: #e0626a;
  --sub: #c98ad6;     /* magenta-pink for sub-agent decoration */
  --spawn: #c98ad6;
}
* { box-sizing: border-box; }
html, body { height: 100%; margin: 0; }
body {
  background: var(--bg); color: var(--fg);
  font: 13px/1.55 -apple-system, "SF Mono", ui-monospace, Menlo, monospace;
}
header {
  position: sticky; top: 0; background: var(--panel);
  border-bottom: 1px solid var(--line);
  padding: 10px 16px; display: flex; gap: 16px; align-items: baseline;
  z-index: 5;
}
header h1 { font: 600 14px -apple-system, system-ui; margin: 0; }
header .meta { color: var(--dim); font-size: 12px; }
header .pulse { width: 7px; height: 7px; border-radius: 50%; background: var(--low); display: inline-block; margin-right: 6px; box-shadow: 0 0 6px var(--low); }
.live { display: inline-flex; align-items: center; }

/* legend bar — explains the symbols, sticks under header */
.legend {
  position: sticky;
  top: 38px;
  z-index: 4;
  background: var(--panel);
  border-bottom: 1px solid var(--line);
  padding: 8px 16px;
  display: flex; flex-wrap: wrap; gap: 18px;
  font-size: 11px; color: var(--dim);
  letter-spacing: 0.04em;
}
.legend .item { display: inline-flex; align-items: center; gap: 6px; }
.legend .glyph { font-weight: 700; font-size: 12px; }
.legend .item.allow .glyph { color: var(--low); }
.legend .item.ask   .glyph { color: var(--high); }
.legend .item.block .glyph { color: var(--crit); }
.legend .item.scope .glyph { color: var(--sub); }
.legend .item.sub   .glyph { color: var(--sub); }

main { padding: 8px 16px 64px 16px; }
.row {
  display: grid;
  grid-template-columns: 80px 90px 130px 1fr;
  gap: 12px; padding: 6px 0; border-bottom: 1px solid var(--line);
  align-items: baseline;
}
.row:hover { background: rgba(255,255,255,0.02); }
.ts { color: var(--dim); }
.risk { font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }
.risk.low { color: var(--low); }
.risk.medium { color: var(--med); }
.risk.high { color: var(--high); }
.risk.critical { color: var(--crit); }
.type { color: var(--dim); }
.type.allowed { color: var(--low); }
.type.blocked, .type.scope { color: var(--crit); }
.type.attempt { color: var(--med); }
.type.spawned { color: var(--spawn); }
.tool { font-weight: 500; }
.reason { color: var(--dim); font-style: italic; }
.empty { padding: 32px; color: var(--dim); text-align: center; }
.dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; margin-right: 8px; }
.dot.low { background: var(--low); }
.dot.medium { background: var(--med); }
.dot.high { background: var(--high); }
.dot.critical { background: var(--crit); }

/* sub-agent decoration: indented, prefixed with ↳, with a small label */
.row.sub { padding-left: 22px; border-left: 1px solid rgba(201,138,214,0.18); margin-left: 6px; }
.row.sub .ts { color: var(--sub); opacity: .75; }
.sub-tag {
  display: inline-block;
  margin-right: 8px;
  padding: 1px 6px;
  font-size: 10px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--sub);
  border: 1px solid rgba(201,138,214,0.4);
  border-radius: 3px;
  vertical-align: 1px;
}
.row.spawn-row {
  background: rgba(201,138,214,0.05);
  border-bottom: 1px solid rgba(201,138,214,0.18);
}
.row.spawn-row .type { color: var(--spawn); font-weight: 600; }

footer { position: fixed; bottom: 0; left: 0; right: 0; background: var(--panel); border-top: 1px solid var(--line); color: var(--dim); padding: 6px 16px; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>quill watch</h1>
  <span class=meta>streaming <code id=logpath></code></span>
  <span class=meta live><span class=pulse></span> live</span>
</header>
<div class=legend>
  <span class="item allow"><span class=glyph>✓</span> allow</span>
  <span class="item ask"><span class=glyph>?</span> ask</span>
  <span class="item block"><span class=glyph>✗</span> block</span>
  <span class="item scope"><span class=glyph>✗</span> scope</span>
  <span class="item sub"><span class=glyph>↳</span> sub-agent</span>
  <span class=meta style="margin-left:auto;">click any row for details</span>
</div>
<main id=feed>
  <div class=empty id=empty>waiting for events...</div>
</main>
<footer>
  <span id=counts>0 events</span> ·
  <span id=subcount>0 sub-agents</span> ·
  <span id=lastevent></span>
</footer>
<script>
const feed = document.getElementById("feed");
const empty = document.getElementById("empty");
const countsEl = document.getElementById("counts");
const subEl = document.getElementById("subcount");
const lastEl = document.getElementById("lastevent");
const logpath = document.getElementById("logpath");
let n = 0;
const subLabels = new Map();   // session_id -> "sub·N"
let subCounter = 0;

function shortType(t) {
  // Match the canonical vocabulary used by audit show / tail / TUI:
  // ✓ allow / ? ask / ✗ block / ✗ scope / ▸ spawn / · attempt
  if (t === "verdict.allowed") return ["allow", "✓ allow"];
  if (t === "verdict.blocked") return ["block", "✗ block"];
  if (t === "verdict.scope_violation") return ["scope", "✗ scope"];
  if (t === "verdict.ask") return ["ask", "? ask"];
  if (t === "tool.attempted") return ["attempt", "· attempt"];
  if (t === "tool.completed") return ["", "✓ done"];
  if (t === "session.start") return ["", "▸ session"];
  if (t === "session.end") return ["", "◂ session"];
  if (t === "agent.spawned") return ["spawned", "▸ spawn"];
  if (t === "agent.closed") return ["", "◂ close"];
  return ["", t];
}

function render(evt) {
  if (empty) { empty.remove(); }

  // assign a stable label to each sub-agent the first time we see it
  if (evt.type === "agent.spawned") {
    const sid = evt.session_id || "";
    if (!subLabels.has(sid)) {
      subCounter++;
      subLabels.set(sid, `sub·${subCounter}`);
      subEl.textContent = `${subCounter} sub-agent${subCounter === 1 ? "" : "s"}`;
    }
  }

  const p = evt.payload || {};
  const parent = p.parent_session_id || "";
  const isSub = !!parent;
  const subTag = isSub ? (subLabels.get(evt.session_id) || "sub") : "";
  const isSpawn = evt.type === "agent.spawned";

  const div = document.createElement("div");
  div.className = "row" + (isSub ? " sub" : "") + (isSpawn ? " spawn-row" : "");
  const ts = (evt.ts || "").slice(11, 19);
  const risk = (evt.risk || "low").toLowerCase();
  const [klass, label] = shortType(evt.type || "");
  const tool = p.tool_name || "";
  const reason = p.reason || p.risk_reason || "";

  let toolHtml = "";
  if (isSpawn) {
    const cwd = p.cwd ? `<span class=reason>in ${escapeHtml(String(p.cwd).slice(-50))}</span>` : "";
    toolHtml = `<span class="sub-tag">${escapeHtml(subLabels.get(evt.session_id) || "sub")}</span><span class=reason>spawned by ${escapeHtml(parent.slice(0, 16))}…</span>  ${cwd}`;
  } else {
    const subPrefix = isSub ? `<span class="sub-tag">${escapeHtml(subTag)}</span>` : "";
    toolHtml = `${subPrefix}${escapeHtml(tool)} ${reason ? `<span class=reason>— ${escapeHtml(reason)}</span>` : ""}`;
  }

  div.innerHTML = `
    <div class=ts>${ts}</div>
    <div class="risk ${risk}">${risk}</div>
    <div class="type ${klass}"><span class="dot ${risk}"></span>${label}</div>
    <div class=tool>${toolHtml}</div>
  `;
  feed.prepend(div);
  n++;
  countsEl.textContent = `${n} event${n === 1 ? "" : "s"}`;
  lastEl.textContent = `last: ${label} · ${ts}`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]));
}

const ev = new EventSource("/stream");
ev.onmessage = (m) => {
  try { render(JSON.parse(m.data)); } catch (e) {}
};
ev.addEventListener("init", (m) => {
  try { logpath.textContent = JSON.parse(m.data).log; } catch (e) {}
});
</script>
</body>
</html>
"""


def _free_port(prefer: int) -> int:
    """Return prefer if it binds; otherwise pick an OS-assigned free port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", prefer))
        s.close()
        return prefer
    except OSError:
        s.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _tail_events(log: Path, q: list[dict[str, Any]],
                 lock: threading.Lock,
                 stop: threading.Event) -> None:
    """Append-only tail: yield each new line of the log as a parsed event."""
    pos = 0
    if log.exists():
        pos = log.stat().st_size
    while not stop.is_set():
        if not log.exists():
            time.sleep(0.25)
            continue
        try:
            sz = log.stat().st_size
        except OSError:
            time.sleep(0.25)
            continue
        if sz < pos:
            # log truncated/rotated — start over
            pos = 0
        if sz == pos:
            time.sleep(0.2)
            continue
        with log.open() as f:
            f.seek(pos)
            for line in f:
                if not line.strip():
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                with lock:
                    q.append(evt)
                    if len(q) > 5000:
                        del q[:-2500]
            pos = f.tell()


def serve(
    log_path: Path,
    port: int = DEFAULT_PORT,
    open_browser: bool = True,
    *,
    write_pid_file: bool = False,
) -> None:
    """Run the watch server until Ctrl-C.

    `write_pid_file=True` records the PID + bound port at ~/.quill/watch.pid
    on startup, and unlinks the file on shutdown — used by `--daemon-child`.
    """
    port = _free_port(port)
    q: list[dict[str, Any]] = []
    lock = threading.Lock()
    stop = threading.Event()
    t = threading.Thread(target=_tail_events, args=(log_path, q, lock, stop), daemon=True)
    t.start()

    log_str = str(log_path)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:  # quiet
            return

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/" or self.path.startswith("/?"):
                body = _DASHBOARD_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if self.path == "/stream":
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("cache-control", "no-cache")
                self.send_header("connection", "keep-alive")
                self.end_headers()
                # initial event so the page can show the log path
                init = json.dumps({"log": log_str})
                try:
                    self.wfile.write(f"event: init\ndata: {init}\n\n".encode())
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                # replay last 50 events so the page isn't empty
                with lock:
                    backlog = list(q[-50:])
                for evt in backlog:
                    self._send_event(evt)
                # then stream forever
                seen = len(q)
                while not stop.is_set():
                    with lock:
                        new = q[seen:]
                        seen = len(q)
                    for evt in new:
                        if not self._send_event(evt):
                            return
                    time.sleep(0.25)
                return

            self.send_response(404)
            self.end_headers()

        def _send_event(self, evt: dict[str, Any]) -> bool:
            try:
                self.wfile.write(f"data: {json.dumps(evt)}\n\n".encode())
                self.wfile.flush()
                return True
            except (BrokenPipeError, ConnectionResetError):
                return False

    class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    httpd = ThreadedServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"

    if write_pid_file:
        write_pid(os.getpid(), port)
    else:
        # Foreground mode — print so the user sees the URL
        print(f"  quill watch: {url}    (log: {log_path})")
        print("  Ctrl-C to stop.")

    if open_browser and not os.environ.get("QUILL_WATCH_NOBROWSER"):
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass

    # Be a good daemon: clean up the PID file on graceful shutdown.
    def _cleanup(*_a: Any) -> None:
        stop.set()
        try:
            httpd.shutdown()
        except Exception:  # noqa: BLE001
            pass
        if write_pid_file:
            with _quiet_oserror():
                _pid_file().unlink()

    if write_pid_file:
        signal.signal(signal.SIGTERM, lambda *_: _cleanup())

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _cleanup()
        httpd.server_close()
