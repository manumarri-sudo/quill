"""Live browser dashboard.

`quill watch` starts a tiny local HTTP server that streams audit-log
events to a single-page dashboard via Server-Sent Events. Auto-opens
the user's default browser. Stays running until Ctrl-C.

No external dependencies — stdlib http.server + threading + a self-
contained HTML page. Cross-platform.

Privacy: the dashboard never leaves localhost. The HTML page is served
from the same process; nothing is fetched from the public internet.
"""
from __future__ import annotations

import http.server
import json
import os
import socket
import socketserver
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

DEFAULT_PORT = 9099


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
.tool { font-weight: 500; }
.reason { color: var(--dim); font-style: italic; }
.empty { padding: 32px; color: var(--dim); text-align: center; }
.dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; margin-right: 8px; }
.dot.low { background: var(--low); }
.dot.medium { background: var(--med); }
.dot.high { background: var(--high); }
.dot.critical { background: var(--crit); }
footer { position: fixed; bottom: 0; left: 0; right: 0; background: var(--panel); border-top: 1px solid var(--line); color: var(--dim); padding: 6px 16px; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>quill watch</h1>
  <span class=meta>streaming <code id=logpath></code></span>
  <span class=meta live><span class=pulse></span> live</span>
</header>
<main id=feed>
  <div class=empty id=empty>waiting for events...</div>
</main>
<footer>
  <span id=counts>0 events</span> ·
  <span id=lastevent></span>
</footer>
<script>
const feed = document.getElementById("feed");
const empty = document.getElementById("empty");
const countsEl = document.getElementById("counts");
const lastEl = document.getElementById("lastevent");
const logpath = document.getElementById("logpath");
let n = 0;

function shortType(t) {
  if (t === "verdict.allowed") return ["allowed", "allowed"];
  if (t === "verdict.blocked") return ["blocked", "blocked"];
  if (t === "verdict.scope_violation") return ["scope", "scope"];
  if (t === "tool.attempted") return ["attempt", "attempted"];
  if (t === "tool.completed") return ["", "completed"];
  if (t === "session.start") return ["", "session start"];
  if (t === "session.end") return ["", "session end"];
  return ["", t];
}

function render(evt) {
  if (empty) { empty.remove(); }
  const div = document.createElement("div");
  div.className = "row";
  const ts = (evt.ts || "").slice(11, 19);
  const risk = (evt.risk || "low").toLowerCase();
  const [klass, label] = shortType(evt.type || "");
  const p = evt.payload || {};
  const tool = p.tool_name || "";
  const reason = p.reason || p.risk_reason || "";
  div.innerHTML = `
    <div class=ts>${ts}</div>
    <div class="risk ${risk}">${risk}</div>
    <div class="type ${klass}"><span class="dot ${risk}"></span>${label}</div>
    <div class=tool>${escapeHtml(tool)} ${reason ? `<span class=reason>— ${escapeHtml(reason)}</span>` : ""}</div>
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


def serve(log_path: Path, port: int = DEFAULT_PORT, open_browser: bool = True) -> None:
    """Run the watch server until Ctrl-C."""
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
    print(f"  quill watch: {url}    (log: {log_path})")
    print("  Ctrl-C to stop.")

    if open_browser and not os.environ.get("QUILL_WATCH_NOBROWSER"):
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        httpd.server_close()
