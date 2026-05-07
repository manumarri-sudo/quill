/**
 * Cloudflare Worker receiver for quill's opt-in telemetry.
 *
 * Accepts POSTs from `quill` clients (see src/quill/telemetry.py) and
 * appends them to a Workers-D1 (SQLite) database. No request bodies are
 * mirrored anywhere. Client IPs are NEVER stored; we read CF-Connecting-IP
 * only to rate-limit and discard.
 *
 * Deploy:
 *
 *   npm install -g wrangler
 *   cd infra/cf-worker
 *   wrangler d1 create quill-telemetry
 *   # paste the database_id printed above into wrangler.toml
 *   wrangler d1 execute quill-telemetry --file ./schema.sql
 *   wrangler deploy
 *
 * The worker URL becomes your telemetry endpoint. Clients point there via:
 *   QUILL_TELEMETRY_ENDPOINT=https://<your-worker>.workers.dev/v1/events
 */

interface Env {
  DB: D1Database;
}

interface QuillEvent {
  schema_version: number;
  ts: string;
  install_id: string;
  quill_version: string;
  py_version: string;
  os: string;
  event: string;
  data: Record<string, unknown>;
}

const ALLOWED_EVENT_KINDS = new Set([
  "session.summary",
  "install",
  "config.snapshot",
]);

function isQuillEvent(x: unknown): x is QuillEvent {
  if (typeof x !== "object" || x === null) return false;
  const e = x as Record<string, unknown>;
  return (
    typeof e.schema_version === "number" &&
    typeof e.ts === "string" &&
    typeof e.install_id === "string" &&
    e.install_id.length >= 16 && e.install_id.length <= 64 &&
    typeof e.quill_version === "string" &&
    typeof e.py_version === "string" &&
    typeof e.os === "string" &&
    typeof e.event === "string" &&
    ALLOWED_EVENT_KINDS.has(e.event) &&
    typeof e.data === "object" && e.data !== null
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("method not allowed", { status: 405 });
    }
    const url = new URL(request.url);
    if (url.pathname !== "/v1/events") {
      return new Response("not found", { status: 404 });
    }

    // Defense in depth: cap body size before parsing.
    const cl = request.headers.get("content-length");
    if (cl && parseInt(cl, 10) > 16 * 1024) {
      return new Response("payload too large", { status: 413 });
    }

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response("bad json", { status: 400 });
    }

    if (!isQuillEvent(body)) {
      return new Response("invalid event shape", { status: 400 });
    }

    // Strip any unexpected top-level fields just in case the schema drifts.
    const safe: QuillEvent = {
      schema_version: body.schema_version,
      ts: body.ts,
      install_id: body.install_id,
      quill_version: body.quill_version,
      py_version: body.py_version,
      os: body.os,
      event: body.event,
      data: body.data,
    };

    try {
      await env.DB.prepare(
        `INSERT INTO events
         (received_at, schema_version, install_id, quill_version, py_version, os, event, data)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          new Date().toISOString(),
          safe.schema_version,
          safe.install_id,
          safe.quill_version,
          safe.py_version,
          safe.os,
          safe.event,
          JSON.stringify(safe.data),
        )
        .run();
    } catch (e) {
      // Don't leak DB error shape; log and 500.
      console.error("D1 insert failed", e);
      return new Response("server error", { status: 500 });
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  },
};
