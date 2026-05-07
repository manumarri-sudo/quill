// =====================================================================
// quill telemetry — Supabase Edge Function (ingest)
// =====================================================================
// Public receiver. Quill clients POST session.summary events here. We
// validate the shape, strip everything we don't expect, drop the client
// IP (we never want it), and insert into public.events. The Postgres
// after-insert trigger does the rest (rollup + per-event insights).
//
// Deploy:
//   supabase functions deploy ingest --no-verify-jwt
//   (no-verify-jwt because clients don't have JWTs; the receiver is
//    public, the gate is the schema validation here.)
//
// Set the function secret:
//   supabase secrets set SUPABASE_SERVICE_ROLE_KEY=...
//
// Then the public URL becomes
//   https://<project-ref>.functions.supabase.co/ingest/v1/events
// which clients set as QUILL_TELEMETRY_ENDPOINT.
// =====================================================================

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const ALLOWED_EVENT_KINDS = new Set([
  "session.summary",
  "install",
  "config.snapshot",
]);

const MAX_BODY_BYTES = 16 * 1024;
const SCHEMA_VERSION = 1;

// ---- type guards ----

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

function isUuidLike(s: unknown): s is string {
  return typeof s === "string" && s.length >= 16 && s.length <= 64
    && /^[a-zA-Z0-9-]+$/.test(s);
}

function isQuillEvent(x: unknown): x is QuillEvent {
  if (typeof x !== "object" || x === null) return false;
  const e = x as Record<string, unknown>;
  return (
    typeof e.schema_version === "number" &&
    e.schema_version === SCHEMA_VERSION &&
    typeof e.ts === "string" && e.ts.length <= 40 &&
    isUuidLike(e.install_id) &&
    typeof e.quill_version === "string" && e.quill_version.length <= 32 &&
    typeof e.py_version === "string" && e.py_version.length <= 32 &&
    typeof e.os === "string" && e.os.length <= 16 &&
    typeof e.event === "string" && ALLOWED_EVENT_KINDS.has(e.event) &&
    typeof e.data === "object" && e.data !== null
  );
}

// Whitelist of keys we accept inside `data`. Anything else is dropped.
// This is the privacy contract: even if a future client misbehaves and
// tries to send tool args / paths / intent, the receiver refuses.
const DATA_ALLOWED_KEYS = new Set<string>([
  "n_attempts",
  "n_allowed",
  "n_blocked",
  "n_scope_violations",
  "n_human_paused",
  "risk_dist",
  "top_namespaces",
  "n_upstreams",
  "duration_s",
  "has_budget_cap",
  "budget_exceeded",
]);

function sanitizeData(d: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(d)) {
    if (!DATA_ALLOWED_KEYS.has(k)) continue;
    out[k] = v;
  }
  // top_namespaces: enforce max 10 items, each max 32 chars, alnum+_-
  const ns = out.top_namespaces;
  if (Array.isArray(ns)) {
    out.top_namespaces = ns
      .filter((s) => typeof s === "string" && /^[a-zA-Z0-9_-]{1,32}$/.test(s))
      .slice(0, 10);
  }
  return out;
}

// ---- handler ----

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "content-type",
        "access-control-max-age": "86400",
      },
    });
  }
  if (req.method !== "POST") {
    return new Response("method not allowed", { status: 405 });
  }
  const url = new URL(req.url);
  // Edge function paths are /functions/v1/ingest/<rest>
  // We accept either /v1/events or /events (clients append /v1/events).
  if (!url.pathname.endsWith("/events") && !url.pathname.endsWith("/v1/events")) {
    return new Response("not found", { status: 404 });
  }

  const cl = req.headers.get("content-length");
  if (cl && Number(cl) > MAX_BODY_BYTES) {
    return new Response("payload too large", { status: 413 });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return new Response("bad json", { status: 400 });
  }

  if (!isQuillEvent(body)) {
    return new Response("invalid event shape", { status: 400 });
  }

  const safe: QuillEvent = {
    schema_version: body.schema_version,
    ts: body.ts,
    install_id: body.install_id,
    quill_version: body.quill_version,
    py_version: body.py_version,
    os: body.os.toLowerCase(),
    event: body.event,
    data: sanitizeData(body.data),
  };

  const supabase = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { error } = await supabase.from("events").insert({
    schema_version: safe.schema_version,
    install_id: safe.install_id,
    quill_version: safe.quill_version,
    py_version: safe.py_version,
    os: safe.os,
    event: safe.event,
    data: safe.data,
    // received_at defaults to now() on the server
  });

  if (error) {
    console.error("insert failed", error);
    return new Response("server error", { status: 500 });
  }

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
  });
});
