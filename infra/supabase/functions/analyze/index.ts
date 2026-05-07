// =====================================================================
// quill telemetry — Supabase Edge Function (analyze)
// =====================================================================
// Periodic analyzer: pulls recent quantitative rollups out of
// behavioral_insights, sends them to Claude for qualitative pattern
// extraction, writes the response back as a new behavioral_insights
// row. This is the "feedback loop" — analyses become data themselves.
//
// Trigger:
//   - schedule from pg_cron (preferred; row in cron.job)
//   - or hit the URL with a Bearer token from any cron service
//
// Env required:
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, ANTHROPIC_API_KEY
//   ANALYZE_BEARER (optional; if set, requests must carry it)
//
// Privacy: this function reads only behavioral_insights + install_profiles,
// never raw events, never tool args. The LLM only ever sees aggregate counts.
// =====================================================================

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const serviceKey  = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const anthropicKey = Deno.env.get("ANTHROPIC_API_KEY") || "";
const requireBearer = Deno.env.get("ANALYZE_BEARER") || "";

const ANALYSIS_KIND = "qualitative_summary_24h";

// keep this prompt LEAN — the LLM only ever sees aggregate signals.
const SYSTEM_PROMPT = `You are an analyst for a developer tool called Quill.
Quill is an MCP proxy that gates risky AI-agent tool calls (Bash, Edit,
Write, etc.) and signs every decision into a tamper-evident audit log.

You will be given aggregate telemetry rollups from the last 24 hours:
  - top tool namespaces by mention count
  - verdict distribution per Quill version (allow/ask/block/scope)
  - new vs returning install cohort

Your job is to extract NON-OBVIOUS PATTERNS that a maintainer should
act on. Examples of what's interesting:
  - a new version showing a different verdict mix than previous versions
    (might indicate a new pattern is firing or mis-firing)
  - a tool namespace appearing for the first time
  - cohort behavior (new installs blocking more than returning ones)
  - sudden drops or spikes that suggest a regression

Output must be valid JSON, no markdown fences, with this schema:
{
  "headline": "<one sentence; the most actionable observation>",
  "patterns": [
    { "title": "...", "evidence": "...", "suggested_action": "..." }
  ],
  "data_quality_notes": "<any caveat about sparseness or noise>",
  "confidence": "low" | "medium" | "high"
}

Be concrete. Cite specific versions or namespace names. If the data is
too sparse to say anything useful, say so honestly with confidence: low.`;

interface AnyRow { kind: string; computed_at: string; data: unknown }

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization",
  };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }
  if (req.method !== "POST") {
    return new Response("method not allowed", { status: 405, headers: corsHeaders() });
  }

  if (requireBearer) {
    const auth = req.headers.get("authorization") || "";
    if (auth !== `Bearer ${requireBearer}`) {
      return new Response("unauthorized", { status: 401, headers: corsHeaders() });
    }
  }

  if (!anthropicKey) {
    return new Response("ANTHROPIC_API_KEY not set", { status: 500, headers: corsHeaders() });
  }

  const supabase = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  // pull the most recent quantitative rollups
  const { data: rollups, error: e1 } = await supabase
    .from("behavioral_insights")
    .select("kind, computed_at, data")
    .in("kind", [
      "top_namespaces_last_24h",
      "verdict_dist_by_version_last_24h",
      "install_cohort_last_24h",
    ])
    .order("computed_at", { ascending: false })
    .limit(6);

  if (e1) {
    console.error(e1);
    return new Response("read failed", { status: 500, headers: corsHeaders() });
  }
  if (!rollups || rollups.length === 0) {
    return new Response(JSON.stringify({ ok: true, skipped: "no rollups yet" }), {
      status: 200,
      headers: { "content-type": "application/json", ...corsHeaders() },
    });
  }

  // de-dup by kind, keep the freshest
  const latest: Record<string, AnyRow> = {};
  for (const r of rollups as AnyRow[]) {
    if (!latest[r.kind] || r.computed_at > latest[r.kind].computed_at) {
      latest[r.kind] = r;
    }
  }

  const userPayload = JSON.stringify(latest, null, 2);

  // call Claude. Use the small, fast model — this runs hourly.
  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": anthropicKey,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model: "claude-haiku-4-5",
      max_tokens: 800,
      system: SYSTEM_PROMPT,
      messages: [
        { role: "user", content: `Recent rollups (raw JSON):\n\n${userPayload}` },
      ],
    }),
  });

  if (!resp.ok) {
    const txt = await resp.text();
    console.error("anthropic call failed", resp.status, txt);
    return new Response("llm call failed", { status: 502, headers: corsHeaders() });
  }

  const llm = await resp.json() as { content: Array<{ type: string; text?: string }> };
  const textBlock = (llm.content || []).find((c) => c.type === "text");
  const raw = textBlock?.text || "{}";

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = { headline: "non-JSON response", raw };
  }

  const { error: e2 } = await supabase.from("behavioral_insights").insert({
    kind: ANALYSIS_KIND,
    scope: "global",
    data: parsed,
    notes: "qualitative pattern extraction from the last 24h of rollups",
  });

  if (e2) {
    console.error(e2);
    return new Response("insert failed", { status: 500, headers: corsHeaders() });
  }

  return new Response(JSON.stringify({ ok: true, written_kind: ANALYSIS_KIND }), {
    status: 200,
    headers: { "content-type": "application/json", ...corsHeaders() },
  });
});
