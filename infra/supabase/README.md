# Supabase telemetry receiver for quill

The recommended receiver for opt-in `quill` telemetry. Three layers:

| layer | what it is | how it runs |
|---|---|---|
| `events` (table) | raw POSTs from clients, aggregate-only fields | inserted by the `ingest` Edge Function |
| `install_profiles` (table) | running rollup per `install_id` | maintained by an after-insert Postgres trigger |
| `behavioral_insights` (table) | derived signals (per-event flags + hourly global rollups + LLM-extracted qualitative summaries) | written by trigger + pg_cron + the `analyze` Edge Function |

The point: **every ingest produces both new raw data AND new derived data**. Derived data lands in `behavioral_insights` as queryable rows, so analyses become first-class data themselves. Future analyses can read prior analyses to detect drift.

## Privacy contract (load-bearing)

Even though `events.data` is `jsonb` and could in principle hold anything, the **ingest Edge Function whitelists the keys it accepts** (`n_attempts`, `n_allowed`, `n_blocked`, `n_scope_violations`, `n_human_paused`, `risk_dist`, `top_namespaces`, `n_upstreams`, `duration_s`, `has_budget_cap`, `budget_exceeded`). Anything else a misbehaving client tried to send is dropped at the receiver. The schema enforces:

- `top_namespaces` items are 1–32 chars of `[a-zA-Z0-9_-]`, max 10 items
- `install_id` is UUID-shaped, 16–64 chars
- payload size capped at 16 KB

What is NEVER stored: tool args, file paths, command bodies, intent strings, audit-log contents, the user's HMAC key, IP addresses (we don't read CF-Connecting-IP).

## Setup

```bash
# 1. install the supabase CLI (one time)
brew install supabase/tap/supabase    # or: npm i -g supabase

# 2. link your local checkout to the Supabase project
cd infra/supabase
supabase login
supabase link --project-ref <YOUR_PROJECT_REF>

# 3. apply the schema
psql "$SUPABASE_DB_URL" -f sql/0001_init.sql
#    (or paste sql/0001_init.sql into Supabase Dashboard → SQL Editor → Run)

# 4. set the analyzer's secrets
supabase secrets set ANTHROPIC_API_KEY="sk-ant-..."
supabase secrets set ANALYZE_BEARER="$(openssl rand -hex 24)"   # optional, recommended

# 5. deploy both functions
supabase functions deploy ingest  --no-verify-jwt
supabase functions deploy analyze --no-verify-jwt

# 6. point quill clients at the ingest URL
#    (this is what users will set in QUILL_TELEMETRY_ENDPOINT or
#     [telemetry.endpoint] in their config.toml)
echo "https://<YOUR_PROJECT_REF>.functions.supabase.co/ingest/v1/events"
```

To run the analyzer hourly via pg_cron (preferred, free):

```sql
-- in Supabase SQL Editor, AFTER deploying the analyze function:
select
  cron.schedule(
    'quill_run_analyzer',
    '15 * * * *',   -- 15 past every hour, after the recompute_global_insights cron
    $$
    select net.http_post(
      url     := 'https://<YOUR_PROJECT_REF>.functions.supabase.co/analyze',
      headers := jsonb_build_object(
        'content-type',  'application/json',
        'authorization', 'Bearer <YOUR_ANALYZE_BEARER>'
      ),
      body    := '{}'::jsonb
    );
    $$
  );
```

## Useful queries

```sql
-- top 10 dangerous-pattern namespaces in the last 24h
select data->'top'
from behavioral_insights
where kind = 'top_namespaces_last_24h'
order by computed_at desc
limit 1;

-- block rate per quill version this week
select
  data->'rows'
from behavioral_insights
where kind = 'verdict_dist_by_version_last_24h'
  and computed_at > now() - interval '7 days'
order by computed_at desc
limit 1;

-- the most recent qualitative summary
select data->>'headline' as headline, data->'patterns' as patterns
from behavioral_insights
where kind = 'qualitative_summary_24h'
order by computed_at desc
limit 1;

-- which installs are showing high block-rate sessions?
select scope, count(*), max(computed_at) as last
from behavioral_insights
where kind = 'high_block_rate_session'
group by scope
order by count(*) desc
limit 20;
```

## Pointing clients at this receiver

In a user's `~/.quill/config.toml`:

```toml
[telemetry]
enabled = true
endpoint = "https://<YOUR_PROJECT_REF>.functions.supabase.co/ingest/v1/events"
```

…or via env: `QUILL_TELEMETRY_ENDPOINT=https://...`

For the public default (`https://telemetry.quill.dev/v1/events`), wire DNS at quill.dev to your Supabase function URL with a CNAME or proxy through Cloudflare.

## Cost shape (Supabase free tier as of 2026-05)

- 500 MB Postgres (≈ 5M rows of `events` at our row size)
- 500K Edge Function invocations / month (≈ one event per install per session)
- 2 GB egress
- pg_cron: free
- D1 alternative in `../cf-worker/` if you'd rather not use Supabase

## Why Supabase over the Cloudflare Worker

`infra/cf-worker/` is the alternative — simpler, stateless, D1-backed. Supabase is preferred when you want:

- the **feedback loop** baked in (triggers, derived tables, pg_cron, edge functions calling the LLM)
- **richer queries** (Postgres window functions, jsonb path queries)
- **dashboards** out of the box (Supabase Studio + Grafana plugin)
- **future product** built on top of the same Postgres (auth, storage, realtime)

The Cloudflare Worker stays as the minimal-deployment-footprint path.
