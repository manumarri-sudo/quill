# quill telemetry receiver

Cloudflare Worker + D1 SQLite database that receives opt-in telemetry from `quill` clients.

## What it stores

Exactly the fields documented in `src/quill/telemetry.py`:

| column | source |
|---|---|
| `received_at` | server-generated ISO timestamp |
| `schema_version` | from client; pinned to `1` |
| `install_id` | client UUIDv4, generated once per machine |
| `quill_version` | e.g. `0.1.0` |
| `py_version` | e.g. `3.12.4` |
| `os` | `linux` / `darwin` / `windows` |
| `event` | one of `session.summary`, `install`, `config.snapshot` |
| `data` | aggregate-only JSON; counts + risk distribution + namespace top-N |

It does NOT store: client IP (we do not record it), tool arguments (clients never send them), file paths, intent text, scope strings, audit-log contents, or anything user-identifiable beyond the random `install_id`.

## Deploy

```bash
npm install -g wrangler
cd infra/cf-worker
npm install

# Create the D1 database
wrangler d1 create quill-telemetry
# → wrangler prints a `database_id`. Paste it into wrangler.toml.

# Apply schema
wrangler d1 execute quill-telemetry --file ./schema.sql

# Deploy
wrangler deploy
```

The deployed Worker URL becomes `QUILL_TELEMETRY_ENDPOINT`. Either point clients at it via environment, or set the production endpoint in `src/quill/telemetry.py::DEFAULT_ENDPOINT` and ship a release.

## Query the data

```bash
wrangler d1 execute quill-telemetry --command "SELECT quill_version, COUNT(*) FROM events GROUP BY quill_version"

wrangler d1 execute quill-telemetry --command "SELECT json_extract(data, '$.n_blocked') AS blocked, COUNT(*) FROM events WHERE event='session.summary' GROUP BY blocked ORDER BY blocked"

wrangler d1 execute quill-telemetry --command "SELECT json_extract(data, '$.top_namespaces') AS ns, COUNT(*) FROM events WHERE event='session.summary' GROUP BY ns ORDER BY 2 DESC LIMIT 20"
```

## Privacy

The Worker logs nothing it doesn't insert. Cloudflare's edge logs are 24h retention by default; turn that off in the dashboard if you want zero log retention. We do not enable Cloudflare Analytics on this Worker.

## Cost

D1 free tier is 5M reads/day, 100k writes/day, 5GB storage. At one event per client per session, that supports ~100k active users on the free tier; well past where we'd start sending revenue back to Cloudflare for capacity, not for any one user.
