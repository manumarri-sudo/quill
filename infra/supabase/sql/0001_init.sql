-- =====================================================================
-- quill telemetry — Supabase / Postgres schema (template, not auto-applied)
-- =====================================================================
-- Stores ONLY what's documented in src/quill/telemetry.py:
--   install_id (random uuid per machine), quill_version, py_version, os,
--   event kind, aggregate-only data jsonb.
-- Never stores: tool args, file paths, intent text, audit-log contents,
--   client IP (even if Supabase exposes it, the Edge Function drops it).
--
-- Apply manually:
--   psql "$SUPABASE_DB_URL" -f infra/supabase/sql/0001_init.sql
--   (or paste into the Supabase SQL Editor in the dashboard).
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- raw events — one row per POST from a quill client
-- ---------------------------------------------------------------------
create table if not exists public.events (
    id              bigserial      primary key,
    received_at     timestamptz    not null default now(),
    schema_version  smallint       not null,
    install_id      uuid           not null,
    quill_version   text           not null,
    py_version      text           not null,
    os              text           not null,
    event           text           not null
        check (event in ('session.summary', 'install', 'config.snapshot')),
    data            jsonb          not null default '{}'::jsonb
);

create index if not exists events_install_id_idx     on public.events (install_id);
create index if not exists events_received_at_idx    on public.events (received_at desc);
create index if not exists events_quill_version_idx  on public.events (quill_version);
create index if not exists events_event_idx          on public.events (event);
create index if not exists events_session_summary_idx on public.events (received_at desc)
    where event = 'session.summary';


-- ---------------------------------------------------------------------
-- install_profiles — running rollup per install_id
-- recomputed on every event ingest by the after-insert trigger below
-- ---------------------------------------------------------------------
create table if not exists public.install_profiles (
    install_id              uuid           primary key,
    first_seen              timestamptz    not null,
    last_seen               timestamptz    not null,
    os                      text,
    last_quill_version      text,
    last_py_version         text,
    total_sessions          integer        not null default 0,
    total_attempts          bigint         not null default 0,
    total_allowed           bigint         not null default 0,
    total_blocked           bigint         not null default 0,
    total_scope_violations  bigint         not null default 0,
    total_human_paused      bigint         not null default 0,
    namespace_counts        jsonb          not null default '{}'::jsonb,
    risk_dist               jsonb          not null default '{}'::jsonb,
    has_budget_cap_ever     boolean        not null default false,
    budget_exceeded_ever    boolean        not null default false,
    updated_at              timestamptz    not null default now()
);

create index if not exists install_profiles_last_seen_idx
    on public.install_profiles (last_seen desc);
create index if not exists install_profiles_version_idx
    on public.install_profiles (last_quill_version);


-- ---------------------------------------------------------------------
-- behavioral_insights — derived signals that come back as data.
-- The "feedback loop": analyzer writes here on every ingest +
-- on a periodic schedule. Rows here are read by dashboards / future
-- product decisions, and are themselves analyzable like any other data.
-- ---------------------------------------------------------------------
create table if not exists public.behavioral_insights (
    id              bigserial    primary key,
    computed_at     timestamptz  not null default now(),
    kind            text         not null,
    scope           text,
    data            jsonb        not null,
    source_event_id bigint                   references public.events(id) on delete set null,
    notes           text
);
create index if not exists behavioral_insights_kind_idx
    on public.behavioral_insights (kind, computed_at desc);
create index if not exists behavioral_insights_scope_idx
    on public.behavioral_insights (scope, computed_at desc);


-- ---------------------------------------------------------------------
-- on-insert function: refresh install_profiles + emit per-ingest insights
-- ---------------------------------------------------------------------
create or replace function public.ingest_event_aftermath()
returns trigger
language plpgsql
as $$
declare
    d         jsonb := coalesce(new.data, '{}'::jsonb);
    n_att     bigint  := coalesce((d->>'n_attempts')::bigint, 0);
    n_allow   bigint  := coalesce((d->>'n_allowed')::bigint, 0);
    n_block   bigint  := coalesce((d->>'n_blocked')::bigint, 0);
    n_scope   bigint  := coalesce((d->>'n_scope_violations')::bigint, 0);
    n_paused  bigint  := coalesce((d->>'n_human_paused')::bigint, 0);
    has_cap   boolean := coalesce((d->>'has_budget_cap')::boolean, false);
    exceeded  boolean := coalesce((d->>'budget_exceeded')::boolean, false);
    ns_arr    jsonb   := coalesce(d->'top_namespaces', '[]'::jsonb);
    risks     jsonb   := coalesce(d->'risk_dist', '{}'::jsonb);
    block_rate numeric;
begin
    insert into public.install_profiles as p (
        install_id, first_seen, last_seen, os,
        last_quill_version, last_py_version,
        total_sessions, total_attempts, total_allowed,
        total_blocked, total_scope_violations, total_human_paused,
        namespace_counts, risk_dist,
        has_budget_cap_ever, budget_exceeded_ever, updated_at
    ) values (
        new.install_id, new.received_at, new.received_at, new.os,
        new.quill_version, new.py_version,
        case when new.event = 'session.summary' then 1 else 0 end,
        n_att, n_allow, n_block, n_scope, n_paused,
        '{}'::jsonb, risks,
        has_cap, exceeded, now()
    )
    on conflict (install_id) do update set
        last_seen              = greatest(p.last_seen, excluded.last_seen),
        os                     = coalesce(excluded.os, p.os),
        last_quill_version     = excluded.last_quill_version,
        last_py_version        = excluded.last_py_version,
        total_sessions         = p.total_sessions
                                  + case when new.event = 'session.summary' then 1 else 0 end,
        total_attempts         = p.total_attempts + n_att,
        total_allowed          = p.total_allowed + n_allow,
        total_blocked          = p.total_blocked + n_block,
        total_scope_violations = p.total_scope_violations + n_scope,
        total_human_paused     = p.total_human_paused + n_paused,
        risk_dist              = excluded.risk_dist,
        has_budget_cap_ever    = p.has_budget_cap_ever or has_cap,
        budget_exceeded_ever   = p.budget_exceeded_ever or exceeded,
        updated_at             = now();

    if new.event = 'session.summary' and n_att > 0 then
        block_rate := (n_block + n_scope)::numeric / n_att;
        if block_rate >= 0.30 then
            insert into public.behavioral_insights (kind, scope, data, source_event_id, notes)
            values (
                'high_block_rate_session',
                'install:' || new.install_id::text,
                jsonb_build_object(
                    'block_rate', block_rate,
                    'n_attempts', n_att,
                    'n_blocked', n_block,
                    'n_scope_violations', n_scope,
                    'quill_version', new.quill_version,
                    'top_namespaces', ns_arr
                ),
                new.id,
                'session with >=30% blocked or scope-violated calls'
            );
        end if;
    end if;

    return new;
end;
$$;

drop trigger if exists events_after_insert on public.events;
create trigger events_after_insert
    after insert on public.events
    for each row execute function public.ingest_event_aftermath();


-- ---------------------------------------------------------------------
-- recompute_global_insights() — call from pg_cron hourly to roll up
-- non-per-event signals.
-- ---------------------------------------------------------------------
create or replace function public.recompute_global_insights(window_hours integer default 24)
returns void
language plpgsql
as $$
declare
    cutoff timestamptz := now() - make_interval(hours => window_hours);
    label  text := 'last_' || window_hours::text || 'h';
begin
    insert into public.behavioral_insights (kind, scope, data, notes)
    select
        'top_namespaces_' || label,
        'global',
        jsonb_build_object(
            'window_hours', window_hours,
            'top', (
                select jsonb_agg(jsonb_build_object('ns', ns, 'mentions', cnt))
                from (
                    select ns, count(*) as cnt
                    from public.events e,
                         lateral jsonb_array_elements_text(e.data->'top_namespaces') as ns
                    where e.received_at >= cutoff
                      and e.event = 'session.summary'
                    group by ns
                    order by cnt desc
                    limit 10
                ) t
            )
        ),
        'rolling top tool-namespaces seen in session summaries';

    insert into public.behavioral_insights (kind, scope, data, notes)
    select
        'verdict_dist_by_version_' || label,
        'global',
        jsonb_build_object(
            'window_hours', window_hours,
            'rows', (
                select jsonb_agg(row_to_json(t)) from (
                    select
                        quill_version,
                        count(*) as sessions,
                        sum(coalesce((data->>'n_attempts')::bigint, 0))         as attempts,
                        sum(coalesce((data->>'n_allowed')::bigint, 0))          as allowed,
                        sum(coalesce((data->>'n_blocked')::bigint, 0))          as blocked,
                        sum(coalesce((data->>'n_scope_violations')::bigint, 0)) as scope_violations,
                        sum(coalesce((data->>'n_human_paused')::bigint, 0))     as human_paused
                    from public.events
                    where received_at >= cutoff and event = 'session.summary'
                    group by quill_version
                    order by sessions desc
                ) t
            )
        ),
        'verdict mix per quill version — watch for regressions on a new release';

    insert into public.behavioral_insights (kind, scope, data, notes)
    select
        'install_cohort_' || label,
        'global',
        jsonb_build_object(
            'window_hours', window_hours,
            'new_installs',      (select count(*) from public.install_profiles where first_seen >= cutoff),
            'active_installs',   (select count(*) from public.install_profiles where last_seen >= cutoff),
            'returning_installs',(select count(*) from public.install_profiles
                                  where last_seen >= cutoff and first_seen < cutoff),
            'os_breakdown',      (select jsonb_object_agg(coalesce(os, 'unknown'), c)
                                  from (
                                      select os, count(*) c from public.install_profiles
                                      where last_seen >= cutoff group by os
                                  ) t)
        ),
        'cohort split: who is new, who came back';
end;
$$;


-- ---------------------------------------------------------------------
-- pg_cron schedule (Supabase has pg_cron; safe no-op if extension missing)
-- ---------------------------------------------------------------------
do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron') then
        perform cron.unschedule(jobid)
            from cron.job
            where jobname = 'quill_recompute_global_insights';
        perform cron.schedule(
            'quill_recompute_global_insights',
            '0 * * * *',
            $cmd$ select public.recompute_global_insights(24); $cmd$
        );
    end if;
end $$;


-- ---------------------------------------------------------------------
-- Row-Level Security: default deny. Edge Function uses service_role key.
-- ---------------------------------------------------------------------
alter table public.events                enable row level security;
alter table public.install_profiles      enable row level security;
alter table public.behavioral_insights   enable row level security;
