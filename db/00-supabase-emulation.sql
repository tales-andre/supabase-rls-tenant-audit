-- Minimal emulation of the parts of Supabase that matter for Row Level Security.
-- Plain Postgres, no Supabase images. What is emulated:
--   * the API roles: anon (logged-out), authenticated (logged-in), service_role (bypasses RLS)
--   * auth.uid(), auth.role(), auth.jwt(): read the JWT claims from the `request.jwt.claims`
--     setting, the same way Supabase's PostgREST layer passes them to Postgres
--   * Supabase's default grants: anon and authenticated get ALL on new tables and functions in
--     `public`, so RLS is the only thing between the public API and the data
--   * a small `storage` schema (buckets, objects, storage.foldername) for bucket policies

-- Roles are cluster-wide, so create them only once.
do $$
begin
  if not exists (select from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  if not exists (select from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
end $$;

-- auth schema -------------------------------------------------------------
create schema auth;

create table auth.users (
  id uuid primary key,
  email text unique not null,
  raw_user_meta_data jsonb not null default '{}'::jsonb,  -- editable by the user (auth.updateUser)
  raw_app_meta_data  jsonb not null default '{}'::jsonb   -- editable only with the service role
);

create function auth.jwt() returns jsonb
language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')
  )::jsonb
$$;

create function auth.uid() returns uuid
language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;

create function auth.role() returns text
language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;

grant usage on schema auth to anon, authenticated, service_role;
grant execute on all functions in schema auth to anon, authenticated, service_role;

-- Supabase default privileges on the exposed `public` schema ---------------
grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables    to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;

-- storage schema ------------------------------------------------------------
create schema storage;

create table storage.buckets (
  id text primary key,
  name text not null,
  public boolean not null default false
);

create table storage.objects (
  id uuid primary key default gen_random_uuid(),
  bucket_id text not null references storage.buckets (id),
  name text not null,             -- path inside the bucket, e.g. '<org_id>/INV-0001.pdf'
  owner uuid,
  created_at timestamptz not null default now(),
  unique (bucket_id, name)
);

-- Returns the folders of an object path: 'a/b/c.pdf' -> {a,b}
create function storage.foldername(name text) returns text[]
language sql immutable as $$
  select (string_to_array(name, '/'))[1:array_length(string_to_array(name, '/'), 1) - 1]
$$;

-- Supabase ships storage tables with RLS on; access comes only from policies.
alter table storage.buckets enable row level security;
alter table storage.objects enable row level security;

grant usage on schema storage to anon, authenticated, service_role;
grant all on storage.buckets, storage.objects to anon, authenticated, service_role;
grant execute on function storage.foldername(text) to anon, authenticated, service_role;
