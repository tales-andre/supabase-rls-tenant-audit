-- FIXED policy set. Same schema and data as broken.sql; only grants, policies, the view and
-- the RPC change. Rules applied everywhere:
--   1. The tenant comes from public.memberships (written by the server), never from a column,
--      claim or argument the user controls.
--   2. Every write policy has a WITH CHECK that pins the row to a tenant the caller belongs to.
--   3. Policies name their role (TO authenticated). anon gets nothing unless it is meant to.
--   4. No SECURITY DEFINER in exposed schemas; views use security_invoker.

-- Helpers in a schema the API does not expose. SECURITY DEFINER here is deliberate: it reads
-- memberships without triggering memberships' own RLS (avoids recursive policies), and it
-- only ever answers about the caller (auth.uid()), never about an id passed by the client.
create schema private;
grant usage on schema private to authenticated;

create function private.is_member(p_org_id uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.memberships m
    where m.org_id = p_org_id and m.user_id = (select auth.uid())
  )
$$;

create function private.is_admin(p_org_id uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.memberships m
    where m.org_id = p_org_id and m.user_id = (select auth.uid()) and m.role = 'admin'
  )
$$;

create function private.my_org_ids() returns setof uuid
language sql stable security definer set search_path = '' as $$
  select m.org_id from public.memberships m where m.user_id = (select auth.uid())
$$;

revoke all on function private.is_member(uuid), private.is_admin(uuid), private.my_org_ids() from public;
grant execute on function private.is_member(uuid), private.is_admin(uuid), private.my_org_ids() to authenticated;

-- organizations --------------------------------------------------------------------------
alter table public.organizations enable row level security;

create policy "Members can view their organizations" on public.organizations
  for select to authenticated
  using ((select private.is_member(id)));

-- memberships: read your own rows (admins see their org). No insert/update/delete policy:
-- invites run server-side, after the server checks that the caller is an admin of that org.
alter table public.memberships enable row level security;

create policy "Members can view memberships" on public.memberships
  for select to authenticated
  using (user_id = (select auth.uid()) or (select private.is_admin(org_id)));

-- profiles: the user may change their name only. org_id is not used by any policy.
alter table public.profiles enable row level security;

create policy "Users can view own profile" on public.profiles
  for select to authenticated
  using (id = (select auth.uid()));

create policy "Users can update own profile" on public.profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

revoke update on public.profiles from authenticated, anon;
grant update (full_name) on public.profiles to authenticated;

-- projects -------------------------------------------------------------------------------
alter table public.projects enable row level security;

create policy "Members can view projects" on public.projects
  for select to authenticated
  using ((select private.is_member(org_id)));

create policy "Members can create projects" on public.projects
  for insert to authenticated
  with check ((select private.is_member(org_id)));

create policy "Members can update projects" on public.projects
  for update to authenticated
  using ((select private.is_member(org_id)))
  with check ((select private.is_member(org_id)));

create policy "Admins can delete projects" on public.projects
  for delete to authenticated
  using ((select private.is_admin(org_id)));

-- customers ------------------------------------------------------------------------------
alter table public.customers enable row level security;

create policy "Members can view and manage customers" on public.customers
  for all to authenticated
  using ((select private.is_member(org_id)))
  with check ((select private.is_member(org_id)));

-- invoices -------------------------------------------------------------------------------
alter table public.invoices enable row level security;

create policy "Members can view invoices" on public.invoices
  for select to authenticated
  using ((select private.is_member(org_id)));

create policy "Members can create invoices" on public.invoices
  for insert to authenticated
  with check ((select private.is_member(org_id)) and created_by = (select auth.uid()));

create policy "Members can update invoices" on public.invoices
  for update to authenticated
  using ((select private.is_member(org_id)))
  with check ((select private.is_member(org_id)));

create policy "Admins can delete invoices" on public.invoices
  for delete to authenticated
  using ((select private.is_admin(org_id)));

-- integration_secrets: RLS on, no policies, no grants. Only the service role (server) reads it.
alter table public.integration_secrets enable row level security;
revoke all on public.integration_secrets from anon, authenticated;

-- invoice_summary view: runs with the caller's rights, so invoices' RLS applies.
create view public.invoice_summary with (security_invoker = true) as
  select org_id, count(*) as invoice_count, sum(amount_cents) as total_cents
  from public.invoices
  group by org_id;
revoke all on public.invoice_summary from anon;

-- RPC: SECURITY INVOKER, pinned search_path, not callable by anon. RLS filters the rows, so a
-- foreign org id simply returns nothing.
create function public.get_org_invoices(p_org_id uuid)
returns setof public.invoices
language sql stable security invoker set search_path = '' as $$
  select * from public.invoices where org_id = p_org_id
$$;
revoke all on function public.get_org_invoices(uuid) from public, anon;
grant execute on function public.get_org_invoices(uuid) to authenticated;

-- storage: first folder of the path must be an organization the caller belongs to.
create policy "Members can read their org's invoice PDFs" on storage.objects
  for select to authenticated
  using (
    bucket_id = 'invoice-pdfs'
    and (storage.foldername(name))[1] in (select t.id::text from private.my_org_ids() as t(id))
  );

create policy "Members can upload to their org's folder" on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'invoice-pdfs'
    and (storage.foldername(name))[1] in (select t.id::text from private.my_org_ids() as t(id))
  );
