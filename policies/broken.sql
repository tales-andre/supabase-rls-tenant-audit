-- BROKEN policy set.
-- Each block is a mistake that shows up often in AI-generated Supabase code: the policy names
-- are the kind an AI agent or a dashboard template produces, and every one of them "looks fine"
-- at a glance. The test IDs in brackets refer to audit/checks.py and the README table.

-- organizations: fine on its own (but see memberships below) ---------------------------
alter table public.organizations enable row level security;

create policy "Members can view their organizations" on public.organizations
  for select to authenticated
  using (id in (select m.org_id from public.memberships m where m.user_id = auth.uid()));

-- memberships ----------------------------------------------------------------------------
alter table public.memberships enable row level security;

create policy "Users can view their memberships" on public.memberships
  for select to authenticated
  using (user_id = auth.uid());

-- MISTAKE [W5]: "a user can only insert rows for themselves" sounds safe, but nothing limits
-- org_id or role. Any user can make themselves admin of any organization.
create policy "Users can join organizations" on public.memberships
  for insert to authenticated
  with check (user_id = auth.uid());

-- profiles -------------------------------------------------------------------------------
alter table public.profiles enable row level security;

create policy "Users can view own profile" on public.profiles
  for select to authenticated
  using (id = auth.uid());

-- MISTAKE [R3]: the user can update every column of their own profile, including org_id,
-- and the invoice policies below trust profiles.org_id as the tenant.
create policy "Users can update own profile" on public.profiles
  for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

-- projects -------------------------------------------------------------------------------
alter table public.projects enable row level security;

-- MISTAKE [R1, R1b]: dashboard-template policy. No TO clause, so it applies to anon too.
create policy "Enable read access for all users" on public.projects
  for select
  using (true);

create policy "Enable insert for org members" on public.projects
  for insert to authenticated
  with check (org_id in (select m.org_id from public.memberships m where m.user_id = auth.uid()));

-- MISTAKE [W3]: checks that the caller is logged in, not that the row is theirs.
create policy "Enable update for authenticated users only" on public.projects
  for update to authenticated
  using (auth.role() = 'authenticated');

-- MISTAKE [W4]: checks that the caller is an admin of SOME organization, not of this row's.
create policy "Admins can delete projects" on public.projects
  for delete to authenticated
  using (exists (
    select 1 from public.memberships m
    where m.user_id = auth.uid() and m.role = 'admin'
  ));

-- customers ------------------------------------------------------------------------------
alter table public.customers enable row level security;

-- MISTAKE [R4]: tenant taken from user_metadata. Supabase users can change their own
-- user_metadata with auth.updateUser({ data: ... }), and it is copied into their next JWT.
create policy "Org members can view customers" on public.customers
  for select to authenticated
  using (org_id = (auth.jwt() -> 'user_metadata' ->> 'org_id')::uuid);

-- invoices -------------------------------------------------------------------------------
alter table public.invoices enable row level security;

-- Looks right, and a direct cross-tenant read IS blocked [R2]. But see profiles above [R3].
create policy "Users can view invoices of their org" on public.invoices
  for select to authenticated
  using (org_id = (select p.org_id from public.profiles p where p.id = auth.uid()));

-- MISTAKE [W1]: WITH CHECK only asks "is someone logged in?" -> insert into any tenant.
create policy "Users can create invoices" on public.invoices
  for insert to authenticated
  with check (auth.uid() is not null);

-- MISTAKE [W2]: USING is tenant-scoped, WITH CHECK (true) lets the row move to another tenant.
create policy "Users can update invoices of their org" on public.invoices
  for update to authenticated
  using (org_id = (select p.org_id from public.profiles p where p.id = auth.uid()))
  with check (true);

-- integration_secrets --------------------------------------------------------------------
-- MISTAKE [R5]: table added by a later migration; RLS was never enabled. With Supabase's
-- default grants, anyone holding the public anon key can read it.

-- invoice_summary view -------------------------------------------------------------------
-- MISTAKE [R6]: a plain view runs with the owner's rights (here: postgres), so RLS on
-- invoices is skipped. Supabase's linter calls this "security definer view".
create view public.invoice_summary as
  select org_id, count(*) as invoice_count, sum(amount_cents) as total_cents
  from public.invoices
  group by org_id;

-- RPC ------------------------------------------------------------------------------------
-- MISTAKE [R7, R7b]: SECURITY DEFINER "to fix a permission error", trusts the org id argument,
-- no search_path, and EXECUTE is granted to anon by Supabase's default privileges.
create function public.get_org_invoices(p_org_id uuid)
returns setof public.invoices
language sql security definer as $$
  select * from public.invoices where org_id = p_org_id
$$;

-- storage --------------------------------------------------------------------------------
-- MISTAKE [R8]: bucket is private, but the policy only checks the bucket, not the tenant folder.
create policy "Authenticated users can read invoice PDFs" on storage.objects
  for select to authenticated
  using (bucket_id = 'invoice-pdfs');

create policy "Authenticated users can upload invoice PDFs" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'invoice-pdfs');
