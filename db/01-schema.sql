-- Fictional multi-tenant invoicing SaaS. Every business row belongs to one organization (tenant).
-- Tables are created WITHOUT RLS here; each policy set (policies/broken.sql, policies/fixed.sql)
-- decides what gets enabled.

create table public.organizations (
  id uuid primary key,
  name text not null
);

-- Source of truth for "who belongs to which tenant". Written by the server, not by the user.
create table public.memberships (
  org_id uuid not null references public.organizations (id),
  user_id uuid not null references auth.users (id),
  role text not null check (role in ('admin', 'member')),
  primary key (org_id, user_id)
);

-- One row per user. `org_id` is a convenience copy that the app shows in the UI.
create table public.profiles (
  id uuid primary key references auth.users (id),
  full_name text,
  org_id uuid references public.organizations (id)
);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id),
  name text not null
);

create table public.customers (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id),
  name text not null,
  email text not null
);

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id),
  project_id uuid references public.projects (id) on delete set null,
  number text not null,
  amount_cents integer not null,
  status text not null default 'draft',
  created_by uuid references auth.users (id)
);

-- Added "later" by a migration: API keys for third-party integrations, per organization.
create table public.integration_secrets (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id),
  provider text not null,
  secret text not null
);
