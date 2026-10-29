-- Two fictional tenants with one admin each. Fixed ids so tests can refer to them.
--   Org A: Acme Supply Co.     admin: alice   ids start with aaaaaaaa
--   Org B: Blue Harbor Studio  admin: bob     ids start with bbbbbbbb

insert into auth.users (id, email, raw_user_meta_data) values
  ('aaaaaaaa-1111-0000-0000-000000000001', 'alice@acme.example',
     '{"full_name": "Alice A.", "org_id": "aaaaaaaa-0000-0000-0000-000000000000"}'),
  ('bbbbbbbb-1111-0000-0000-000000000001', 'bob@blueharbor.example',
     '{"full_name": "Bob B.", "org_id": "bbbbbbbb-0000-0000-0000-000000000000"}');

insert into public.organizations (id, name) values
  ('aaaaaaaa-0000-0000-0000-000000000000', 'Acme Supply Co.'),
  ('bbbbbbbb-0000-0000-0000-000000000000', 'Blue Harbor Studio');

insert into public.memberships (org_id, user_id, role) values
  ('aaaaaaaa-0000-0000-0000-000000000000', 'aaaaaaaa-1111-0000-0000-000000000001', 'admin'),
  ('bbbbbbbb-0000-0000-0000-000000000000', 'bbbbbbbb-1111-0000-0000-000000000001', 'admin');

insert into public.profiles (id, full_name, org_id) values
  ('aaaaaaaa-1111-0000-0000-000000000001', 'Alice A.', 'aaaaaaaa-0000-0000-0000-000000000000'),
  ('bbbbbbbb-1111-0000-0000-000000000001', 'Bob B.',   'bbbbbbbb-0000-0000-0000-000000000000');

insert into public.projects (id, org_id, name) values
  ('aaaaaaaa-2222-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000000', 'Warehouse move'),
  ('bbbbbbbb-2222-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000000', 'Brand refresh');

insert into public.customers (id, org_id, name, email) values
  ('aaaaaaaa-4444-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000000', 'Fictional Buyer One', 'buyer1@example.com'),
  ('bbbbbbbb-4444-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000000', 'Fictional Buyer Two', 'buyer2@example.com');

insert into public.invoices (id, org_id, project_id, number, amount_cents, status, created_by) values
  ('aaaaaaaa-3333-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000000',
     'aaaaaaaa-2222-0000-0000-000000000001', 'A-0001', 120000, 'sent', 'aaaaaaaa-1111-0000-0000-000000000001'),
  ('bbbbbbbb-3333-0000-0000-000000000001', 'bbbbbbbb-0000-0000-0000-000000000000',
     'bbbbbbbb-2222-0000-0000-000000000001', 'B-0001', 98000, 'sent', 'bbbbbbbb-1111-0000-0000-000000000001'),
  ('bbbbbbbb-3333-0000-0000-000000000002', 'bbbbbbbb-0000-0000-0000-000000000000',
     'bbbbbbbb-2222-0000-0000-000000000001', 'B-0002', 45000, 'draft', 'bbbbbbbb-1111-0000-0000-000000000001');

insert into public.integration_secrets (org_id, provider, secret) values
  ('aaaaaaaa-0000-0000-0000-000000000000', 'payments', 'fake-secret-for-org-a'),
  ('bbbbbbbb-0000-0000-0000-000000000000', 'payments', 'fake-secret-for-org-b');

insert into storage.buckets (id, name, public) values ('invoice-pdfs', 'invoice-pdfs', false);

insert into storage.objects (bucket_id, name, owner) values
  ('invoice-pdfs', 'aaaaaaaa-0000-0000-0000-000000000000/A-0001.pdf', 'aaaaaaaa-1111-0000-0000-000000000001'),
  ('invoice-pdfs', 'bbbbbbbb-0000-0000-0000-000000000000/B-0001.pdf', 'bbbbbbbb-1111-0000-0000-000000000001');
