# Review checklist: AI-built Next.js + Supabase app

Short list for the first pass of a tenant-isolation review. Each item is a question with a way
to check it. Items marked **(tested here)** have an attack test or check in this repo; the rest
are read by hand.

## 1. Tenant boundary

- [ ] Which tables hold tenant data, and which column owns each row (`org_id`, `team_id`)?
- [ ] Where does the app decide which tenant a user belongs to? It should be one table written
      by the server (e.g. `memberships`), not a column, claim or argument the user can change.
      **(tested here: R3, R4, W5)**

## 2. RLS and grants

- [ ] RLS enabled on every table in exposed schemas (`public`, `storage`, any schema added to
      the API settings). **(tested here: lint `table_without_rls`, R5)**
- [ ] No `USING (true)` / `WITH CHECK (true)` on tenant tables; no policy without a `TO` role
      unless anon access is intended. **(R1, R1b, W2/W2b)**
- [ ] No policy that only checks "logged in" (`auth.uid() is not null`,
      `auth.role() = 'authenticated'`). **(W1, W3)**
- [ ] Role checks include the row's tenant ("admin of *this* org", not "admin somewhere"). **(W4)**
- [ ] Every INSERT/UPDATE policy has a WITH CHECK that pins the row to the caller's tenant. **(W1, W2b)**
- [ ] No policy reads `user_metadata` (user-editable). Use `memberships` or `app_metadata`. **(R4)**
- [ ] Column grants for tables where users edit their own row (`profiles`): only safe columns.
- [ ] Tables only the server should touch: RLS on, no policies, grants revoked. **(R5)**

## 3. Views and functions

- [ ] Views in exposed schemas use `with (security_invoker = true)`. **(R6)**
- [ ] No `SECURITY DEFINER` function in an exposed schema. If one is needed, it lives in a
      private schema, has `set search_path = ''`, and only answers about `auth.uid()`. **(R7)**
- [ ] EXECUTE revoked from `anon` (and `public`) on functions logged-out users should not call. **(R7b)**

## 4. Storage

- [ ] Bucket `public` flag: public buckets serve files by URL with no policy check.
- [ ] Policies on `storage.objects` check the tenant, usually the first path folder
      (`storage.foldername(name)`), for SELECT, INSERT, UPDATE and DELETE. **(R8, W6)**
- [ ] Signed URL expiry is short; upload size and MIME type are limited.

## 5. Service role key and Next.js

- [ ] No service or secret key in a `NEXT_PUBLIC_` variable. **(scan NX1)**
- [ ] No client component (`'use client'`) imports a module that uses the service key. **(scan NX2)**
- [ ] The admin client lives in a file that starts with `import 'server-only'`.
- [ ] Every route handler and server action that uses the service key first identifies the
      caller with `auth.getUser()` and checks membership. Server actions are public endpoints. **(scan NX3)**
- [ ] Server code does not trust `auth.getSession()` alone to identify the user.
- [ ] Search the built bundle, not only the source:
      `grep -rl "service_role" .next/static` should return nothing.
- [ ] Tenant filters in the UI (`.eq('org_id', ...)`) are convenience, never the security control.

## 6. Edge Functions

- [ ] JWT verification is on for functions that act for a user.
- [ ] Functions using the service key check the caller and the tenant before acting.
- [ ] CORS is limited to the app's origins; inputs are validated.
- [ ] Secrets come from function secrets, not from code or request input.

## 7. Auth settings

- [ ] Sign-up open or invite-only, matching the product. If open, "any logged-in user" means
      anyone, and that is how findings are ranked.
- [ ] Email confirmation on; redirect URLs allow-listed.
- [ ] MFA available (at least for org admins); session and token lifetimes reviewed.

## 8. Environment variables and repo

- [ ] No `.env` with real keys in git history (`git log -p -- .env*`).
- [ ] Preview deployments do not point at the production database with the service key.
- [ ] Keys rotated after any exposure; old keys revoked, not just replaced in the env file.

## 9. Keep it from coming back

- [ ] Attack tests (tenant A vs tenant B) run in CI on every migration, including the ones an
      AI agent writes.
- [ ] Supabase's database linter (Security Advisor) runs before each release.
