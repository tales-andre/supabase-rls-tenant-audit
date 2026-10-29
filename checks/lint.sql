-- Static RLS checks over the exposed schemas (public, storage). Read-only: catalog queries only.
-- One row per finding: level | check | object | detail
--   FAIL   = a pattern that is wrong in a multi-tenant app almost every time
--   REVIEW = a policy with no visible tenant reference; a human must decide
-- These checks are heuristics. They do NOT replace the attack tests in audit/checks.py:
-- a policy can reference org_id and still trust a value the user controls.

with exposed as (
  select unnest(array['public', 'storage']) as nspname
),
tables_without_rls as (
  select 'FAIL'::text as level, 'table_without_rls'::text as check_name,
         n.nspname || '.' || c.relname as object,
         'RLS is disabled; with Supabase default grants the anon key can read and write it' as detail
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where c.relkind in ('r', 'p')
    and n.nspname in (select nspname from exposed)
    and not c.relrowsecurity
),
policy_text as (
  select p.schemaname, p.tablename, p.policyname, p.cmd, p.roles,
         coalesce(p.qual, '') as qual, coalesce(p.with_check, '') as with_check,
         coalesce(p.qual, '') || ' ' || coalesce(p.with_check, '') as expr
  from pg_policies p
  where p.schemaname in (select nspname from exposed)
),
always_true as (
  select 'FAIL', 'policy_always_true',
         schemaname || '.' || tablename || ' / "' || policyname || '"',
         cmd || ' policy with ' ||
           case when qual = 'true' then 'USING (true)' else 'WITH CHECK (true)' end ||
           case when roles @> array['public']::name[] then ', applies to every role including anon' else '' end
  from policy_text
  where qual = 'true' or with_check = 'true'
),
login_only as (
  select 'FAIL', 'policy_checks_login_not_tenant',
         schemaname || '.' || tablename || ' / "' || policyname || '"',
         cmd || ' policy only checks that the caller is logged in: ' || btrim(expr)
  from policy_text
  where btrim(qual) in ('(auth.uid() IS NOT NULL)', '(auth.role() = ''authenticated''::text)')
     or btrim(with_check) in ('(auth.uid() IS NOT NULL)', '(auth.role() = ''authenticated''::text)')
),
user_metadata as (
  select 'FAIL', 'policy_trusts_user_metadata',
         schemaname || '.' || tablename || ' / "' || policyname || '"',
         'reads user_metadata from the JWT; users can edit it with auth.updateUser()'
  from policy_text
  where expr ilike '%user_metadata%'
),
no_tenant_reference as (
  select 'REVIEW', 'policy_without_tenant_reference',
         schemaname || '.' || tablename || ' / "' || policyname || '"',
         cmd || ' policy does not mention org_id or a membership helper: ' || btrim(expr)
  from policy_text
  where expr !~* '(org_id|is_member|is_admin|my_org_ids)'
    and qual <> 'true' and with_check <> 'true'
    and btrim(qual) not in ('(auth.uid() IS NOT NULL)', '(auth.role() = ''authenticated''::text)')
    and btrim(with_check) not in ('(auth.uid() IS NOT NULL)', '(auth.role() = ''authenticated''::text)')
),
definer_functions as (
  select 'FAIL', 'security_definer_in_exposed_schema',
         n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
         'SECURITY DEFINER callable through the API; runs as ' || pg_get_userbyid(p.proowner) ||
           ' and skips RLS' ||
           case when p.proconfig is null or not exists (
                  select 1 from unnest(p.proconfig) cfg where cfg like 'search_path=%')
                then '; search_path not set' else '' end
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where p.prosecdef
    and n.nspname in (select nspname from exposed)
),
definer_no_search_path as (
  select 'FAIL', 'security_definer_without_search_path',
         n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
         'SECURITY DEFINER without a pinned search_path'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where p.prosecdef
    and n.nspname not in ('pg_catalog', 'information_schema')
    and n.nspname not in (select nspname from exposed)
    and (p.proconfig is null or not exists (
           select 1 from unnest(p.proconfig) cfg where cfg like 'search_path=%'))
),
anon_execute as (
  select 'FAIL', 'function_executable_by_anon',
         n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
         'logged-out visitors can call this function through the API'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and has_function_privilege('anon', p.oid, 'EXECUTE')
),
definer_views as (
  select 'FAIL', 'view_without_security_invoker',
         n.nspname || '.' || c.relname,
         'view runs as its owner (' || pg_get_userbyid(c.relowner) || '), so RLS on the tables it reads is skipped'
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where c.relkind = 'v'
    and n.nspname in (select nspname from exposed)
    and not coalesce(c.reloptions @> array['security_invoker=true'], false)
)
select * from tables_without_rls
union all select * from always_true
union all select * from login_only
union all select * from user_metadata
union all select * from no_tenant_reference
union all select * from definer_functions
union all select * from definer_no_search_path
union all select * from anon_execute
union all select * from definer_views
order by 1, 2, 3;
