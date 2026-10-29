"""The attack matrix: what a tenant-A user (or a logged-out visitor) tries against tenant B.

Each check runs SQL as an API role with a given JWT, the same requests anyone can send to the
Supabase REST API with the public anon key and their own token. App-level checks in Next.js
(middleware, server actions, UI filters) are skipped on purpose: the database must hold alone.

Outcomes
  LEAK     tenant boundary crossed (read B's data, or wrote into / changed / deleted B's data)
  BLOCKED  the database refused (0 rows, RLS violation or permission error)
  ALLOWED  a legitimate same-tenant action worked (the fix must not break the app)
  DENIED   a legitimate action was refused (would be a bug in the fix)
  BYPASS   the service role ignored RLS, which is by design: server code using it must
           enforce the tenant itself
"""
from __future__ import annotations

from dataclasses import dataclass, field

import psycopg

from .db import session

ORG_A = "aaaaaaaa-0000-0000-0000-000000000000"
ORG_B = "bbbbbbbb-0000-0000-0000-000000000000"
ALICE = "aaaaaaaa-1111-0000-0000-000000000001"
BOB = "bbbbbbbb-1111-0000-0000-000000000001"
INVOICE_A1 = "aaaaaaaa-3333-0000-0000-000000000001"
INVOICE_B1 = "bbbbbbbb-3333-0000-0000-000000000001"
PROJECT_A1 = "aaaaaaaa-2222-0000-0000-000000000001"
PROJECT_B1 = "bbbbbbbb-2222-0000-0000-000000000001"

ACTORS = {
    "alice (org A)": ("authenticated", {
        "sub": ALICE, "role": "authenticated", "email": "alice@acme.example",
        "user_metadata": {"org_id": ORG_A}}),
    # Same user, after calling supabase.auth.updateUser({ data: { org_id: ORG_B } }) and
    # refreshing the session. Supabase copies user_metadata into the new JWT.
    "alice, edited user_metadata": ("authenticated", {
        "sub": ALICE, "role": "authenticated", "email": "alice@acme.example",
        "user_metadata": {"org_id": ORG_B}}),
    "bob (org B)": ("authenticated", {
        "sub": BOB, "role": "authenticated", "email": "bob@blueharbor.example",
        "user_metadata": {"org_id": ORG_B}}),
    "anon (logged out)": ("anon", {"role": "anon"}),
    "service_role": ("service_role", {"role": "service_role"}),
}

SUCCESS = {"attack": "LEAK", "legit": "ALLOWED", "bypass": "BYPASS"}
FAILURE = {"attack": "BLOCKED", "legit": "DENIED", "bypass": "ENFORCED"}


@dataclass
class Check:
    id: str
    kind: str            # attack | legit | bypass
    area: str            # read | write | rpc/view | storage | ...
    title: str
    actor: str
    steps: list[str]     # SQL run as the actor; the last one decides when verify is None
    verify: str | None = None   # SQL run as postgres after the steps; returns one boolean
    expect: dict = field(default_factory=dict)  # {"broken": outcome, "fixed": outcome}
    note: str = ""


def _attack(id, area, title, actor, steps, verify=None, broken="LEAK", note=""):
    return Check(id, "attack", area, title, actor, steps, verify,
                 {"broken": broken, "fixed": "BLOCKED"}, note)


def _legit(id, area, title, actor, steps, verify=None):
    return Check(id, "legit", area, title, actor, steps, verify,
                 {"broken": "ALLOWED", "fixed": "ALLOWED"})


CHECKS: list[Check] = [
    # --- reads ------------------------------------------------------------------------
    _attack("R1", "read", "Read org B's projects", "alice (org A)",
            [f"select id, org_id, name from public.projects where org_id = '{ORG_B}'"]),
    _attack("R1b", "read", "Read every org's projects while logged out", "anon (logged out)",
            ["select id, org_id, name from public.projects"]),
    _attack("R2", "read", "Read org B's invoices directly", "alice (org A)",
            [f"select id, org_id, number from public.invoices where org_id = '{ORG_B}'"],
            broken="BLOCKED",
            note="A naive isolation test stops here and passes. R3 shows why that is not enough."),
    _attack("R3", "read", "Read org B's invoices after setting own profile.org_id to B",
            "alice (org A)",
            [f"update public.profiles set org_id = '{ORG_B}' where id = '{ALICE}'",
             f"select id, org_id, number from public.invoices where org_id = '{ORG_B}'"]),
    _attack("R4", "read", "Read org B's customers with self-edited user_metadata",
            "alice, edited user_metadata",
            [f"select id, org_id, name, email from public.customers where org_id = '{ORG_B}'"]),
    _attack("R5", "read", "Read integration secrets while logged out", "anon (logged out)",
            ["select org_id, provider, secret from public.integration_secrets"]),
    _attack("R6", "rpc/view", "Read org B's totals through the invoice_summary view",
            "alice (org A)",
            [f"select org_id, invoice_count, total_cents from public.invoice_summary "
             f"where org_id = '{ORG_B}'"]),
    _attack("R7", "rpc/view", "Call get_org_invoices() with org B's id", "alice (org A)",
            [f"select id, org_id, number from public.get_org_invoices('{ORG_B}')"]),
    _attack("R7b", "rpc/view", "Call get_org_invoices() with org B's id while logged out",
            "anon (logged out)",
            [f"select id, org_id, number from public.get_org_invoices('{ORG_B}')"]),
    _attack("R8", "storage", "List org B's invoice PDFs in the private bucket", "alice (org A)",
            [f"select bucket_id, name from storage.objects "
             f"where bucket_id = 'invoice-pdfs' and name like '{ORG_B}/%'"]),
    # --- writes -----------------------------------------------------------------------
    _attack("W1", "write", "Insert an invoice into org B", "alice (org A)",
            [f"insert into public.invoices (org_id, number, amount_cents, created_by) "
             f"values ('{ORG_B}', 'INJECTED-1', 1, '{ALICE}')"],
            verify="select exists (select 1 from public.invoices where number = 'INJECTED-1' "
                   f"and org_id = '{ORG_B}')"),
    _attack("W2", "write", "Move own invoice into org B (update with a filter)", "alice (org A)",
            [f"update public.invoices set org_id = '{ORG_B}' where id = '{INVOICE_A1}'"],
            verify=f"select org_id = '{ORG_B}' from public.invoices where id = '{INVOICE_A1}'",
            broken="BLOCKED",
            note="WITH CHECK (true) is masked here: when an UPDATE reads columns (WHERE or "
                 "RETURNING), Postgres also checks the new row against the SELECT policy. "
                 "Latent defect, see W2b."),
    _attack("W2b", "write", "Move own org's invoices into org B (update without a filter)",
            "alice (org A)",
            [f"update public.invoices set org_id = '{ORG_B}'"],
            verify=f"select org_id = '{ORG_B}' from public.invoices where id = '{INVOICE_A1}'",
            note="Same policy as W2. Without a WHERE clause the SELECT policy is not applied "
                 "and WITH CHECK (true) lets the rows move. Reachable by any unfiltered UPDATE "
                 "running as the user (for example inside a SQL function); a filtered "
                 "update behaves like W2."),
    _attack("W3", "write", "Rename org B's project", "alice (org A)",
            [f"update public.projects set name = 'renamed by alice' where id = '{PROJECT_B1}'"],
            verify=f"select name = 'renamed by alice' from public.projects where id = '{PROJECT_B1}'"),
    _attack("W4", "write", "Delete org B's project", "alice (org A)",
            [f"delete from public.projects where id = '{PROJECT_B1}'"],
            verify=f"select not exists (select 1 from public.projects where id = '{PROJECT_B1}')"),
    _attack("W5", "write", "Add self as admin of org B", "alice (org A)",
            [f"insert into public.memberships (org_id, user_id, role) "
             f"values ('{ORG_B}', '{ALICE}', 'admin')"],
            verify=f"select exists (select 1 from public.memberships where org_id = '{ORG_B}' "
                   f"and user_id = '{ALICE}')"),
    _attack("W6", "storage", "Upload a file into org B's folder", "alice (org A)",
            [f"insert into storage.objects (bucket_id, name, owner) "
             f"values ('invoice-pdfs', '{ORG_B}/planted.pdf', '{ALICE}')"],
            verify=f"select exists (select 1 from storage.objects where name = '{ORG_B}/planted.pdf')"),
    # --- service role -----------------------------------------------------------------
    Check("S1", "bypass", "service key",
          "Read every org's invoices with the service role key", "service_role",
          ["select id, org_id, number from public.invoices"], None,
          {"broken": "BYPASS", "fixed": "BYPASS"},
          "By design. Any Next.js code that uses this key must check the tenant itself."),
    # --- legitimate same-tenant actions (the fix must keep these working) --------------
    _legit("L1", "read", "Read own org's invoices", "alice (org A)",
           [f"select id from public.invoices where org_id = '{ORG_A}'"]),
    _legit("L2", "read", "Read own org's projects and customers", "alice (org A)",
           [f"select p.id from public.projects p join public.customers c using (org_id) "
            f"where p.org_id = '{ORG_A}'"]),
    _legit("L3", "write", "Create an invoice in own org", "alice (org A)",
           [f"insert into public.invoices (org_id, number, amount_cents, created_by) "
            f"values ('{ORG_A}', 'A-0002', 5000, '{ALICE}')"],
           verify="select exists (select 1 from public.invoices where number = 'A-0002')"),
    _legit("L4", "write", "Mark own invoice as paid", "alice (org A)",
           [f"update public.invoices set status = 'paid' where id = '{INVOICE_A1}'"],
           verify=f"select status = 'paid' from public.invoices where id = '{INVOICE_A1}'"),
    _legit("L5", "rpc/view", "Call get_org_invoices() for own org", "alice (org A)",
           [f"select id from public.get_org_invoices('{ORG_A}')"]),
    _legit("L6", "storage", "List own org's invoice PDFs", "alice (org A)",
           [f"select name from storage.objects where name like '{ORG_A}/%'"]),
    _legit("L7", "read", "Bob reads his own org's invoices", "bob (org B)",
           [f"select id from public.invoices where org_id = '{ORG_B}'"]),
]


def run_check(url: str, check: Check) -> dict:
    role, claims = ACTORS[check.actor]
    result = {"rows": [], "rowcount": None, "error": None}
    success = False
    with session(url, role, claims) as conn:
        try:
            cur = None
            for sql in check.steps:
                cur = conn.execute(sql)
            result["rowcount"] = cur.rowcount
            if cur.description is not None:
                cols = [d.name for d in cur.description]
                result["rows"] = [
                    {k: (str(v) if v is not None else None) for k, v in zip(cols, row)}
                    for row in cur.fetchall()
                ]
            if check.verify is None:
                success = len(result["rows"]) > 0
            else:
                conn.execute("reset role")
                success = bool(conn.execute(check.verify).fetchone()[0])
        except psycopg.Error as exc:
            diag = exc.diag.message_primary if exc.diag else None
            result["error"] = diag or str(exc).strip()
            success = False
    outcome = SUCCESS[check.kind] if success else FAILURE[check.kind]
    return {
        "id": check.id,
        "kind": check.kind,
        "area": check.area,
        "title": check.title,
        "actor": check.actor,
        "jwt_claims": claims,
        "db_role": role,
        "sql": check.steps,
        "verify_as_postgres": check.verify,
        "outcome": outcome,
        **result,
        "note": check.note,
    }
