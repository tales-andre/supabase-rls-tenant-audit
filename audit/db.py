"""Build a throwaway database for a policy set and run SQL as a Supabase API role.

Impersonation works the way Supabase's API layer (PostgREST) does it: inside one transaction,
`SET LOCAL ROLE <anon|authenticated|service_role>` and put the JWT claims in the
`request.jwt.claims` setting, which auth.uid() / auth.jwt() read. Every check runs in its own
transaction and is rolled back, so the seed data is the same for every check.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

ROOT = Path(__file__).resolve().parent.parent
ADMIN_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:54329/postgres")
POLICY_SETS = ("broken", "fixed")
SETUP_FILES = ("db/00-supabase-emulation.sql", "db/01-schema.sql", "db/02-seed.sql")


def build_database(policy_set: str) -> str:
    """(Re)create database rls_<policy_set> with schema, seed and the chosen policies."""
    if policy_set not in POLICY_SETS:
        raise ValueError(f"unknown policy set: {policy_set}")
    dbname = f"rls_{policy_set}"
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        conn.execute(f"drop database if exists {dbname} with (force)")
        conn.execute(f"create database {dbname}")
    url = make_conninfo(ADMIN_URL, dbname=dbname)
    with psycopg.connect(url, autocommit=True) as conn:
        for rel in (*SETUP_FILES, f"policies/{policy_set}.sql"):
            conn.execute((ROOT / rel).read_text(encoding="utf-8"))
    return url


@contextmanager
def session(url: str, role: str, claims: dict):
    """A transaction acting as `role` with `claims`; always rolled back."""
    conn = psycopg.connect(url)
    try:
        conn.execute("select set_config('request.jwt.claims', %s, true)", [json.dumps(claims)])
        conn.execute(f"set local role {role}")
        yield conn
    finally:
        conn.rollback()
        conn.close()


def server_version(url: str) -> str:
    with psycopg.connect(url) as conn:
        return conn.execute("show server_version").fetchone()[0]


def run_lint(url: str) -> list[dict]:
    sql = (ROOT / "checks" / "lint.sql").read_text(encoding="utf-8")
    with psycopg.connect(url) as conn:
        cur = conn.execute(sql)
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
