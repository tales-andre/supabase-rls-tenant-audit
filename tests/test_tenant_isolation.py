"""The core claim of the repo, as tests.

broken.sql must leak where the README says it leaks (otherwise the demo proves nothing), and
fixed.sql must block every cross-tenant attempt while same-tenant actions keep working.
"""
import pytest

from audit.checks import CHECKS, run_check

ATTACKS = [c for c in CHECKS if c.kind == "attack"]
LEGIT = [c for c in CHECKS if c.kind == "legit"]


@pytest.mark.parametrize("check", ATTACKS, ids=lambda c: c.id)
def test_fixed_policies_block_cross_tenant_access(db_urls, check):
    result = run_check(db_urls["fixed"], check)
    assert result["outcome"] == "BLOCKED", result


@pytest.mark.parametrize("check", ATTACKS, ids=lambda c: c.id)
def test_broken_policies_behave_as_documented(db_urls, check):
    result = run_check(db_urls["broken"], check)
    assert result["outcome"] == check.expect["broken"], result


@pytest.mark.parametrize("policy_set", ["broken", "fixed"])
@pytest.mark.parametrize("check", LEGIT, ids=lambda c: c.id)
def test_same_tenant_actions_still_work(db_urls, policy_set, check):
    result = run_check(db_urls[policy_set], check)
    assert result["outcome"] == "ALLOWED", result


@pytest.mark.parametrize("policy_set", ["broken", "fixed"])
def test_service_role_bypasses_rls_in_both(db_urls, policy_set):
    s1 = next(c for c in CHECKS if c.id == "S1")
    result = run_check(db_urls[policy_set], s1)
    assert result["outcome"] == "BYPASS"
    assert {r["org_id"][:8] for r in result["rows"]} == {"aaaaaaaa", "bbbbbbbb"}


def test_leaked_rows_really_belong_to_the_other_tenant(db_urls):
    """A LEAK must be org B's data, not an artifact of the query."""
    for check in ATTACKS:
        if check.verify is not None or check.expect["broken"] != "LEAK":
            continue
        rows = run_check(db_urls["broken"], check)["rows"]
        assert rows, check.id
        org_ids = {r.get("org_id") or r.get("name", "")[:36] for r in rows}
        assert any(o and o.startswith("bbbbbbbb") for o in org_ids), (check.id, rows)
