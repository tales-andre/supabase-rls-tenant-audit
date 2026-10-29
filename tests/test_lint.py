from audit.db import run_lint


def _by_check(findings):
    out = {}
    for f in findings:
        out.setdefault(f["check_name"], set()).add(f["object"])
    return out


def test_lint_flags_the_obvious_mistakes_in_broken(db_urls):
    found = _by_check(run_lint(db_urls["broken"]))
    assert "public.integration_secrets" in found["table_without_rls"]
    assert any("projects" in o for o in found["policy_always_true"])
    assert any("invoices" in o for o in found["policy_checks_login_not_tenant"])
    assert any("customers" in o for o in found["policy_trusts_user_metadata"])
    assert any("get_org_invoices" in o for o in found["security_definer_in_exposed_schema"])
    assert any("get_org_invoices" in o for o in found["function_executable_by_anon"])
    assert "public.invoice_summary" in found["view_without_security_invoker"]


def test_lint_misses_the_profile_org_id_trust(db_urls):
    """The invoice SELECT policy mentions org_id, so no static check flags it. Only the attack
    test R3 shows the leak. This is why the method does not stop at a linter."""
    findings = run_lint(db_urls["broken"])
    invoice_select = [f for f in findings if "Users can view invoices of their org" in f["object"]]
    assert invoice_select == []


def test_fixed_has_no_fail_findings(db_urls):
    fails = [f for f in run_lint(db_urls["fixed"]) if f["level"] == "FAIL"]
    assert fails == []


def test_fixed_review_items_are_only_user_scoped_profile_policies(db_urls):
    reviews = [f for f in run_lint(db_urls["fixed"]) if f["level"] == "REVIEW"]
    assert reviews and all(f["object"].startswith("public.profiles") for f in reviews)
