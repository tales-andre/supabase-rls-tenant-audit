from audit.db import ROOT
from audit.scan_nextjs import scan


def test_scan_flags_service_role_misuse_in_broken_example():
    findings = scan(ROOT / "examples" / "nextjs-broken")
    rules = {(f["rule"], f["file"]) for f in findings}
    assert ("NX1", ".env.example") in rules
    assert ("NX1", "lib/supabase.ts") in rules
    assert ("NX2", "app/dashboard/invoices/page.tsx") in rules
    assert ("NX3", "app/api/invoices/route.ts") in rules


def test_scan_is_clean_on_fixed_example():
    assert scan(ROOT / "examples" / "nextjs-fixed") == []
