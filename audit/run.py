"""Run every check against both policy sets and write the raw evidence.

    python -m audit.run

Writes to evidence/:
  results-<set>.json   every check: actor, JWT claims, SQL, rows returned or error, outcome
  lint-<set>.json      static catalog checks (checks/lint.sql)
  nextjs-scan-<set>.json  service-role scan of examples/nextjs-<set>
  summary.md           the README table
  run-output.txt       what this command printed
Exits with status 1 if any outcome differs from the expected one.
"""
from __future__ import annotations

import datetime as dt
import json
import sys

from .checks import CHECKS, run_check
from .db import POLICY_SETS, ROOT, build_database, run_lint, server_version
from .scan_nextjs import scan

EVIDENCE = ROOT / "evidence"
MARK = {"LEAK": "LEAK", "BLOCKED": "blocked", "ALLOWED": "allowed", "DENIED": "DENIED",
        "BYPASS": "bypasses RLS", "ENFORCED": "enforced"}


def _dump(name: str, data) -> None:
    (EVIDENCE / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    EVIDENCE.mkdir(exist_ok=True)
    out: list[str] = []
    say = lambda s="": (print(s), out.append(s))  # noqa: E731

    results: dict[str, dict[str, dict]] = {}
    lint: dict[str, list[dict]] = {}
    scans: dict[str, list[dict]] = {}
    stamp = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

    for policy_set in POLICY_SETS:
        url = build_database(policy_set)
        version = server_version(url)
        rows = [run_check(url, c) for c in CHECKS]
        results[policy_set] = {r["id"]: r for r in rows}
        lint[policy_set] = run_lint(url)
        scans[policy_set] = scan(ROOT / "examples" / f"nextjs-{policy_set}")
        meta = {"policy_set": policy_set, "generated_at": stamp, "postgres": version}
        _dump(f"results-{policy_set}.json", {**meta, "checks": rows})
        _dump(f"lint-{policy_set}.json", {**meta, "findings": lint[policy_set]})
        _dump(f"nextjs-scan-{policy_set}.json",
              {**meta, "target": f"examples/nextjs-{policy_set}", "findings": scans[policy_set]})

    mismatches = []
    say(f"Tenant isolation checks, PostgreSQL {version}, {stamp}")
    say()
    header = f"{'ID':<5} {'Who':<28} {'Tries to':<62} {'broken.sql':<13} {'fixed.sql':<13}"
    say(header)
    say("-" * len(header))
    md = ["| ID | Who | Tries to | `broken.sql` | `fixed.sql` |", "|---|---|---|---|---|"]
    for check in CHECKS:
        b = results["broken"][check.id]["outcome"]
        f = results["fixed"][check.id]["outcome"]
        for policy_set, got in (("broken", b), ("fixed", f)):
            if got != check.expect[policy_set]:
                mismatches.append(f"{check.id} {policy_set}: expected {check.expect[policy_set]}, got {got}")
        say(f"{check.id:<5} {check.actor:<28} {check.title:<62} {MARK[b]:<13} {MARK[f]:<13}")
        md_mark = lambda o: f"**{MARK[o]}**" if o in ("LEAK", "DENIED") else MARK[o]  # noqa: E731
        md.append(f"| {check.id} | {check.actor} | {check.title} | {md_mark(b)} | {md_mark(f)} |")

    say()
    for policy_set in POLICY_SETS:
        fails = sum(1 for x in lint[policy_set] if x["level"] == "FAIL")
        reviews = sum(1 for x in lint[policy_set] if x["level"] == "REVIEW")
        nx = len(scans[policy_set])
        say(f"lint {policy_set:<7} FAIL={fails} REVIEW={reviews}   nextjs-scan {policy_set:<7} findings={nx}")

    (EVIDENCE / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    say()
    if mismatches:
        say("UNEXPECTED OUTCOMES:")
        for m in mismatches:
            say(f"  {m}")
    else:
        say("All outcomes match expectations: broken.sql leaks where expected, fixed.sql blocks "
            "every cross-tenant attempt and keeps same-tenant actions working.")
    (EVIDENCE / "run-output.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
