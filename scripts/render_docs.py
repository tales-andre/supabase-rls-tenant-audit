"""Render HTML pages from evidence/ for the README screenshots, and the sample report as HTML.

    python scripts/render_docs.py

Writes docs/results.html, docs/test-run.html and (if the `markdown` package is installed)
report/sample-review-report.html. The PNGs and the PDF are made from these files with a
headless browser; see scripts/render-images.sh.
"""
from __future__ import annotations

import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "evidence"
DOCS = ROOT / "docs"
REPO_URL = "https://github.com/tales-andre/supabase-rls-tenant-audit"

BASE_CSS = """
body { margin: 0; background: #f4f6f8; font-family: 'Segoe UI', system-ui, sans-serif; color: #1c2430; }
.wrap { padding: 28px 32px; }
h1 { font-size: 22px; margin: 0 0 4px; }
p.sub { margin: 0 0 18px; color: #4a5565; font-size: 14px; }
table { border-collapse: collapse; width: 100%; background: #fff; font-size: 14px; }
th, td { border-bottom: 1px solid #e3e7ec; padding: 7px 10px; text-align: left; }
th { background: #24364b; color: #fff; font-weight: 600; }
td.id { font-family: Consolas, monospace; color: #4a5565; }
.leak { background: #c62828; color: #fff; font-weight: 700; border-radius: 4px; padding: 2px 8px; }
.blocked { background: #2e7d32; color: #fff; border-radius: 4px; padding: 2px 8px; }
.allowed { background: #e3efe4; color: #1b5e20; border-radius: 4px; padding: 2px 8px; }
.bypass { background: #ef6c00; color: #fff; border-radius: 4px; padding: 2px 8px; }
tr.sep td { background: #eef1f4; font-weight: 600; color: #4a5565; font-size: 12px; text-transform: uppercase; }
"""

LABEL = {"LEAK": ("leak", "LEAK"), "BLOCKED": ("blocked", "blocked"), "ALLOWED": ("allowed", "allowed"),
         "DENIED": ("leak", "DENIED"), "BYPASS": ("bypass", "bypasses RLS")}
GROUPS = {"attack": "Cross-tenant attempts", "bypass": "Service role", "legit": "Same-tenant actions (must keep working)"}


def _badge(outcome: str) -> str:
    cls, text = LABEL.get(outcome, ("", outcome))
    return f'<span class="{cls}">{text}</span>'


def results_page() -> str:
    broken = json.loads((EVIDENCE / "results-broken.json").read_text(encoding="utf-8"))
    fixed = {c["id"]: c for c in json.loads((EVIDENCE / "results-fixed.json").read_text(encoding="utf-8"))["checks"]}
    rows, last_kind = [], None
    for c in broken["checks"]:
        if c["kind"] != last_kind:
            rows.append(f'<tr class="sep"><td colspan="5">{GROUPS[c["kind"]]}</td></tr>')
            last_kind = c["kind"]
        rows.append(
            f'<tr><td class="id">{c["id"]}</td><td>{html.escape(c["actor"])}</td>'
            f'<td>{html.escape(c["title"])}</td><td>{_badge(c["outcome"])}</td>'
            f'<td>{_badge(fixed[c["id"]]["outcome"])}</td></tr>')
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Results</title>
<style>{BASE_CSS}</style></head><body><div class="wrap">
<h1>Can tenant A reach tenant B's data?</h1>
<p class="sub">Same schema and data, two policy sets. Requests sent as Supabase API roles with the
user's own JWT, app-level checks skipped. PostgreSQL {html.escape(broken["postgres"].split()[0])},
run {html.escape(broken["generated_at"])}. Raw output: evidence/results-*.json</p>
<table><tr><th>ID</th><th>Who</th><th>Tries to</th><th>broken.sql</th><th>fixed.sql</th></tr>
{''.join(rows)}</table></div></body></html>"""


def terminal_page() -> str:
    text = (EVIDENCE / "run-output.txt").read_text(encoding="utf-8")
    pytest_out = EVIDENCE / "pytest-output.txt"
    if pytest_out.exists():
        text += "\n$ python -m pytest -q\n" + pytest_out.read_text(encoding="utf-8")
    body = html.escape("$ docker compose run --rm audit\n" + text)
    for word, color in (("LEAK", "#ff6b6b"), ("blocked", "#7ee787"), ("allowed", "#a5d6a7"),
                        ("bypasses RLS", "#ffb74d"), ("passed", "#7ee787")):
        body = body.replace(word, f'<span style="color:{color}">{word}</span>')
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Test run</title>
<style>body {{ margin:0; background:#0d1117; }}
pre {{ margin:0; padding:24px 28px; color:#d6dde6; font: 13.5px/1.45 Consolas, 'Cascadia Mono', monospace; }}</style>
</head><body><pre>{body}</pre></body></html>"""


def report_page() -> str | None:
    try:
        import markdown  # optional, only for the PDF
    except ImportError:
        return None
    md = (ROOT / "report" / "sample-review-report.md").read_text(encoding="utf-8")
    body = markdown.markdown(md, extensions=["tables"])
    css = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: 'Segoe UI', system-ui, sans-serif; color: #1c2430; font-size: 10.5pt; line-height: 1.45; }
h1 { font-size: 19pt; margin-top: 0; } h2 { font-size: 14pt; border-bottom: 1px solid #ccd3db; padding-bottom: 3px; margin-top: 22px; }
h3 { font-size: 11.5pt; margin-bottom: 4px; page-break-after: avoid; }
blockquote { margin: 0 0 12px; padding: 8px 12px; background: #fff4e5; border-left: 4px solid #ef6c00; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 12px; font-size: 9.5pt; }
th, td { border: 1px solid #d5dbe1; padding: 4px 7px; text-align: left; vertical-align: top; }
th { background: #eef1f4; }
code { font-family: Consolas, monospace; font-size: 9pt; background: #f1f3f5; padding: 0 3px; }
a { color: #1f5fa8; text-decoration: none; }
"""
    # Relative evidence links must point at the repo on GitHub in the PDF, not at local files.
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Sample review report</title>
<base href="{REPO_URL}/blob/main/report/">
<style>{css}</style></head><body>{body}</body></html>"""


if __name__ == "__main__":
    DOCS.mkdir(exist_ok=True)
    (DOCS / "results.html").write_text(results_page(), encoding="utf-8")
    (DOCS / "test-run.html").write_text(terminal_page(), encoding="utf-8")
    report = report_page()
    if report:
        (ROOT / "report" / "sample-review-report.html").write_text(report, encoding="utf-8")
    print("rendered" + ("" if report else " (report skipped: pip install markdown)"))
