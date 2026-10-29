#!/usr/bin/env bash
# Maintainer script (Windows Git Bash + Edge): regenerates docs/*.png and the report PDF.
# Needs: python with `markdown` installed (only for the PDF), Microsoft Edge or Chrome.
set -euo pipefail
cd "$(dirname "$0")/.."
BROWSER="${BROWSER:-/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe}"
win() { cygpath -w "$PWD/$1" 2>/dev/null || echo "$PWD/$1"; }
python scripts/render_docs.py
"$BROWSER" --headless=new --disable-gpu --hide-scrollbars --screenshot="$(win docs/results.png)" \
  --window-size=1400,1100 "file:///$(win docs/results.html)"
"$BROWSER" --headless=new --disable-gpu --hide-scrollbars --screenshot="$(win docs/test-run.png)" \
  --window-size=1180,810 "file:///$(win docs/test-run.html)"
if [ -f report/sample-review-report.html ]; then
  "$BROWSER" --headless=new --disable-gpu --no-pdf-header-footer \
    --print-to-pdf="$(win report/sample-review-report.pdf)" "file:///$(win report/sample-review-report.html)"
fi
