#!/usr/bin/env bash
# Runs the attack matrix (writes evidence/) and then the test suite.
set -euo pipefail
cd "$(dirname "$0")/.."
python -m audit.run
echo
python -m pytest -q -p no:cacheprovider 2>&1 | tee evidence/pytest-output.txt
