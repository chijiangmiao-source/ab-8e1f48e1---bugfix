#!/usr/bin/env bash
# verify container entrypoint:
#   1) build check (byte-compile every source file)
#   2) recovery-rule unit tests (committed redo, loser rollback, corrupted
#      predecessor chains and all other stable-rejection rules)
#   3) API/HTTP smoke against the running `web` service
# Exits non-zero on the first failing stage.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=============================================================="
echo " Stage 1/3: build check (python3 -m py_compile)"
echo "=============================================================="
python3 -m py_compile app/*.py tests/*.py
echo "build check OK"
echo

echo "=============================================================="
echo " Stage 2/3: recovery rule tests"
echo "=============================================================="
python3 -m unittest discover -s tests -p "test_*.py" -v
echo

echo "=============================================================="
if [ -n "${SMOKE_BASE_URL:-}" ]; then
  echo " Stage 3/3: API/HTTP smoke against ${SMOKE_BASE_URL}"
  echo "=============================================================="
  python3 tests/smoke_http.py
else
  # No external target (e.g. running outside compose): the smoke script
  # launches a throwaway server instance itself.
  echo " Stage 3/3: API/HTTP smoke (self-spawned server)"
  echo "=============================================================="
  python3 tests/smoke_http.py
fi

echo
echo "VERIFY: all stages passed"
