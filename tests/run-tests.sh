#!/usr/bin/env bash
# Runs every cx-security test suite — Python (hooks) + shell (scripts) — and exits non-zero
# if any suite fails. Single entry point for local runs and CI.
#
#   bash tests/run-tests.sh
#
# If coverage.py is importable, the Python suites run under coverage and a combined report is
# printed; otherwise they run with plain Python. Coverage data stays under tests/ (gitignored).
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(cd "$DIR/../plugins/cx-security" && pwd)"

# --- pick a Python 3 interpreter (mirrors the gate's own Py3 requirement) -------------------
# PY is an ARRAY so the `py -3` launcher (two words) invokes correctly under `"${PY[@]}"`.
PY=()
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1 \
       && "$cand" -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' >/dev/null 2>&1; then
        PY=("$cand"); break
    fi
done
# Windows: the `py` launcher (`py -3`) is often the only Python on PATH — mirror cx_check.sh.
if [ "${#PY[@]}" -eq 0 ] && command -v py >/dev/null 2>&1 \
   && py -3 -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' >/dev/null 2>&1; then
    PY=(py -3)
fi
if [ "${#PY[@]}" -eq 0 ]; then
    printf 'ERROR: no Python 3 interpreter found on PATH\n' >&2
    exit 1
fi

# --- coverage.py is optional --------------------------------------------------------------
COV=0
if "${PY[@]}" -c 'import coverage' >/dev/null 2>&1; then
    COV=1
    export COVERAGE_FILE="$DIR/.coverage"
    rm -f "$COVERAGE_FILE" "$COVERAGE_FILE".* 2>/dev/null || true
fi

fail=0

run_py() {
    local f="$1"
    printf '\n========== python: %s ==========\n' "${f#"$PLUGIN_ROOT/"}"
    if [ "$COV" -eq 1 ]; then
        "${PY[@]}" -m coverage run --parallel-mode --source="$PLUGIN_ROOT/hooks" "$f" || fail=1
    else
        "${PY[@]}" "$f" || fail=1
    fi
}

run_sh() {
    local f="$1"
    printf '\n========== shell: %s ==========\n' "${f#"$PLUGIN_ROOT/"}"
    bash "$f" || fail=1
}

run_py "$DIR/hooks/test_cx_check.py"
run_py "$DIR/hooks/test_cx_log.py"
run_py "$DIR/test_packaging.py"
run_sh "$DIR/scripts/test_cx_asset_resolver.sh"
run_sh "$DIR/scripts/test_cx_path_probe.sh"
run_sh "$DIR/scripts/test_cx_bootstrap.sh"
run_sh "$DIR/scripts/test_cx_resolution_contract.sh"

if [ "$COV" -eq 1 ]; then
    printf '\n========== coverage (hooks) ==========\n'
    "${PY[@]}" -m coverage combine >/dev/null 2>&1 || true
    "${PY[@]}" -m coverage report -m || true
fi

if [ "$fail" -ne 0 ]; then
    printf '\nRESULT: FAIL — one or more suites failed\n' >&2
    exit 1
fi
printf '\nRESULT: PASS — all suites green\n'
