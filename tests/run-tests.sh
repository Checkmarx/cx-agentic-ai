#!/usr/bin/env bash
# Runs every cx-devassist test suite — Python (hooks) + shell (scripts) — and exits non-zero
# if any suite fails. Single entry point for local runs and CI.
#
#   bash tests/run-tests.sh
#
# If coverage.py is importable, the Python suites run under coverage and a combined report is
# printed; otherwise they run with plain Python. Coverage data stays under tests/ (gitignored).
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Three plugins are covered: copilot-devassist (the older suites under hooks/ and scripts/),
# cx-devassist (the Claude gate suites directly under tests/), and the Gemini CLI extension
# (hooks/ at repo root). Gemini suites live in test_gemini_*.py so they never share an
# interpreter with Claude/Copilot — one process can only hold one module named `cx_check`.
# NOT named CLAUDE_PLUGIN_ROOT: that is a real env var cx_check.py reads, and Claude Code exports it to
# hooks. A bash assignment keeps an inherited export attribute, so reusing the name would silently
# redefine it for every test subprocess on any machine where it is already exported.
PLUGIN_ROOT="$(cd "$DIR/../plugins/copilot-devassist" && pwd)"
CX_PLUGIN_ROOT="$(cd "$DIR/../plugins/cx-devassist" && pwd)"
GEMINI_ROOT="$(cd "$DIR/.." && pwd)"

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
# Measure all three hook trees. Sourcing only one would report the others as 0% and hide real gaps.
COV_SOURCES="$PLUGIN_ROOT/hooks,$CX_PLUGIN_ROOT/hooks,$GEMINI_ROOT/hooks"
COV=0
if "${PY[@]}" -c 'import coverage' >/dev/null 2>&1; then
    COV=1
    export COVERAGE_FILE="$DIR/.coverage"
    rm -f "$COVERAGE_FILE" "$COVERAGE_FILE".* 2>/dev/null || true
fi

# Gate-verdict env vars set in the developer's own shell leak into the suites and fail tests for
# reasons unrelated to the code — a valid CX_BINARY pin outranks the fake canonical store that
# tests/hooks/test_cx_check.py's tier assertions monkeypatch, and CX_GATE_ALL_FILES=1 defeats the
# unscannable-file carve-out the scannable-files suite asserts. Tests that need these set them
# themselves, so clear the whole verdict-affecting namespace for a hermetic run.
#
# Belt-and-braces only: this cannot protect someone running a single suite directly, which is the
# normal inner loop. The durable fix is per-test isolation — tests/test_cx_check_scannable_files.py
# already builds a hermetic subprocess env; the copilot suite relies on convention and has the
# mechanism (`run(env=…)`, `_with_env`) but five tier tests do not use it.
unset CX_BINARY CX_GATE_ALL_FILES CX_GATE_ALL_COMMANDS CX_ALLOW_UNLICENSED

fail=0

# $1 = header label, rest = python argv. One home for the coverage/plain fork so the two wrappers
# below cannot drift on --source.
_run_py_argv() {
    local label="$1"; shift
    printf '\n========== python: %s ==========\n' "$label"
    if [ "$COV" -eq 1 ]; then
        "${PY[@]}" -m coverage run --parallel-mode --source="$COV_SOURCES" "$@" || fail=1
    else
        "${PY[@]}" "$@" || fail=1
    fi
}

run_py() { _run_py_argv "${1#"$PLUGIN_ROOT/"}" "$1"; }

# Run a suite through unittest discovery rather than as a script, so tests/ lands on sys.path and
# `import _gatelib` resolves. -t pins the top-level dir so discovery does not walk the whole repo.
run_py_discover() { _run_py_argv "$1 (discover)" -m unittest discover -s "$DIR" -t "$DIR" -p "$1"; }

run_sh() {
    local f="$1"
    printf '\n========== shell: %s ==========\n' "${f#"$PLUGIN_ROOT/"}"
    sh "$f" || fail=1
}

run_py "$DIR/hooks/test_cx_check.py"
run_py "$DIR/hooks/test_cx_log.py"
run_py "$DIR/test_packaging.py"
# Gate suites — ONE PROCESS EACH, deliberately. Do not collapse into a single
# -p "test_cx_check_*.py": admin_config imports copilot-devassist's cx_check while the other two
# import cx-devassist's, and one interpreter can only hold one module named `cx_check`, so whichever
# binds sys.modules first silently shadows the other. Measured: combined, 63 of 130 tests error.
run_py_discover "test_cx_check_scannable_files.py"
run_py_discover "test_cx_check_login_history.py"
run_py_discover "test_cx_check_admin_config.py"
run_py_discover "test_gemini_cx_check_scannable_files.py"
run_py_discover "test_gemini_cx_check_login_history.py"
run_sh "$DIR/scripts/test_cx_asset_resolver.sh"
run_sh "$DIR/scripts/test_cx_path_probe.sh"
run_sh "$DIR/scripts/test_cx_bootstrap.sh"
run_sh "$DIR/scripts/test_cx_resolution_contract.sh"
run_sh "$DIR/scripts/test_cx_mcp_guard.sh"
run_sh "$DIR/scripts/test_cx_run_mcp_guard.sh"

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
