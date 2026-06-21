#!/usr/bin/env bash
# Cross-platform launcher for cx_check.py.
# Runs on macOS and Linux natively.
# On Windows this script requires Git Bash (MSYS2), which ships with Git for Windows.
# Claude Code on Windows can invoke bash via the Git for Windows bash.exe that Git
# installs on PATH — so any Windows user with Git for Windows already has bash available.
# hooks.json must invoke this as: bash "${CLAUDE_PLUGIN_ROOT}/hooks/cx_check.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_SCRIPT="$SCRIPT_DIR/cx_check.py"

# On Windows/Git Bash, convert POSIX path to native Windows path for python.exe.
if command -v cygpath &>/dev/null; then
    PY_SCRIPT="$(cygpath -w "$PY_SCRIPT")"
fi

export PYTHONUTF8=1

# Probe a candidate interpreter: run a no-op to detect silent failures
# (e.g. the Microsoft Store python3 stub that exits non-zero in non-TTY context).
probe_python() {
    local candidate="$1"
    "$candidate" -c "import sys; sys.exit(0)" &>/dev/null
}

CANDIDATES=(
    python3.13 python3.12 python3.11 python3.10 python3.9 python3.8
    python3 python
)

PYTHON_BIN=""
for candidate in "${CANDIDATES[@]}"; do
    if command -v "$candidate" &>/dev/null && probe_python "$candidate"; then
        PYTHON_BIN="$candidate"
        break
    fi
done

# Also try the Windows py launcher (py -3) if nothing found yet.
if [[ -z "$PYTHON_BIN" ]] && command -v py &>/dev/null && py -3 -c "import sys; sys.exit(0)" &>/dev/null; then
    PYTHON_BIN="py -3"
fi

if [[ -z "$PYTHON_BIN" ]]; then
    echo "ERROR: No working Python 3 interpreter found." >&2
    echo "  Windows: install from https://python.org (do NOT use the Microsoft Store version)" >&2
    echo "  macOS:   brew install python3" >&2
    exit 1
fi

exec $PYTHON_BIN "$PY_SCRIPT" "$@"
