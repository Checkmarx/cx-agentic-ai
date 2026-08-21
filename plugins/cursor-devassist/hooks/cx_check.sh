#!/bin/sh
# Cross-platform launcher for cx_check.py — fail-closed. POSIX sh (no bashisms).
#
# Invoked by hooks.json as:  sh "${CURSOR_PLUGIN_ROOT}/hooks/cx_check.sh"
#
# Why `sh` and not `bash`: on Windows a bare `bash` resolves to the System32 WSL
# launcher (C:\Windows\System32\bash.exe), which is handed a Windows file path it
# cannot open and exits 127. A non-zero/non-two exit from a failClosed Cursor hook
# risks being treated as a non-blocking error, so the whole fail-closed gate could
# silently FAIL OPEN. `sh` has no System32 / WSL variant — it resolves only to Git
# Bash's sh.exe — so the gate actually runs. Requires Git for Windows with its Unix
# tools on PATH. On macOS/Linux `sh` is the system shell; this script is POSIX so it
# runs under dash/ash too (not just bash).

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PY_SCRIPT="$SCRIPT_DIR/cx_check.py"

# Capture stdin ONCE into a temp file. NEVER assign hook JSON to a shell variable and
# later expand it with double quotes — PowerShell OAuth commands contain `1>$null`, and
# Git Bash expands `$null` to empty inside `"$VAR"`, corrupting the JSON/command and
# breaking the auth-recovery carve-out (cx_run allows via scanner; cx_check denied).
_CX_HOOK_INPUT_FILE=$(mktemp 2>/dev/null) || _CX_HOOK_INPUT_FILE="/tmp/cx_hook_input.$$"
cat > "$_CX_HOOK_INPUT_FILE"
trap 'rm -f "$_CX_HOOK_INPUT_FILE"' EXIT HUP INT

# On Windows/Git Bash, convert the POSIX path to a native Windows path for python.exe
# BEFORE any Python invocation (including the auth-recovery fast path below).
if command -v cygpath >/dev/null 2>&1; then
    PY_SCRIPT=$(cygpath -w "$PY_SCRIPT")
fi

export PYTHONUTF8=1
export PYTHONDONTWRITEBYTECODE=1

# Fast Python 3 probe — used ONLY for the auth/setup carve-out fast path (must finish in
# milliseconds, not after the full 12s interpreter search used by the main gate below).
_cx_fast_python() {
    for _cxfp in python3 python; do
        if command -v "$_cxfp" >/dev/null 2>&1 && \
           "$_cxfp" -c "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)" >/dev/null 2>&1; then
            printf '%s' "$_cxfp"
            return 0
        fi
    done
    if command -v py >/dev/null 2>&1 && \
       py -3 -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
        printf '%s' "py -3"
        return 0
    fi
    return 1
}

_cx_fast_py=$(_cx_fast_python) || _cx_fast_py=""
if [ -n "$_cx_fast_py" ]; then
    $_cx_fast_py "$PY_SCRIPT" --match-auth-recovery < "$_CX_HOOK_INPUT_FILE" >/dev/null 2>&1 && \
        printf '%s\n' '{"permission":"allow"}' && exit 0
    $_cx_fast_py "$PY_SCRIPT" --match-ignore-vulnerability < "$_CX_HOOK_INPUT_FILE" >/dev/null 2>&1 && \
        printf '%s\n' '{"permission":"allow"}' && exit 0
    $_cx_fast_py "$PY_SCRIPT" --match-checkmarx-prep < "$_CX_HOOK_INPUT_FILE" >/dev/null 2>&1 && \
        printf '%s\n' '{"permission":"allow"}' && exit 0
    $_cx_fast_py "$PY_SCRIPT" --match-trusted-setup < "$_CX_HOOK_INPUT_FILE" >/dev/null 2>&1 && \
        printf '%s\n' '{"permission":"allow"}' && exit 0
fi

# TRUSTED BOOTSTRAP / AUTH / SETUP CARVE-OUT (POSIX sh fallback when Python is absent or
# could not decide): same input file, never a shell-expanded JSON string.
if [ -f "$SCRIPT_DIR/_cx_bootstrap_match.sh" ]; then
    . "$SCRIPT_DIR/_cx_bootstrap_match.sh"
    cx_is_auth_recovery_command "$_CX_HOOK_INPUT_FILE" "$PY_SCRIPT" && \
        printf '%s\n' '{"permission":"allow"}' && exit 0
    cx_is_trusted_setup_command "$_CX_HOOK_INPUT_FILE" "$SCRIPT_DIR" && \
        printf '%s\n' '{"permission":"allow"}' && exit 0
fi

# Probe a candidate interpreter for the FULL gate. It MUST be Python 3: a Python-2 `python`
# would pass a naive no-op probe but then crash cx_check.py on its Python-3-only syntax and
# exit 1 — a non-2 exit that fails OPEN.
probe_python() {
    if command -v timeout >/dev/null 2>&1; then
        timeout 3 "$@"
        return
    fi
    "$@" &
    _probe_pid=$!
    ( sleep 3; kill "$_probe_pid" 2>/dev/null ) &
    _probe_killer=$!
    wait "$_probe_pid" 2>/dev/null
    _probe_status=$?
    kill "$_probe_killer" 2>/dev/null
    wait "$_probe_killer" 2>/dev/null
    return "$_probe_status"
}

_probe_start="$(date +%s 2>/dev/null || echo 0)"
PYTHON_BIN="$_cx_fast_py"
if [ -z "$PYTHON_BIN" ]; then
    for candidate in python3 python python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
        [ "$(( $(date +%s 2>/dev/null || echo "$_probe_start") - _probe_start ))" -ge 12 ] && break
        if command -v "$candidate" >/dev/null 2>&1 && \
           probe_python "$candidate" -c "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)" >/dev/null 2>&1; then
            PYTHON_BIN="$candidate"
            break
        fi
    done
fi
if [ -z "$PYTHON_BIN" ] && command -v py >/dev/null 2>&1 && \
   probe_python py -3 -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
    PYTHON_BIN="py -3"
fi

if [ -z "$PYTHON_BIN" ]; then
    cat <<'JSON'
{"permission":"deny","user_message":"The Checkmarx security gate could not run: no working Python 3 interpreter was found, so the scanner is inactive. This operation is BLOCKED fail-closed.","agent_message":"CHECKMARX_HOOK_DENY — MANDATORY agent_message (follow exactly; cx-hook-deny rule applies):\n\nDo not bypass the scan by writing the same content through another tool or shell command.\n\nInstall Python 3, then retry. Windows: install from https://python.org (NOT the Microsoft Store stub). macOS: xcode-select --install or brew install python3. Linux: apt install python3 / dnf install python3 / apk add python3. The plugin bundled bootstrap (scripts/cx-bootstrap.sh) installs the cx CLI and itself needs NO Python, but this version/auth gate does. Without Python 3 the gate cannot tell which files Checkmarx can scan, so ALL file writes and Checkmarx MCP calls are blocked. Shell commands are never blocked, so you can install Python 3 and cx from here.","additional_context":"CHECKMARX_HOOK_DENY — MANDATORY agent_message (follow exactly; cx-hook-deny rule applies):\n\nDo not bypass the scan by writing the same content through another tool or shell command.\n\nInstall Python 3, then retry. Windows: install from https://python.org (NOT the Microsoft Store stub). macOS: xcode-select --install or brew install python3. Linux: apt install python3 / dnf install python3 / apk add python3. The plugin bundled bootstrap (scripts/cx-bootstrap.sh) installs the cx CLI and itself needs NO Python, but this version/auth gate does. Without Python 3 the gate cannot tell which files Checkmarx can scan, so ALL file writes and Checkmarx MCP calls are blocked. Shell commands are never blocked, so you can install Python 3 and cx from here."}
JSON
    exit 2
fi

# Belt-and-suspenders (fast path above should already have returned for auth/setup commands).
$PYTHON_BIN "$PY_SCRIPT" --match-auth-recovery < "$_CX_HOOK_INPUT_FILE" >/dev/null 2>&1 && \
    printf '%s\n' '{"permission":"allow"}' && exit 0

$PYTHON_BIN "$PY_SCRIPT" --match-ignore-vulnerability < "$_CX_HOOK_INPUT_FILE" >/dev/null 2>&1 && \
    printf '%s\n' '{"permission":"allow"}' && exit 0

$PYTHON_BIN "$PY_SCRIPT" --match-checkmarx-prep < "$_CX_HOOK_INPUT_FILE" >/dev/null 2>&1 && \
    printf '%s\n' '{"permission":"allow"}' && exit 0

$PYTHON_BIN "$PY_SCRIPT" "$@" < "$_CX_HOOK_INPUT_FILE"
