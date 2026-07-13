#!/bin/sh
# Cross-platform launcher for cx_check.py — fail-closed. POSIX sh (no bashisms).
#
# Invoked by hooks.json as:              sh "${CLAUDE_PLUGIN_ROOT}/hooks/cx_check.sh"
# Invoked by hooks-copilot-cli.json as:  sh "${COPILOT_CLI_PLUGIN_ROOT}/hooks/cx_check.sh" --copilot-cli
#
# Why `sh` and not `bash`: on Windows a bare `bash` resolves to the System32 WSL
# launcher (C:\Windows\System32\bash.exe), which is handed a Windows file path it
# cannot open and exits 127. `sh` has no System32 / WSL variant — it resolves only to
# Git Bash's sh.exe — so the gate actually runs. Requires Git for Windows with its Unix
# tools on PATH. On macOS/Linux `sh` is the system shell; this script is POSIX so it
# runs under dash/ash too (not just bash).
#
# Exit-code contract (both Claude Code AND Copilot CLI): a PreToolUse "deny" is signaled
# by EXIT 0 with a `hookSpecificOutput.permissionDecision:"deny"` JSON body on stdout —
# NOT exit 2. Both clients signal a deny via exit 0 + JSON on stdout, but with DIFFERENT
# JSON shapes: Claude Code reads a nested hookSpecificOutput wrapper; Copilot CLI reads a
# FLAT JSON object with permissionDecision/permissionDecisionReason at the top level (per
# https://docs.github.com/en/copilot/reference/hooks-reference). cx_check.py detects the
# client via --copilot-cli flag (passed from hooks-copilot-cli.json) and emits the correct
# shape. A crash / no-Python condition still exits 1 (a genuine hook error) — every
# DECIDABLE outcome (allow or deny) uses exit 0.

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PY_SCRIPT="$SCRIPT_DIR/cx_check.py"

# Capture stdin once: we inspect it (carve-out below) and replay it to Python.
INPUT=$(cat)

# DEBUG LOGGING — set CX_CHECK_DEBUG=1 to capture the raw stdin JSON and key decisions
# to $HOME/.checkmarx/agent-logs/cx_check_debug.log. Lets you verify the exact field names
# (toolName vs tool_name, toolInput vs tool_input) that the agent client actually sends.
# Never enabled by default; has no effect on gate behaviour.
if [ "${CX_CHECK_DEBUG:-0}" = "1" ]; then
    _DEBUG_LOG="${CX_LOG_DIR:-${HOME}/.checkmarx/agent-logs}/cx_check_debug.log"
    mkdir -p "$(dirname "$_DEBUG_LOG")" 2>/dev/null
    printf '[cx_check.sh] %s stdin=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo ts-unavail)" "$INPUT" >> "$_DEBUG_LOG"
fi

# ALWAYS log for debugging — temporary, remove after diagnosis
_DIAG_LOG="${HOME}/.checkmarx/agent-logs/cx_diag.log"
mkdir -p "$(dirname "$_DIAG_LOG")" 2>/dev/null
printf '[cx_check.sh diag] %s args=%s stdin=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo ts)" "$*" "$INPUT" >> "$_DIAG_LOG" 2>/dev/null


# The shell-level bootstrap carve-out now lives INSIDE the no-Python branch below (search:
# NO-PYTHON CARVE-OUT). When Python 3 IS present (the normal case on all three OSes),
# cx_check.py's strict _is_bootstrap_command is the AUTHORITATIVE matcher, so this coarse shell
# matcher is neither needed nor run then — which also removes the old unconditional-bypass risk.

# On Windows/Git Bash, convert the POSIX path to a native Windows path for python.exe.
if command -v cygpath >/dev/null 2>&1; then
    PY_SCRIPT=$(cygpath -w "$PY_SCRIPT")
fi

export PYTHONUTF8=1

# Probe a candidate interpreter. It MUST be Python 3: a Python-2 `python` would pass a
# naive no-op probe but then crash cx_check.py on its Python-3-only syntax — rejecting it
# here (version_info[0] >= 3) routes to the no-Python deny JSON below instead of a bare
# crash. The probe also runs the interpreter, which detects and skips the Microsoft Store
# python3 stub (it exits non-zero in non-TTY use). Bound each interpreter probe: a wedged
# python must NOT hang the hook past the client's kill timeout (a killed hook can't emit
# JSON, so it degrades to a generic error). Prefer coreutils `timeout`; where it is absent —
# stock macOS ships NO `timeout`, and minimal containers may not either — fall back to a
# portable background watchdog so the probe is STILL bounded rather than unbounded (the old
# fallback). On a hang the probe is killed and reported as a failure → that candidate is rejected.
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

# Bound the TOTAL probe phase (not just each probe): several present-but-wedged interpreters could
# each burn a full per-probe timeout and, summed, exceed the client's hook budget — a killed hook
# can't emit JSON. If the budget is spent, stop probing and fall through to the no-Python deny
# below. (date-less hosts skip the deadline; each probe is still individually bounded.)
_probe_start="$(date +%s 2>/dev/null || echo 0)"
PYTHON_BIN=""
# Try the canonical names FIRST (usually the one working interpreter), so a few wedged versioned
# binaries early in the list can't burn the whole probe budget before python3/python are reached.
for candidate in python3 python python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
    [ "$(( $(date +%s 2>/dev/null || echo "$_probe_start") - _probe_start ))" -ge 12 ] && break
    if command -v "$candidate" >/dev/null 2>&1 && \
       probe_python "$candidate" -c "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

# Windows `py` launcher (`py -3` is always Python 3).
if [ -z "$PYTHON_BIN" ] && command -v py >/dev/null 2>&1 && \
   probe_python py -3 -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
    PYTHON_BIN="py -3"
fi

if [ -z "$PYTHON_BIN" ]; then
    # NO-PYTHON CARVE-OUT: the bootstrap installs cx and itself needs NO Python, so it alone may run
    # even here. Delegated to the shared matcher (hooks/_cx_bootstrap_match.sh) that cx_run.sh's
    # cx-absent branch also uses, so the two shell stages can't drift into disagreeing about the
    # bootstrap shape. Coarse on purpose; the AUTHORITATIVE matcher is cx_check.py's
    # _is_bootstrap_command (run whenever Python 3 is present). A non-match falls through to the deny
    # below (fail CLOSED); a missing/unsourceable helper also falls through → deny (safe).
    if [ -f "$SCRIPT_DIR/_cx_bootstrap_match.sh" ]; then
        . "$SCRIPT_DIR/_cx_bootstrap_match.sh"
        cx_is_bootstrap_command "$INPUT" "$SCRIPT_DIR" && exit 0
    fi
    # No working Python 3 ⇒ the gate cannot evaluate ⇒ fail CLOSED (deny JSON, exit 0 — see the
    # exit-code contract note at the top of this file).
    cat <<'JSON'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"The Checkmarx security gate could not run: no working Python 3 interpreter was found, so the scanner is inactive. This operation is BLOCKED fail-closed.","additionalContext":"Install Python 3, then retry. Windows: install from https://python.org (NOT the Microsoft Store stub). macOS: `xcode-select --install` or `brew install python3`. Linux: `apt install python3` / `dnf install python3` / `apk add python3`. The plugin's bundled bootstrap (scripts/cx-bootstrap.sh) installs the cx CLI and itself needs NO Python, but this version/auth gate does. All agent actions remain blocked until a Python 3 interpreter is available."}}
JSON
    exit 0
fi

# Replay the captured stdin to Python (we already consumed it above, so it can't stream).
# cx_check.py's own allow/deny paths now exit 0 with the decision JSON on stdout (see the
# exit-code contract note at the top of this file), so its exit code is safe to propagate
# as-is: 0 for any decided outcome, non-zero only for a genuine crash inside cx_check.py.
printf '%s' "$INPUT" | $PYTHON_BIN "$PY_SCRIPT" "$@"
