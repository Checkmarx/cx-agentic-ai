#!/bin/sh
# Cross-platform launcher for cx_check.py — fail-closed. POSIX sh (no bashisms).
#
# Invoked by hooks.json as:  sh "${CLAUDE_PLUGIN_ROOT}/hooks/cx_check.sh"
#
# Why `sh` and not `bash`: on Windows a bare `bash` resolves to the System32 WSL
# launcher (C:\Windows\System32\bash.exe), which is handed a Windows file path it
# cannot open and exits 127. A non-2 exit is treated by Claude Code as a NON-blocking
# hook error, so the whole fail-closed gate silently FAILS OPEN. `sh` has no System32
# / WSL variant — it resolves only to Git Bash's sh.exe — so the gate actually runs.
# Requires Git for Windows with its Unix tools on PATH. On macOS/Linux `sh` is the
# system shell; this script is POSIX so it runs under dash/ash too (not just bash).

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PY_SCRIPT="$SCRIPT_DIR/cx_check.py"

# Capture stdin once: we inspect it (carve-out below) and replay it to Python.
INPUT=$(cat)

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
# naive no-op probe but then crash cx_check.py on its Python-3-only syntax and exit 1 —
# a non-2 exit that fails OPEN. Requiring version_info[0] >= 3 rejects Py2 so the
# no-Python deny (fail CLOSED) fires instead. The probe also runs the interpreter, which
# detects and skips the Microsoft Store python3 stub (it exits non-zero in non-TTY use).
# Bound each interpreter probe: a wedged python must NOT hang the hook to Claude Code's kill
# timeout (a killed hook is non-blocking = fail OPEN). Prefer coreutils `timeout`; where it is
# absent — stock macOS ships NO `timeout`, and minimal containers may not either — fall back to a
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
# each burn a full per-probe timeout and, summed, exceed Claude Code's 45s hook budget — a KILLED
# hook is non-2 = fail OPEN. If the budget is spent, stop probing and fall through to the no-Python
# deny (exit 2) below. (date-less hosts skip the deadline; each probe is still individually bounded.)
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
    # No working Python 3 ⇒ the gate cannot evaluate ⇒ fail CLOSED (deny JSON on stdout).
    # Exit code differs by client: Claude Code parses the JSON only when exit=2 (exit 1 is a
    # non-blocking hook error there = fail OPEN). Codex CLI's contract is the OPPOSITE for this
    # exact JSON-on-stdout shape: Codex only parses hookSpecificOutput when exit=0 — exit 2 is
    # documented as "write the reason to stderr instead" (plain text, no JSON) — so exit 2 here
    # with a Codex invocation would produce an unparsed, reason-less hook failure instead of a
    # deny. Detect via the same --codex argv flag cx_check.py uses.
    cat <<'JSON'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"The Checkmarx security gate could not run: no working Python 3 interpreter was found, so the scanner is inactive. This operation is BLOCKED fail-closed.","additionalContext":"Install Python 3, then retry. Windows: install from https://python.org (NOT the Microsoft Store stub). macOS: `xcode-select --install` or `brew install python3`. Linux: `apt install python3` / `dnf install python3` / `apk add python3`. The plugin's bundled bootstrap (scripts/cx-bootstrap.sh) installs the cx CLI and itself needs NO Python, but this version/auth gate does. All agent actions remain blocked until a Python 3 interpreter is available."}}
JSON
    case " $* " in
        *' --codex '*) exit 0 ;;
        *)             exit 2 ;;
    esac
fi

# Replay the captured stdin to Python (we already consumed it above, so it can't stream).
printf '%s' "$INPUT" | $PYTHON_BIN "$PY_SCRIPT" "$@"
