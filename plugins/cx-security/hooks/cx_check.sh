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
        timeout 5 "$@"
        return
    fi
    "$@" &
    _probe_pid=$!
    ( sleep 5; kill "$_probe_pid" 2>/dev/null ) &
    _probe_killer=$!
    wait "$_probe_pid" 2>/dev/null
    _probe_status=$?
    kill "$_probe_killer" 2>/dev/null
    wait "$_probe_killer" 2>/dev/null
    return "$_probe_status"
}

PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3 python; do
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
    # NO-PYTHON CARVE-OUT: the bootstrap installs cx and itself needs NO Python, so it alone may
    # run even here. Tightened (review F-CR2): the command must reference the plugin's OWN bundled
    # bootstrap by its resolved ABSOLUTE path — a bare filename like `bash /tmp/cx-bootstrap.sh` no
    # longer qualifies. Still gated by: Bash tool, no shell chaining / substitution / redirects,
    # and a `bash "<bundled>" [install|upgrade]` shape. Coarse on purpose; the AUTHORITATIVE matcher
    # is cx_check.py's _is_bootstrap_command (run whenever Python 3 is present). Anything that does
    # not match here falls through to the deny below (fail CLOSED).
    BOOT_DIR=$(cd "$SCRIPT_DIR/../scripts" 2>/dev/null && pwd)
    # Collapse JSON-escaped separators to plain '/': `\\` (a Windows path separator, doubled by
    # JSON) and `\"` (an escaped quote) both reduce to '/' under `tr -s`, so paths compare uniformly.
    # Only Windows paths carry backslashes, so if `tr` is unavailable we keep the raw INPUT — a
    # POSIX (forward-slash) bootstrap path still matches, and a Windows one simply fails CLOSED.
    if command -v tr >/dev/null 2>&1; then
        NORM=$(printf '%s' "$INPUT" | tr -s '\\' '/')
    else
        NORM=$INPUT
    fi
    BOOT_POSIX=""
    BOOT_WIN=""
    if [ -n "$BOOT_DIR" ]; then
        BOOT_POSIX="$BOOT_DIR/cx-bootstrap.sh"
        # On Git Bash $BOOT_DIR is a POSIX path (/c/...) but the agent's command carries a Windows
        # path (C:/...); cygpath -m yields the matching mixed form so the Windows case matches too.
        if command -v cygpath >/dev/null 2>&1; then
            _bw=$(cygpath -m "$BOOT_DIR" 2>/dev/null)
            [ -n "$_bw" ] && BOOT_WIN="$_bw/cx-bootstrap.sh"
        fi
    fi
    case "$NORM" in
        *'"tool_name":"Bash"'* | *'"tool_name": "Bash"'*)
            case "$NORM" in
                *';'* | *'|'* | *'&'* | *'`'* | *'$('* | *'<'* | *'>'*) ;;  # chaining → deny
                *)
                    for _bp in "$BOOT_POSIX" "$BOOT_WIN"; do
                        [ -n "$_bp" ] || continue
                        # Exact sanctioned shape ONLY: the command value is precisely
                        # `bash "<bundled-bootstrap>" install` (or upgrade) and nothing else. The
                        # `bash /"` prefix (a JSON `bash \"`) rejects `bash -c …`; the bundled
                        # ABSOLUTE path rejects foreign scripts; the trailing mode + closing quote
                        # reject extra arguments and a missing mode.
                        case "$NORM" in
                            *'"command":"bash /"'"$_bp"'/" install"'*  | \
                            *'"command": "bash /"'"$_bp"'/" install"'* | \
                            *'"command":"bash /"'"$_bp"'/" upgrade"'*  | \
                            *'"command": "bash /"'"$_bp"'/" upgrade"'*)
                                exit 0 ;;
                        esac
                    done
                    ;;
            esac
            ;;
    esac
    # No working Python 3 ⇒ the gate cannot evaluate ⇒ fail CLOSED (deny + exit 2). A plain
    # exit 1 would be treated as non-blocking by Claude Code and silently fail OPEN.
    cat <<'JSON'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"The Checkmarx security gate could not run: no working Python 3 interpreter was found, so the scanner is inactive. This operation is BLOCKED fail-closed.","additionalContext":"Install Python 3, then retry. Windows: install from https://python.org (NOT the Microsoft Store stub). macOS: `xcode-select --install` or `brew install python3`. Linux: `apt install python3` / `dnf install python3` / `apk add python3`. The plugin's bundled bootstrap (scripts/cx-bootstrap.sh) installs the cx CLI and itself needs NO Python, but this version/auth gate does. All agent actions remain blocked until a Python 3 interpreter is available."}}
JSON
    exit 2
fi

# Replay the captured stdin to Python (we already consumed it above, so it can't stream).
printf '%s' "$INPUT" | $PYTHON_BIN "$PY_SCRIPT" "$@"
