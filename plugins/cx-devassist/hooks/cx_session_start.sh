#!/bin/sh
# cx_session_start.sh — emits cx_check.py's `session-start` JSON (the posture announcement) on stdout.
# ANNOUNCER, not a gate: SessionStart carries no permission decision and every path here exits 0.
# See cx_check.py's cx_session_start() for the two output channels and what the posture costs.
#
# Why `sh` and not `bash`: on Windows a bare `bash` resolves to the System32 WSL launcher, which is
# handed a Windows path it cannot open and exits 127. `sh` has no System32 variant. POSIX sh — no
# bashisms — so it runs under dash/ash too.

# Drain the stdin payload so the writer never sees a broken pipe; the announcer derives everything from
# cx itself. A builtin loop, not `cat` — measured, `cat` costs a ~65ms fork here to discard bytes, the
# loop ~4ms. (The sibling hooks use `INPUT=$(cat)` because they actually consume the payload.)
while IFS= read -r _cxss_discard; do :; done

# `${0%/*}` rather than `$(cd "$(dirname "$0")" && pwd)`: the latter is a subshell plus a `dirname`
# exec (~86ms on Git-Bash Windows) to rebuild a path hooks.json already passes absolutely.
case "$0" in
    */*) SCRIPT_DIR=${0%/*} ;;
    *)   SCRIPT_DIR=. ;;
esac
PY_SCRIPT="$SCRIPT_DIR/cx_check.py"

# Turn EVERY dir-resolution failure into a visible diagnostic instead of a silent missing banner. This
# covers the whole family — a `$0` with no separator, a pure-backslash path, an unexpanded
# ${CLAUDE_PLUGIN_ROOT}, a truncated install — where a separator-matching `case` would only have caught
# one of them. stderr, never stdout: stdout IS the announcement channel and must stay pure JSON.
if [ ! -f "$PY_SCRIPT" ]; then
    printf 'cx-devassist: cx_check.py not found next to %s — no posture announcement.\n' "$0" >&2
    exit 0
fi

# On Windows/Git Bash, hand python.exe a native path — but only when the path is not ALREADY
# drive-lettered. hooks.json passes ${CLAUDE_PLUGIN_ROOT}/hooks/…, and CLAUDE_PLUGIN_ROOT is a native
# Windows path, so in production this is a 67ms fork that only swaps slashes python accepts either way.
case "$PY_SCRIPT" in
    [A-Za-z]:*) ;;
    *)
        if command -v cygpath >/dev/null 2>&1; then
            PY_SCRIPT=$(cygpath -w "$PY_SCRIPT" 2>/dev/null) || PY_SCRIPT="$SCRIPT_DIR/cx_check.py"
        fi
        ;;
esac

export PYTHONUTF8=1

# First WORKING Python 3: python3 -> python -> py -3. Keep this candidate list in step with
# cx_record_login.sh's and cx_run.sh's — a Windows host reachable only through the `py` launcher is a
# normal python.org install. Deliberately NOT cx_check.sh's rigorous probe loop (~530ms): here a
# candidate that turns out to be Python 2 just fails and the loop moves on.
for _cxss_py in python3 python "py -3"; do
    # Probe the command word only — `py -3` is command plus argument.
    _cxss_which=$(command -v "${_cxss_py%% *}" 2>/dev/null) || continue
    # Skip Windows' Microsoft Store App Execution Aliases. They are ON PATH, so the probe above says
    # yes, but they run nothing — they print an "install from the Microsoft Store" notice and exit
    # non-zero. Measured 209ms to learn that, per session start, before falling through to the real
    # interpreter. `command -v` is a builtin, so recognising them costs ~1ms.
    case "$_cxss_which" in *[Ww]indows[Aa]pps*) continue ;; esac
    # Run UNQUOTED so `py -3` word-splits; safe from globbing, all three candidates are literals.
    # CAPTURE rather than letting the interpreter write straight through: stdout IS the announcement,
    # and a working Python 3 can still pollute it (sitecustomize.py, PYTHONSTARTUP, a conda activation
    # banner, a corporate wrapper). `break` on a successful RUN — not on a match — so an interpreter
    # that legitimately prints nothing (the "posture unknown, stay quiet" path) does not send the loop
    # on to re-run the whole readiness chain under the next candidate.
    # shellcheck disable=SC2086
    _cxss_out=$($_cxss_py "$PY_SCRIPT" session-start 2>/dev/null) && break
done

# Emit only a real JSON object; anything else is dropped rather than announced. Prefix-matching means a
# junk-then-JSON stdout is discarded rather than salvaged — deliberate: a missing banner beats a wrong one.
case "${_cxss_out:-}" in
    '{'*) printf '%s\n' "$_cxss_out" ;;
esac

exit 0
