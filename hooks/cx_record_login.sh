#!/bin/sh
# cx_record_login.sh — the ONLY hook this extension puts on run_shell_command, and it is an
# OBSERVER, not a gate. It notes the --base-auth-uri / --tenant of a `cx auth login` so a later
# logged-out session can offer that environment back instead of re-asking the developer from
# scratch.
#
# WHY A SHELL HOOK IS REQUIRED AT ALL
#   ast-cli's `cx auth login` behaves two ways (auth_login.go:57-86). WITH connection flags
#   (--base-uri / --base-auth-uri / --tenant) it skips the prompt and persists ONLY the refresh
#   token (auth_login.go:102, params.AstAPIKey alone) — cx_base_auth_uri / cx_tenant never reach
#   checkmarxcli.yaml. WITHOUT them it prompts via PromptAuthConnection (configuration.go:98-119)
#   and DOES persist all three. An agent cannot answer an interactive prompt, so an agent-issued
#   login is always the flag form — the one that persists nothing; a non-interactive stdin
#   likewise sets nothing. Hence observing the command as issued.
#
# WHY THIS CANNOT REINTRODUCE A BLOCKING SHELL GATE
#   Only a hook's non-zero exit (Claude Code) or a decision:"deny" payload (Gemini CLI) blocks a
#   tool call. This script emits NO JSON and exits 0 on EVERY path — including a missing Python,
#   an unreadable state dir, and any crash inside the recorder (cx_check.py's record-login mode
#   swallows exceptions and forces exit 0). run_shell_command carries no readiness gate at all in
#   hooks.json — only this observer — so a broken cx can never stop a shell command.
#
# COST
#   The pure-shell prefilter below means an ordinary command (`git status`, `npm test`) costs one
#   `sh` spawn and nothing else — no Python, no cx. Python is spawned only for a command that
#   actually mentions `auth`/`configure`, which is rare. Deliberately NOT using cx_check.sh: its
#   Python interpreter-probe loop costs real time per call, which would be paid on every command
#   for a feature that only concerns logins.
#
# Requires Git for Windows on Windows (same `sh` requirement as the other hooks; never bare
# `bash`, which Windows resolves to the System32 WSL stub — see cx_check.sh). POSIX sh — no
# bashisms.

INPUT=$(cat) || exit 0

# PREFILTER (pure shell, NO subprocess) — deliberately the very first thing this script does,
# before even resolving its own directory: every `$(...)` costs a fork.
#
# Scoped to the COMMAND, not the whole payload. The payload also carries `cwd` and other fields,
# so matching all of it would fire on commands with nothing to do with cx (a checkout path
# containing "auth", `./configure`, `git commit -m "fix auth"`, …), paying a full Python spawn on
# every shell call. `${INPUT#*'"command":'}` is a builtin expansion (no fork); when there is no
# `"command":` key it leaves INPUT unchanged, which degrades to the old payload-wide behaviour
# rather than skipping a real login.
_cxrl_cmd=${INPUT#*'"command":'}

# `cx` first because it is the most selective: the Python-side matcher requires an executable
# token ending in cx/cx.exe, so a real login ALWAYS contains that substring — this cannot
# under-match. Bracket classes make both tests case-insensitive.
case "$_cxrl_cmd" in
    *[Cc][Xx]*) : ;;
    *) exit 0 ;;
esac
# Require cx/cx.exe immediately followed by auth|configure — mirroring _OBSERVABLE_LOGIN_RE in
# cx_check.py. The old *auth*/*configure* tests matched anywhere in the JSON tail (e.g.
# "authenticated": true after the command value), which spawned Python on every `cx scan` shell
# call and tripped the 10s hook timeout.
case "$_cxrl_cmd" in
    *cx.exe\"[[:space:]]auth*|*cx.exe\"[[:space:]]configure*|\
    *cx.exe\'[[:space:]]auth*|*cx.exe\'[[:space:]]configure*|\
    *cx\"[[:space:]]auth*|*cx\"[[:space:]]configure*|\
    *cx\'[[:space:]]auth*|*cx\'[[:space:]]configure*|\
    *cx[[:space:]]auth*|*cx[[:space:]]configure*) : ;;
    *) exit 0 ;;
esac

# Only run_shell_command payloads are worth handing to Python; a file write can never be a login.
# Match snake_case, camelCase, and toolCalls[].name so a payload-shape drift cannot skip Python
# (that used to mean cx_login_history.json was never written).
case "$INPUT" in
    *'"tool_name":"run_shell_command"'*|*'"tool_name": "run_shell_command"'*|*'"toolName":"run_shell_command"'*|*'"toolName": "run_shell_command"'*|*'"name":"run_shell_command"'*|*'"name": "run_shell_command"'*) : ;;
    *) exit 0 ;;
esac

# Past the prefilter: this really might be a login, so the remaining setup cost is justified.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PY_SCRIPT="$SCRIPT_DIR/cx_check.py"
# On Windows/Git Bash, convert the POSIX path to a native Windows path for python.exe.
if command -v cygpath >/dev/null 2>&1; then
    PY_SCRIPT=$(cygpath -w "$PY_SCRIPT" 2>/dev/null) || PY_SCRIPT="$SCRIPT_DIR/cx_check.py"
fi
export PYTHONUTF8=1

# Bound each Python attempt so a wedged interpreter (e.g. the Microsoft Store python3 stub on
# Windows) cannot burn the whole 10s hook budget — mirrors hooks/cx_check.sh probe_python().
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

# No unbounded probe loop: unlike the gate, a failure here costs a remembered environment rather
# than a security decision, but a wedged interpreter must not trip the hook timeout either.
set -f
for _py in python3 python "py -3"; do
    # shellcheck disable=SC2086  # intentional split: "py -3" must expand to two words
    set -- $_py
    command -v "$1" >/dev/null 2>&1 || continue
    printf '%s' "$INPUT" | probe_python $_py "$PY_SCRIPT" record-login >/dev/null 2>&1 && break
done
set +f

# Unconditional: never let this observer's outcome reach the client as a blocking signal.
exit 0
