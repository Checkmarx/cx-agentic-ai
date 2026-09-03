#!/bin/sh
# cx_record_login.sh — the ONLY hook on the Bash matcher (shell commands are never blocked, matching
# cx-devassist's Claude Code design), and it is an OBSERVER, not a gate. It notes the
# --base-auth-uri / --tenant of a `cx auth login` so a later logged-out session can offer that
# environment back instead of re-asking the developer from scratch.
#
# WHY A SEPARATE OBSERVER IS NEEDED AT ALL, ON TOP OF THE GATE'S OWN INLINE RECORDING
#   cx_check.py's cx_check() already records a login attempt inline, at its auth-recovery carve-out —
#   but only for commands _is_auth_recovery_command admits (a narrow PERMISSION guard pinned to the
#   gate's own resolved cx path). That guard's false negatives are self-correcting for a permission
#   decision (the command is simply denied and the developer sees why), but as an OBSERVATION signal
#   a false negative is silent data loss: the remembered-environments feature just never fires, with
#   nothing logged to explain it. This script instead pipes into cx_check.py's LOOSER
#   _is_observable_login_command matcher (record-login mode), so any `<any cx path> auth|configure`
#   command gets recorded regardless of whether the gate's own admission guard happens to match it.
#
# WHY ast-cli's `cx auth login` BEHAVIOR MAKES OBSERVING THE COMMAND NECESSARY
#   ast-cli's `cx auth login` behaves two ways (auth_login.go:57-86). WITH connection flags
#   (--base-uri / --base-auth-uri / --tenant) it skips the prompt and persists ONLY the refresh token
#   (auth_login.go:102, params.AstAPIKey alone) — cx_base_auth_uri / cx_tenant never reach
#   checkmarxcli.yaml. WITHOUT them it prompts via PromptAuthConnection (configuration.go:98-119) and
#   DOES persist all three. An agent cannot answer an interactive prompt, so an agent-issued login is
#   always the flag form — the one that persists nothing; a non-interactive stdin likewise sets
#   nothing. (An API-key setup is worse still: the values live only inside the JWT, whose `iss` yields
#   the IAM host rather than the app host a developer types.) Hence observing the command as issued.
#
# WHY THIS CANNOT REINTRODUCE "EVERY COMMAND IS BLOCKED"
#   Only a hook's exit 0 with a deny JSON (or the client's equivalent) blocks a tool call. This script
#   emits NO JSON and exits 0 on EVERY path — including a missing Python, an unreadable state dir, and
#   any crash inside the recorder (cx_check.py's record-login mode swallows exceptions and forces
#   exit 0). It is the ONLY hook on the Bash matcher — there is no scan gate to loosen or replace,
#   matching the "shell commands are never blocked" design shared with cx-devassist (Claude Code).
#
# COST
#   The pure-shell prefilter below means an ordinary command (`git status`, `npm test`) costs one `sh`
#   spawn and nothing else — no Python, no cx. Python is spawned only for a command that actually
#   mentions `auth`/`configure`, which is rare. Deliberately NOT using cx_check.sh: its Python
#   interpreter-probe loop costs ~530ms per call, which would be paid on every command for a feature
#   that only concerns logins.
#
# Requires Git for Windows on Windows (same `sh` requirement as the other hooks; never bare `bash`,
# which Windows resolves to the System32 WSL stub). POSIX sh — no bashisms.

INPUT=$(cat) || exit 0

# PREFILTER (pure shell, NO subprocess) — deliberately the very first thing this script does, before
# even resolving its own directory: every `$(...)` costs a fork, and on Git-Bash forks are tens of ms
# that every shell command in the session would pay.
#
# Scoped to the COMMAND, not the whole payload. The payload also carries `cwd`, `transcript_path` and a
# model-written `description`, so matching all of it fired on commands with nothing to do with cx: a
# developer whose checkout path contains "auth" (…/work/authz-service) paid a full Python spawn on
# EVERY shell call — measured 757ms instead of 125ms — as did anyone running `./configure`,
# `pytest tests/test_auth.py`, or `git commit -m "fix auth"`. `${INPUT#*'"command":'}` is a builtin
# expansion (no fork); when there is no `"command":` key it leaves INPUT unchanged, which degrades to
# the old payload-wide behaviour rather than skipping a real login.
_cxrl_cmd=${INPUT#*'"command":'}

# `cx` first because it is the most selective: _OBSERVABLE_LOGIN_RE requires an executable token ending
# in cx/cx.exe, so a real login ALWAYS contains that substring — this cannot under-match. Bracket
# classes make both tests case-insensitive to match that regex's re.IGNORECASE; a case-sensitive
# `*auth*` would silently drop `CX AUTH LOGIN`.
case "$_cxrl_cmd" in
    *[Cc][Xx]*) : ;;
    *) exit 0 ;;
esac
case "$_cxrl_cmd" in
    *[Aa][Uu][Tt][Hh]* | *[Cc][Oo][Nn][Ff][Ii][Gg][Uu][Rr][Ee]*) : ;;
    *) exit 0 ;;
esac

# Only Bash payloads are worth handing to Python; a file write / apply_patch can never be a login.
case "$INPUT" in
    *'"tool_name":"Bash"'* | *'"tool_name": "Bash"'*) : ;;
    *) exit 0 ;;
esac

# Past the prefilter: this really might be a login, so the remaining setup cost is justified.
# `${0%/*}` instead of `$(cd "$(dirname "$0")" && pwd)` — the latter is a subshell plus a `dirname`
# exec (~100ms on Git-Bash) to produce a path hooks.json already passes absolutely.
case "$0" in
    */*) SCRIPT_DIR=${0%/*} ;;
    *)   SCRIPT_DIR=. ;;
esac
PY_SCRIPT="$SCRIPT_DIR/cx_check.py"
# On Windows/Git Bash, convert the POSIX path to a native Windows path for python.exe.
if command -v cygpath >/dev/null 2>&1; then
    PY_SCRIPT=$(cygpath -w "$PY_SCRIPT" 2>/dev/null) || PY_SCRIPT="$SCRIPT_DIR/cx_check.py"
fi
export PYTHONUTF8=1

# No probe loop and no `timeout` wrapper: unlike the gate, a failure here costs a remembered
# environment rather than a security decision, so the cheap path is the right one. `break` only on a
# real success, so Windows' Microsoft-Store `python3` stub (on PATH, exits non-zero without running
# anything) falls through to `python`.
#
# `py -3` is included for the same reason cx_check.sh includes it: a python.org install without "Add
# to PATH" leaves the `py` launcher as the ONLY interpreter, and on those hosts a python3/python-only
# loop silently does nothing — killing the whole remembered-environments feature with no error
# anywhere. It is last because it is Windows-only. Quoted "$_py" would break the two-word form, so the
# loop deliberately relies on word splitting; `set -f` guards against a stray glob in the value.
set -f
for _py in python3 python "py -3"; do
    # shellcheck disable=SC2086  # intentional split: "py -3" must expand to two words
    set -- $_py
    command -v "$1" >/dev/null 2>&1 || continue
    printf '%s' "$INPUT" | $_py "$PY_SCRIPT" record-login >/dev/null 2>&1 && break
done
set +f

# Unconditional: never let this observer's outcome reach Codex CLI as a blocking signal.
exit 0
