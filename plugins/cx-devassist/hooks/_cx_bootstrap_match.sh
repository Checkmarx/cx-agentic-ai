#!/bin/sh
# Shared bootstrap-command matcher for the SHELL stages of the gate. Recognizes ONLY the sanctioned
#   bash "<bundled scripts/cx-bootstrap.sh>" install|upgrade
# so the plugin's self-install can run while the gate is otherwise blocking. Used by BOTH
#   - cx_check.sh   (stage-1, its NO-PYTHON fallback branch), and
#   - cx_run.sh     (stage-2, its cx-ABSENT deny branch — the case that caused the bootstrap deadlock),
# so the two shell stages cannot drift into disagreeing about what the bootstrap looks like (one
# allowing, the other denying → the tool call blocked because every hook in a matcher must allow).
#
# Coarse ON PURPOSE — the AUTHORITATIVE matcher is hooks/cx_check.py `_is_bootstrap_command`, run
# whenever a Python 3 interpreter is present (the normal case). Keep this in lockstep with it. This
# guard is deliberately narrow: Bash tool only, NO shell chaining/substitution/redirects, and the
# command must be exactly `bash "<bundled bootstrap absolute path>" install|upgrade`. Anything else
# returns 1 so the caller falls through to its fail-CLOSED deny. Source this file; do not execute it.
# POSIX sh (no bashisms) — mirrors the launchers that source it.

# cx_is_bootstrap_command <hook_input_json> <hooks_dir>
#   $1 = the raw PreToolUse JSON the launcher read from stdin
#   $2 = the sourcing launcher's OWN directory (…/plugins/cx-devassist/hooks), used to resolve the
#        bundled bootstrap by absolute path so a foreign cx-bootstrap.sh elsewhere cannot match.
#   returns 0 (allow — it is the sanctioned bootstrap) or 1 (not a match → caller denies).
cx_is_bootstrap_command() {
    _cxbm_input="$1"
    _cxbm_boot_dir=$(cd "${2:-}/../scripts" 2>/dev/null && pwd) || return 1
    [ -n "$_cxbm_boot_dir" ] || return 1

    # Collapse JSON-escaped separators to plain '/': `\\` (a Windows path separator, doubled by JSON)
    # and `\"` (an escaped quote) both reduce to '/' under `tr -s`, so POSIX and Windows paths compare
    # uniformly. If `tr` is unavailable we keep the raw input — a POSIX (forward-slash) bootstrap path
    # still matches; a Windows one simply fails CLOSED (falls through to the caller's deny).
    if command -v tr >/dev/null 2>&1; then
        _cxbm_norm=$(printf '%s' "$_cxbm_input" | tr -s '\\' '/')
    else
        _cxbm_norm=$_cxbm_input
    fi

    _cxbm_boot_posix="$_cxbm_boot_dir/cx-bootstrap.sh"
    _cxbm_boot_win=""
    # On Git Bash $BOOT_DIR is a POSIX path (/c/…) but the agent's command carries a Windows path
    # (C:/…); cygpath -m yields the matching mixed form so the Windows case matches too.
    if command -v cygpath >/dev/null 2>&1; then
        _cxbm_bw=$(cygpath -m "$_cxbm_boot_dir" 2>/dev/null)
        [ -n "$_cxbm_bw" ] && _cxbm_boot_win="$_cxbm_bw/cx-bootstrap.sh"
    fi

    case "$_cxbm_norm" in
        *'"tool_name":"Bash"'* | *'"tool_name": "Bash"'*)
            case "$_cxbm_norm" in
                *';'* | *'|'* | *'&'* | *'`'* | *'$('* | *'<'* | *'>'*) return 1 ;;  # chaining/redirect → deny
            esac
            for _cxbm_bp in "$_cxbm_boot_posix" "$_cxbm_boot_win"; do
                [ -n "$_cxbm_bp" ] || continue
                # Exact sanctioned shape ONLY: the command value is precisely
                # `bash "<bundled-bootstrap>" install` (or upgrade) and nothing else. The `bash /"`
                # prefix (a JSON `bash \"`) rejects `bash -c …`; the bundled ABSOLUTE path rejects
                # foreign scripts; the trailing mode + closing quote reject extra arguments / a missing mode.
                case "$_cxbm_norm" in
                    *'"command":"bash /"'"$_cxbm_bp"'/" install"'*  | \
                    *'"command": "bash /"'"$_cxbm_bp"'/" install"'* | \
                    *'"command":"bash /"'"$_cxbm_bp"'/" upgrade"'*  | \
                    *'"command": "bash /"'"$_cxbm_bp"'/" upgrade"'*)
                        return 0 ;;
                esac
            done
            ;;
    esac
    return 1
}
