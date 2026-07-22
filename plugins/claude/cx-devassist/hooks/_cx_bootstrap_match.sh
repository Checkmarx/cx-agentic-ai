#!/bin/sh
# Shared bootstrap-command matcher for the SHELL stages of the gate. Recognizes ONLY the sanctioned
#   sh "<bundled scripts/cx-bootstrap.sh>" install|upgrade
# so the plugin's self-install can run while the gate is otherwise blocking. Used by BOTH
#   - cx_check.sh   (stage-1, its NO-PYTHON fallback branch), and
#   - cx_run.sh     (stage-2, its cx-ABSENT deny branch — the case that caused the bootstrap deadlock),
# so the two shell stages cannot drift into disagreeing about what the bootstrap looks like (one
# allowing, the other denying → the tool call blocked because every hook in a matcher must allow).
#
# Coarse ON PURPOSE — the AUTHORITATIVE matcher is hooks/cx_check.py `_is_bootstrap_command`, run
# whenever a Python 3 interpreter is present (the normal case). Keep this in lockstep with it. This
# guard is deliberately narrow: shell tool only, NO shell chaining/substitution/redirects, and the
# command must be exactly `sh "<bundled bootstrap absolute path>" install|upgrade`. Anything else
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

    # Two normalization strategies depending on input format:
    #
    # Claude Code: tool_name/tool_input fields — raw JSON has literal backslashes only in Windows
    #   paths (e.g. C:\path\...) which are JSON-encoded as C:\\path\\.... Collapsing `\` → `/`
    #   via `tr` normalizes both POSIX and Windows paths to forward-slash form for matching.
    #
    # Copilot CLI: toolName/toolArgs fields — the agent always writes bootstrap paths with FORWARD
    #   slashes (cx_check.py's _bootstrap_command_str() calls .replace("\\","/")), so NO `tr`
    #   normalization is needed. CRITICALLY: applying `tr` to Copilot CLI JSON corrupts the input
    #   because JSON-escaped quotes (`\"`) contain a backslash that tr converts to `/`, turning
    #   `"toolName":"powershell"` into `/"toolName/":/"powershell/"` — breaking all pattern matches.
    #   Use the raw input for Copilot CLI pattern matching.
    #
    # Detect the format by presence of `toolArgs` / `toolName` (Copilot CLI) or `tool_name` (Claude).
    _cxbm_is_copilot=0
    case "$_cxbm_input" in
        *'"toolArgs"'* | *'"toolName"'*) _cxbm_is_copilot=1 ;;
    esac

    if [ "$_cxbm_is_copilot" = "0" ]; then
        # Claude Code format: apply tr normalization for Windows path backslashes.
        if command -v tr >/dev/null 2>&1; then
            _cxbm_norm=$(printf '%s' "$_cxbm_input" | tr -s '\\' '/')
        else
            _cxbm_norm=$_cxbm_input
        fi
    else
        # Copilot CLI format: use raw input — path is already forward-slash, no tr needed.
        _cxbm_norm=$_cxbm_input
    fi

    _cxbm_boot_posix="$_cxbm_boot_dir/cx-bootstrap.sh"
    _cxbm_boot_win=""
    # On Git Bash $BOOT_DIR is a POSIX path (/c/…) but the agent's command may carry a Windows path
    # (C:/…); cygpath -m yields the matching mixed form so the Windows case matches too.
    if command -v cygpath >/dev/null 2>&1; then
        _cxbm_bw=$(cygpath -m "$_cxbm_boot_dir" 2>/dev/null)
        [ -n "$_cxbm_bw" ] && _cxbm_boot_win="$_cxbm_bw/cx-bootstrap.sh"
    fi

    # Reject chaining/redirect metacharacters — same security guard as cx_check.py _bare_bash_command.
    case "$_cxbm_norm" in
        *'"; '* | *'"| '* | *'`'* | *'$('* | *'<'* | *'>"'*) return 1 ;;
    esac

    if [ "$_cxbm_is_copilot" = "0" ]; then
        # ── Claude Code format ──────────────────────────────────────────────────────────────────
        # tool_name = Bash or command; command field = `sh "<abs-path>" install|upgrade`
        case "$_cxbm_norm" in
            *'"tool_name":"Bash"'*    | *'"tool_name": "Bash"'*    | \
            *'"tool_name":"command"'* | *'"tool_name": "command"'*)
                for _cxbm_bp in "$_cxbm_boot_posix" "$_cxbm_boot_win"; do
                    [ -n "$_cxbm_bp" ] || continue
                    case "$_cxbm_norm" in
                        *'"command":"bash /"'"$_cxbm_bp"'/" install"'*  | \
                        *'"command": "bash /"'"$_cxbm_bp"'/" install"'* | \
                        *'"command":"bash /"'"$_cxbm_bp"'/" upgrade"'*  | \
                        *'"command": "bash /"'"$_cxbm_bp"'/" upgrade"'* | \
                        *'"command":"sh /"'"$_cxbm_bp"'/" install"'*    | \
                        *'"command": "sh /"'"$_cxbm_bp"'/" install"'*   | \
                        *'"command":"sh /"'"$_cxbm_bp"'/" upgrade"'*    | \
                        *'"command": "sh /"'"$_cxbm_bp"'/" upgrade"'*)
                            return 0 ;;
                    esac
                done ;;
        esac
    else
        # ── Copilot CLI format ──────────────────────────────────────────────────────────────────
        # toolName = powershell|bash|shell|command; toolArgs = JSON string with command field.
        # cx_check.py's _bootstrap_command_str() emits `sh "forward/slash/path" install|upgrade`
        # so the path in toolArgs always uses forward slashes — no tr needed.
        case "$_cxbm_norm" in
            *'"toolName":"powershell"'* | *'"toolName": "powershell"'* | \
            *'"toolName":"bash"'*       | *'"toolName": "bash"'*       | \
            *'"toolName":"shell"'*      | *'"toolName": "shell"'*      | \
            *'"toolName":"command"'*    | *'"toolName": "command"'*    | \
            *'"name":"powershell"'*     | *'"name": "powershell"'*     | \
            *'"name":"bash"'*           | *'"name": "bash"'*           | \
            *'"name":"shell"'*          | *'"name": "shell"'*)
                for _cxbm_bp in "$_cxbm_boot_posix" "$_cxbm_boot_win"; do
                    [ -n "$_cxbm_bp" ] || continue
                    # toolArgs is a JSON-encoded string so internal quotes are escaped (\").
                    # Pattern: toolArgs contains ...\"command\":\"sh \"<path>\" install\"...
                    case "$_cxbm_norm" in
                        *'\"command\":\"sh \"'"$_cxbm_bp"'\" install\"'*  | \
                        *'\"command\": \"sh \"'"$_cxbm_bp"'\" install\"'* | \
                        *'\"command\":\"sh \"'"$_cxbm_bp"'\" upgrade\"'*  | \
                        *'\"command\": \"sh \"'"$_cxbm_bp"'\" upgrade\"'* | \
                        *'\"command\":\"bash \"'"$_cxbm_bp"'\" install\"'*  | \
                        *'\"command\": \"bash \"'"$_cxbm_bp"'\" install\"'* | \
                        *'\"command\":\"bash \"'"$_cxbm_bp"'\" upgrade\"'*  | \
                        *'\"command\": \"bash \"'"$_cxbm_bp"'\" upgrade\"'*)
                            return 0 ;;
                    esac
                done ;;
        esac
    fi
    return 1
}
