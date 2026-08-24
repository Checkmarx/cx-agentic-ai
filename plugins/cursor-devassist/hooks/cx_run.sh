#!/bin/sh
# cx_run.sh — run the SAME cx the gate validates, resolved by ABSOLUTE path where possible so the
# stage-2 scanner (and the agent's own cx commands) do NOT depend on PATH. A freshly-installed cx in
# the canonical store is usable immediately, even before this session's frozen PATH can see it
# (setx / shell-profile changes only affect FUTURE sessions). Resolution precedence mirrors
# hooks/cx_check.py _cx_exe():  CX_BINARY (pin) -> canonical store -> PATH.
# When cx resolves, it is exec'd transparently (stdin/stdout/stderr and exit code preserved) — EXCEPT
# for three cases:
#   - The blocking scan subcommands (cursor-before-shell / cursor-before-mcp / cursor-before-submit-prompt
#     / cursor-before-file-read / cursor-before-file-write), where stdout and the exit code are captured (not exec'd) just long
#     enough to record the native scanner's own allow/deny to cx-devassist.jsonl via cx_log.py, then
#     relayed unchanged. stderr still streams through live.
#   - cursor-after-file-edit (postToolUse) — captured the same way, but always exits 0 (a completed
#     write cannot be blocked; the scanner can only steer via additional_context).
#   - `mcp bridge` — this is THE command mcp.json declares as the MCP server itself, spawned by Cursor
#     outside the hook system entirely (no pre-execution gate runs first). A resolved cx that is below
#     the minimum version or missing the `mcp bridge` subcommand must NOT be exec'd blindly: it would
#     die on cobra's "unknown command" error before/during the JSON-RPC initialize handshake, which
#     surfaces as a generic, undiagnosable "-32000 / failed to reconnect". So this one case is
#     version/capability-checked first (scripts/cx-mcp-guard.sh, the same decision cx-bootstrap.sh's
#     verify() and cx_check.py's gate already make) and the exact outcome is logged to
#     cx-devassist.jsonl via cx_log.py — on success as well as denial — before exec'ing or refusing.
#
# When cx CANNOT be resolved at all, the fail mode depends on the sub-command so a missing cx is
# never a silent fail-OPEN on the scan path:
#   - cursor-before-mcp (a Checkmarx MCP call) -> emit a deny JSON + exit 2 (fail CLOSED, mirroring
#     cx_check.sh's no-Python deny) so the tool call is BLOCKED, unscanned.
#   - cursor-before-file-write -> exit 0, DEFERRING to stage 1 (cx_check.sh -> cx_check.py), which has
#     already decided this same call and correctly: it denies a scannable file when cx is absent and
#     allows an unscannable one. Denying again here cannot make a scannable write safer (verdicts merge
#     most-restrictive-wins, so stage 1's deny already stands) and DOES block the unscannable writes
#     stage 1 just allowed.
#   - cursor-after-file-edit (postToolUse) -> emit additional_context + exit 0 (a completed write
#     cannot be blocked).
#   - Advisory lifecycle hooks (…stop / …cursor-file-edit-capture) -> exit 0 (non-blocking by design).
#   - Anything else (mcp bridge, scan, auth, configure, version, …) -> stderr error + exit 1.
set -u

# The plugin's hooks/ directory, resolved ONCE for every site that needs it: the audit logger, the MCP
# guard / min-version paths, and the bootstrap matcher. `${0%/*}` rather than
# `$(cd "$(dirname "$0")" && pwd)` — the latter is a subshell plus a `dirname` exec (~86ms measured on
# Git-Bash Windows) to rebuild a path hooks.json already passes absolutely.
case "$0" in
    */*) _CXRUN_DIR=${0%/*} ;;
    *)   _CXRUN_DIR=. ;;
esac

# Write ONE cx_log.py audit record using the first WORKING Python 3: python3 -> python -> py -3.
# Best-effort by contract: every failure is swallowed and callers ignore the status.
_cxrun_log() {
    for _cxrun_py in python3 python "py -3"; do
        command -v "${_cxrun_py%% *}" >/dev/null 2>&1 || continue
        # shellcheck disable=SC2086
        $_cxrun_py "$_CXRUN_DIR/cx_log.py" "$@" >/dev/null 2>&1 && return 0
    done
    return 0
}

# OS detection mirrors cx_check.py's `os.name == "nt"`: on Windows the canonical store is under
# %LOCALAPPDATA%; on Unix it is ~/.checkmarx/bin. Keeping the two adapters OS-consistent avoids the
# resolution drift where the gate validates one cx but stage-2 runs another (a silent fail-open).
case "$(uname -s 2>/dev/null)" in
    MINGW* | MSYS* | CYGWIN*) _CX_WINDOWS=1 ;;
    *)                        _CX_WINDOWS=0 ;;
esac

# Absolute path of cx in the canonical per-OS store, if present and runnable — matching cx_check.py's
# _canonical_cx EXACTLY. Windows: %LOCALAPPDATA%\Checkmarx\cx\cx.exe, falling back to
# %USERPROFILE%\AppData\Local (what expanduser("~") resolves to) then $HOME\AppData\Local. Unix:
# ~/.checkmarx/bin/cx. The unix path is NOT probed on Windows (the gate does not either).
canonical_cx() {
    if [ "$_CX_WINDOWS" = 1 ]; then
        if [ -n "${LOCALAPPDATA:-}" ]; then _base="$LOCALAPPDATA"
        elif [ -n "${USERPROFILE:-}" ]; then _base="$USERPROFILE/AppData/Local"
        else _base="${HOME:-}/AppData/Local"; fi
        _win="$_base/Checkmarx/cx/cx.exe"
        [ -f "$_win" ] && { printf '%s\n' "$_win"; return 0; }
    else
        _unix="${HOME:-}/.checkmarx/bin/cx"
        [ -f "$_unix" ] && [ -x "$_unix" ] && { printf '%s\n' "$_unix"; return 0; }
    fi
    return 1
}

# A CX_BINARY pin is honored ONLY if it is a valid absolute path to an executable file — mirroring
# cx_check.py's _cx_binary (absolute + isfile + (non-Windows) executable). An invalid pin is IGNORED
# (fall through to the canonical store / PATH), never exec'd, so a relative or non-executable
# CX_BINARY can't become an exit-126/127 fail-open on the single-gated paths.
cx_binary_valid() {
    [ -n "${CX_BINARY:-}" ] || return 1
    case "$CX_BINARY" in
        /* | [A-Za-z]:[/\\]*) : ;;   # absolute (POSIX or Windows drive)
        *) return 1 ;;               # relative -> not honored
    esac
    [ -f "$CX_BINARY" ] || return 1
    [ "$_CX_WINDOWS" = 1 ] || [ -x "$CX_BINARY" ] || return 1
    return 0
}

# Resolve cx: CX_BINARY (valid pin) -> canonical store -> PATH. _CX_RESOLVED_TIER records WHICH
# tier supplied it (binary|canonical|path) — mirrors cx_check.py's _cx_exe_with_tier() — so a
# below/incapable/unrunnable MCP guard denial can explain WHY re-running the upgrade bootstrap
# won't help when CX_BINARY is the one pinning an unfit binary (the bootstrap only ever writes the
# canonical store, which a CX_BINARY pin continues to shadow).
CX_RESOLVED=""
_CX_RESOLVED_TIER=""
if cx_binary_valid; then
    CX_RESOLVED="$CX_BINARY"
    _CX_RESOLVED_TIER="binary"
elif _c="$(canonical_cx)"; then
    CX_RESOLVED="$_c"
    _CX_RESOLVED_TIER="canonical"
elif command -v cx >/dev/null 2>&1; then
    CX_RESOLVED="cx"
    _CX_RESOLVED_TIER="path"
fi

# Whether this invocation IS the blocking scan decision (a cursor pre-execution gate) — kept in
# lockstep with the cx-unresolved branch below. Post-write (cursor-after-file-edit) is NOT blocking:
# it only steers via additional_context.
#
# _CXRUN_TIMEOUT is this wrapper's OWN internal budget for the native scanner call below, kept
# comfortably under each subcommand's EXTERNAL hooks.json timeout (30s for the four cursor-before-*
# entries, 60s for cursor-before-file-write) so this script can detect a slow/hung native process
# and emit a well-formed deny itself, BEFORE Cursor's external timeout would kill this whole process
# tree and produce truly empty stdout with no diagnostic at all.
case "${1:-} ${2:-}" in
    *cursor-before-file-write*)
        _CXRUN_SCAN=1
        _CXRUN_POST=0
        _CXRUN_TIMEOUT=50
        ;;
    *cursor-before-shell* | *cursor-before-mcp* | *cursor-before-submit-prompt* | *cursor-before-file-read*)
        _CXRUN_SCAN=1
        _CXRUN_POST=0
        _CXRUN_TIMEOUT=25
        ;;
    *cursor-after-file-edit*)
        _CXRUN_SCAN=0
        _CXRUN_POST=1
        _CXRUN_TIMEOUT=0
        ;;
    *)
        _CXRUN_SCAN=0
        _CXRUN_POST=0
        _CXRUN_TIMEOUT=0
        ;;
esac

# Whether this invocation IS the MCP bridge spawn declared in .mcp.json — the exact-match (not a
# wildcard like the scan patterns above) so nothing else can accidentally take the guarded path.
case "${1:-} ${2:-}" in
    "mcp bridge") _CXRUN_MCP=1 ;;
    *)            _CXRUN_MCP=0 ;;
esac

if [ -n "$CX_RESOLVED" ]; then
    if [ "$_CXRUN_SCAN" = 1 ]; then
        # Capture (rather than exec) ONLY for the blocking scan decision, so this wrapper can observe
        # the native cx scanner's allow/deny and record it — a plain `exec` replaces this process, so
        # nothing downstream could ever see or log the actual vulnerability/policy block (AST-162014).
        # stderr still streams straight through (command substitution only captures stdout); stdin is
        # read once here and replayed to cx unchanged.
        _CXRUN_INPUT_FILE=$(mktemp 2>/dev/null) || _CXRUN_INPUT_FILE="/tmp/cxrun_hook.$$"
        cat > "$_CXRUN_INPUT_FILE"
        # TRUSTED BOOTSTRAP / AUTH / SETUP CARVE-OUT — the same shared matcher cx_check.sh applies to
        # the same input, so the two stages cannot disagree. It runs even when cx RESOLVED (not just
        # on the cx-absent branch below): the native scanner is free to have its own opinion about a
        # `cx auth login` command, and a stage-2 deny would override stage-1's allow and block the very
        # login the deny message asked for. Bootstrap/plugin-script commands are covered here too, so
        # re-running the installer is never blocked by a scan of the installer command itself.
        if [ -f "$_CXRUN_DIR/_cx_bootstrap_match.sh" ]; then
            . "$_CXRUN_DIR/_cx_bootstrap_match.sh"
            _CXRUN_GATE="$_CXRUN_DIR/cx_check.py"
            cx_is_auth_recovery_command "$_CXRUN_INPUT_FILE" "$_CXRUN_GATE" && \
                rm -f "$_CXRUN_INPUT_FILE" && printf '%s\n' '{"permission":"allow"}' && exit 0
            # `cx ignore-vulnerability ...` — a Stage-2 reliability carve-out, not a security-scope
            # widening: Stage 1 (cx_check.sh, the OTHER hooks.json entry for this same matcher) still
            # separately enforces its own auth/version/scanner-licensing gates on this command
            # exactly as before. What this skips is only the native-scanner call further below, which
            # is a blocking call subject to its own internal timeout at best — before that timeout
            # existed, a slow/hung native process meant this whole script just waited until Cursor's
            # OWN external hooks.json timeout killed it, producing empty stdout with no diagnostic at
            # all (the "no output" failures observed in practice). See cx_check.py's
            # _IGNORE_VULN_SUBCOMMAND comment for why this command is safe to trust without the
            # native scan (a bounded, self-referential bookkeeping command).
            #
            # Checked BEFORE cx_is_trusted_setup_command on purpose: that matcher's own POSIX
            # fallback chain (four sub-matchers, each capable of shelling out to Python separately)
            # measured ~5s of pure "not a match" overhead on a real Windows/Git-Bash machine — paying
            # that first would burn most of this hook's 30s external timeout before ever reaching the
            # cheap (~1s), independent check below, undermining the whole point of this carve-out.
            cx_is_ignore_vulnerability_command "$_CXRUN_INPUT_FILE" "$_CXRUN_GATE" && \
                rm -f "$_CXRUN_INPUT_FILE" && printf '%s\n' '{"permission":"allow"}' && exit 0
            cx_is_checkmarx_ignore_prep_command "$_CXRUN_INPUT_FILE" "$_CXRUN_GATE" && \
                rm -f "$_CXRUN_INPUT_FILE" && printf '%s\n' '{"permission":"allow"}' && exit 0
            cx_is_trusted_setup_command "$_CXRUN_INPUT_FILE" "$_CXRUN_DIR" && \
                rm -f "$_CXRUN_INPUT_FILE" && printf '%s\n' '{"permission":"allow"}' && exit 0
        fi
        # Bound the native call to _CXRUN_TIMEOUT (see its definition above) so THIS script can
        # detect a slow/hung scanner and emit a well-formed deny itself, before Cursor's own external
        # hooks.json timeout would kill this whole process tree and produce truly empty stdout with
        # no diagnostic at all. Falls back to the old, unbounded call on a `sh` without `timeout` —
        # already a minimal-enough environment that this one optimization being unavailable is not a
        # regression from before this fix existed.
        if command -v timeout >/dev/null 2>&1; then
            _CXRUN_OUTPUT=$(timeout "$_CXRUN_TIMEOUT" "$CX_RESOLVED" "$@" < "$_CXRUN_INPUT_FILE")
            _CXRUN_STATUS=$?
        else
            _CXRUN_OUTPUT=$("$CX_RESOLVED" "$@" < "$_CXRUN_INPUT_FILE")
            _CXRUN_STATUS=$?
        fi

        # decision + WHY: a literal deny in the native output is a genuine, well-formed finding
        # ("vulnerability_detected"). Otherwise, well-formed non-deny output is trusted as "allow"
        # ONLY when the exit code is also clean (0) — anything else, INCLUDING empty/garbage output
        # (a crash, or this wrapper's own timeout above killing the native process), is
        # "error_during_block": an unexpected/error condition, not evidence of "no issues found".
        # Previously, any exit code other than exactly 2 fell through to "allow, no_issues_found" —
        # including a crash that produced no output at all, which silently logged (and returned) a
        # clean allow with no evidence a scan ever ran.
        case "$_CXRUN_OUTPUT" in
            *'"permissionDecision":"deny"'* | *'"permission":"deny"'*)
                _CXRUN_DECISION=deny
                _CXRUN_REASON=vulnerability_detected
                ;;
            *'"permission"'* | *'"permissionDecision"'*)
                if [ "$_CXRUN_STATUS" -eq 0 ]; then
                    _CXRUN_DECISION=allow
                    _CXRUN_REASON=no_issues_found
                else
                    _CXRUN_DECISION=deny
                    _CXRUN_REASON=error_during_block
                fi
                ;;
            *)
                _CXRUN_DECISION=deny
                _CXRUN_REASON=error_during_block
                ;;
        esac

        # error_during_block with no well-formed JSON body (empty output, or garbage from a crash)
        # must still hand Cursor an actual deny — relaying empty/garbage stdout here is exactly what
        # used to look, from Cursor's side, like a silent hook failure with zero diagnostic
        # information. A well-formed deny (even a generic one) is always better than nothing.
        if [ "$_CXRUN_DECISION" = deny ] && [ "$_CXRUN_REASON" = error_during_block ]; then
            case "$_CXRUN_OUTPUT" in
                *'"permission"'* | *'"permissionDecision"'*) : ;;  # already well-formed — relay as-is
                *)
                    _CXRUN_OUTPUT='{"permission":"deny","user_message":"The Checkmarx security scanner did not return a result (it may have timed out or crashed). This is a hook-chain execution failure, NOT a decision about your file'"'"'s content — no scan of the content completed. This operation is BLOCKED fail-closed.","agent_message":"CHECKMARX_HOOK_DENY — The Checkmarx security scan did not complete (timed out or crashed) for this command — a hook-chain failure, not a content-based policy denial. This is usually transient (often caused by several actions firing at once and competing for the same scan). Wait a few seconds and retry the exact same command once. If it fails the same way again, stop and report it — do not re-wrap it in bash -c, cmd /c, or backtick-escaping.","additional_context":"CHECKMARX_HOOK_DENY — The Checkmarx security scan did not complete (timed out or crashed) for this command — a hook-chain failure, not a content-based policy denial. This is usually transient (often caused by several actions firing at once and competing for the same scan). Wait a few seconds and retry the exact same command once. If it fails the same way again, stop and report it — do not re-wrap it in bash -c, cmd /c, or backtick-escaping."}'
                    _CXRUN_STATUS=2
                    ;;
            esac
        fi
        _CXRUN_TOOL=$(sed -n 's/.*"tool_name" *: *"\([A-Za-z0-9_.:-]*\)".*/\1/p' "$_CXRUN_INPUT_FILE" | head -1)

        _cxrun_log scan_decision \
            "decision=$_CXRUN_DECISION" "tool_name=$_CXRUN_TOOL" "reason_code=$_CXRUN_REASON"

        printf '%s\n' "$_CXRUN_OUTPUT"
        rm -f "$_CXRUN_INPUT_FILE"
        exit "$_CXRUN_STATUS"
    fi
    if [ "$_CXRUN_POST" = 1 ]; then
        # PostToolUse (cursor-after-file-edit): write already landed — relay scanner output and
        # always exit 0. The native cx hook emits {"additional_context":"..."} when findings exist.
        _CXRUN_INPUT_FILE=$(mktemp 2>/dev/null) || _CXRUN_INPUT_FILE="/tmp/cxrun_hook.$$"
        cat > "$_CXRUN_INPUT_FILE"
        _CXRUN_OUTPUT=$("$CX_RESOLVED" "$@" < "$_CXRUN_INPUT_FILE")
        _CXRUN_STATUS=$?
        _CXRUN_TOOL=$(sed -n 's/.*"tool_name" *: *"\([A-Za-z0-9_.:-]*\)".*/\1/p' "$_CXRUN_INPUT_FILE" | head -1)
        _cxrun_log scan_decision \
            "decision=allow" "tool_name=$_CXRUN_TOOL" "reason_code=post_tool_use"
        printf '%s\n' "$_CXRUN_OUTPUT"
        rm -f "$_CXRUN_INPUT_FILE"
        exit 0
    fi
    if [ "$_CXRUN_MCP" = 1 ]; then
        _CXRUN_GUARD="$_CXRUN_DIR/../scripts/cx-mcp-guard.sh"
        _CXRUN_MIN_FILE="$_CXRUN_DIR/../scripts/cx-min-version"
        _CXRUN_MCP_STATE=""
        _CXRUN_MCP_HAVE=""
        _CXRUN_MCP_MIN=""
        if [ -r "$_CXRUN_GUARD" ]; then
            # shellcheck source=../scripts/cx-mcp-guard.sh
            . "$_CXRUN_GUARD"
            _CXRUN_MCP_STATE=$(cx_mcp_guard_state "$CX_RESOLVED" "$_CXRUN_MIN_FILE")
            _CXRUN_MCP_HAVE=$(cx_mcp_parse_semver "$("$CX_RESOLVED" version 2>&1)") || _CXRUN_MCP_HAVE=""
            # No hardcoded fallback here — omitted falls through to cx_mcp_load_min_version's own
            # single default, so the floor constant lives in exactly one place in this module.
            _CXRUN_MCP_MIN=$(cx_mcp_load_min_version "$_CXRUN_MIN_FILE")
        fi
        # A missing/unsourceable guard helper (a broken install) must NOT make the MCP worse than it
        # was before this check existed — unlike cx_check.py's fail-closed SCAN gate, this guard is a
        # reliability diagnostic, not a security control, so an unevaluable guard falls through to the
        # plain exec below exactly as cx_run.sh always has (empty state ~ "ok").
        case "$_CXRUN_MCP_STATE" in
            ok | dev | "")
                _CXRUN_MCP_RESULT=ok
                _CXRUN_MCP_REASON="${_CXRUN_MCP_STATE:-ok}"
                ;;
            *)
                _CXRUN_MCP_RESULT=denied
                _CXRUN_MCP_REASON="$_CXRUN_MCP_STATE"
                ;;
        esac

        _cxrun_log mcp_connect \
            "result=$_CXRUN_MCP_RESULT" "reason_code=$_CXRUN_MCP_REASON" \
            "version_have=$_CXRUN_MCP_HAVE" "version_min=$_CXRUN_MCP_MIN" \
            "tier=$_CX_RESOLVED_TIER"

        if [ "$_CXRUN_MCP_RESULT" = denied ]; then
            # Refuse to exec a subcommand this build can't run — that is what corrupts the stdio
            # transport into today's opaque -32000. stdout stays untouched (no partial MCP framing);
            # the reason goes to stderr (captured in Cursor's own MCP log) AND to cx-devassist.jsonl
            # above, so a connect failure always has an exact cause on disk.
            case "$_CXRUN_MCP_REASON" in
                below)
                    printf 'cx-devassist: Checkmarx MCP bridge unavailable: cx v%s is below the required v%s. Run "bash scripts/cx-bootstrap.sh upgrade" to upgrade.\n' \
                        "$_CXRUN_MCP_HAVE" "$_CXRUN_MCP_MIN" >&2
                    ;;
                incapable)
                    printf "cx-devassist: Checkmarx MCP bridge unavailable: cx v%s is missing the 'mcp bridge' subcommand (capability-incomplete build). Run \"bash scripts/cx-bootstrap.sh upgrade\".\\n" \
                        "$_CXRUN_MCP_HAVE" >&2
                    ;;
                unrunnable)
                    printf 'cx-devassist: Checkmarx MCP bridge unavailable: cx version did not run or returned no usable version. Run "bash scripts/cx-bootstrap.sh install".\n' >&2
                    ;;
                *)
                    printf 'cx-devassist: Checkmarx MCP bridge unavailable (%s). Run "bash scripts/cx-bootstrap.sh install".\n' "$_CXRUN_MCP_REASON" >&2
                    ;;
            esac
            # CX_BINARY takes priority over the canonical store in this exact resolution — re-running
            # the bootstrap upgrade only writes the canonical store, so it would silently NOT fix a
            # CX_BINARY-pinned denial. Say so explicitly instead of leaving a confusing "I upgraded
            # but it's still broken" loop.
            if [ "$_CX_RESOLVED_TIER" = "binary" ]; then
                printf 'cx-devassist: Note: CX_BINARY is pinned to this exact binary and takes priority over the canonical store, so running the bootstrap will NOT fix this. Unset CX_BINARY, replace the binary at that exact path, or repoint CX_BINARY at the canonical store after upgrading.\n' >&2
            fi
            exit 1
        fi
        # ok / dev / guard-unavailable — fall through to the plain exec below.
    fi
    exec "$CX_RESOLVED" "$@"
fi

# --- cx could not be resolved anywhere: pick a fail mode that never silently opens the scan path. ---
case "${1:-} ${2:-}" in
    *cursor-before-file-write*)
        # Bootstrap carve-out: the sanctioned self-install must pass even though cx is absent.
        _CXRUN_INPUT_FILE=$(mktemp 2>/dev/null) || _CXRUN_INPUT_FILE="/tmp/cxrun_hook.$$"
        cat > "$_CXRUN_INPUT_FILE"
        if [ -f "$_CXRUN_DIR/_cx_bootstrap_match.sh" ]; then
            . "$_CXRUN_DIR/_cx_bootstrap_match.sh"
            cx_is_trusted_setup_command "$_CXRUN_INPUT_FILE" "$_CXRUN_DIR" && \
                rm -f "$_CXRUN_INPUT_FILE" && printf '%s\n' '{"permission":"allow"}' && exit 0
        fi
        rm -f "$_CXRUN_INPUT_FILE"
        # Stage 1 (cx_check) has already applied scannable-file logic to this exact call — defer here
        # so unscannable writes stage 1 allowed are not denied again.
        exit 0
        ;;
    *cursor-before-mcp* | *cursor-before-submit-prompt* | *cursor-before-file-read*)
        _CXRUN_INPUT_FILE=$(mktemp 2>/dev/null) || _CXRUN_INPUT_FILE="/tmp/cxrun_hook.$$"
        cat > "$_CXRUN_INPUT_FILE"
        if [ -f "$_CXRUN_DIR/_cx_bootstrap_match.sh" ]; then
            . "$_CXRUN_DIR/_cx_bootstrap_match.sh"
            cx_is_trusted_setup_command "$_CXRUN_INPUT_FILE" "$_CXRUN_DIR" && \
                rm -f "$_CXRUN_INPUT_FILE" && printf '%s\n' '{"permission":"allow"}' && exit 0
        fi
        rm -f "$_CXRUN_INPUT_FILE"
        _CXRUN_BOOTSTRAP="$(cd "$_CXRUN_DIR/.." && pwd)/scripts/cx-bootstrap.sh"
        if command -v cygpath >/dev/null 2>&1; then
            _CXRUN_BOOTSTRAP=$(cygpath -m "$_CXRUN_BOOTSTRAP")
        fi
        cat <<JSON
{"permission":"deny","user_message":"The Checkmarx security scanner could not run: the cx CLI could not be resolved. This operation is BLOCKED fail-closed.","agent_message":"CHECKMARX_HOOK_DENY — MANDATORY agent_message (follow exactly; cx-hook-deny rule applies):\n\nRun the plugin bundled bootstrap to install and authenticate the cx CLI, then retry the blocked operation:\n    bash \"${_CXRUN_BOOTSTRAP}\" install\n\nThe gate resolves cx from the canonical store (%LOCALAPPDATA%\\\\Checkmarx\\\\cx\\\\cx.exe on Windows, ~/.checkmarx/bin/cx on Unix) by absolute path. Shell commands and writes to file types Checkmarx cannot scan still run, so you can install cx from here.","additional_context":"CHECKMARX_HOOK_DENY — MANDATORY agent_message (follow exactly; cx-hook-deny rule applies):\n\nRun the plugin bundled bootstrap to install and authenticate the cx CLI, then retry the blocked operation:\n    bash \"${_CXRUN_BOOTSTRAP}\" install\n\nThe gate resolves cx from the canonical store (%LOCALAPPDATA%\\\\Checkmarx\\\\cx\\\\cx.exe on Windows, ~/.checkmarx/bin/cx on Unix) by absolute path. Shell commands and writes to file types Checkmarx cannot scan still run, so you can install cx from here."}
JSON
        exit 2
        ;;
    *cursor-before-shell*)
        # Shell commands are no longer gated — this path should not run; stay non-blocking if invoked.
        exit 0
        ;;
    *cursor-after-file-edit*)
        cat <<'JSON'
{"additional_context":"The Checkmarx security scanner could not run: the cx CLI is not installed or not on PATH. Run this plugin's bundled bootstrap (bash scripts/cx-bootstrap.sh install) to install and authenticate cx, then review the file you just wrote for security issues."}
JSON
        exit 0
        ;;
    *stop* | *cursor-file-edit-capture*)
        # Advisory lifecycle hook (stop) — stay non-blocking when cx is genuinely absent.
        # cursor-file-edit-capture is included here too: it only caches a diff for later
        # correlation (no security decision of its own), so a missing cx just means the
        # subsequent postToolUse scan falls back to its existing whole-file scan — never a reason
        # to block or error the edit itself.
        exit 0
        ;;
    *)
        if [ "$_CXRUN_MCP" = 1 ]; then
            _cxrun_log mcp_connect "result=denied" "reason_code=cx_absent"
        fi
        printf 'cx-devassist: cx CLI not found (looked at CX_BINARY, the canonical store, and PATH). Run "bash scripts/cx-bootstrap.sh install" to install it.\n' >&2
        exit 1
        ;;
esac
