#!/bin/sh
# cx_run.sh — run the SAME cx the gate validates, resolved by ABSOLUTE path where possible so the
# stage-2 scanner (and the agent's own cx commands) do NOT depend on PATH. A freshly-installed cx in
# the canonical store is usable immediately, even before this session's frozen PATH can see it
# (setx / shell-profile changes only affect FUTURE sessions). Resolution precedence mirrors
# hooks/cx_check.py _cx_exe():  CX_BINARY (pin) -> canonical store -> PATH.
# When cx resolves, it is exec'd transparently (stdin/stdout/stderr and exit code preserved) — EXCEPT
# for two cases:
#   - The two blocking scan subcommands (…pre-tool-use / …pre-file-write), where stdout and the exit
#     code are captured (not exec'd) just long enough to record the native scanner's own allow/deny to
#     checkmarx-devassist.jsonl via cx_log.py, then relayed unchanged. stderr still streams through live.
#   - `mcp bridge` — this is THE command .mcp.json declares as the MCP server itself, spawned by
#     Claude Code outside the hook system entirely (no PreToolUse gate runs first). A resolved cx that
#     is below the minimum version or missing the `mcp bridge` subcommand must NOT be exec'd blindly:
#     it would die on cobra's "unknown command" error before/during the JSON-RPC initialize handshake,
#     which Claude Code surfaces as a generic, undiagnosable "-32000 / failed to reconnect". So this
#     one case is version/capability-checked first (scripts/cx-mcp-guard.sh, the same decision
#     cx-bootstrap.sh's verify() and cx_check.py's gate already make) and the exact outcome is logged
#     to checkmarx-devassist.jsonl via cx_log.py — on success as well as denial — before exec'ing or refusing.
#
# When cx CANNOT be resolved at all, the fail mode depends on the sub-command so a missing cx is
# never a silent fail-OPEN on the scan path:
#   - Blocking PreToolUse scanners (…pre-tool-use / …pre-file-write) -> emit a deny JSON + exit 2
#     (fail CLOSED, mirroring cx_check.sh's no-Python deny) so the tool call is BLOCKED, unscanned.
#   - Advisory lifecycle hooks (…stop / …idle / …prompt-submit) -> exit 0 (non-blocking by design;
#     a fail-closed prompt-submit would deadlock the user before they could even install cx).
#   - Anything else (mcp bridge, scan, auth, configure, version, …) -> stderr error + exit 1.
set -u

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

# Whether this invocation IS the blocking scan decision (pre-tool-use / pre-file-write) — the same
# substring match used below in the cx-unresolved branch, kept in lockstep with it. Advisory
# lifecycle hooks (stop/idle/prompt) are not security decisions and stay on the plain exec fast path.
case "${1:-} ${2:-}" in
    *pre-tool-use* | *pre-file-write*) _CXRUN_SCAN=1 ;;
    *)                                 _CXRUN_SCAN=0 ;;
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
        _CXRUN_INPUT=$(cat)
        _CXRUN_OUTPUT=$(printf '%s' "$_CXRUN_INPUT" | "$CX_RESOLVED" "$@")
        _CXRUN_STATUS=$?

        # decision + WHY: either signal cx may use — a literal deny in its JSON (a genuine,
        # well-formed finding: "vulnerability_detected"), or a bare exit 2 with no such JSON (the
        # same pair this script's OWN fail-closed branch below emits together for its cx-absent
        # deny — an unexpected/error condition, not necessarily a real finding: "error_during_block").
        case "$_CXRUN_OUTPUT" in
            *'"permissionDecision":"deny"'*)
                _CXRUN_DECISION=deny
                _CXRUN_REASON=vulnerability_detected
                ;;
            *)
                if [ "$_CXRUN_STATUS" -eq 2 ]; then
                    _CXRUN_DECISION=deny
                    _CXRUN_REASON=error_during_block
                else
                    _CXRUN_DECISION=allow
                    _CXRUN_REASON=no_issues_found
                fi
                ;;
        esac
        _CXRUN_TOOL=$(printf '%s' "$_CXRUN_INPUT" | sed -n 's/.*"tool_name" *: *"\([A-Za-z0-9_.:-]*\)".*/\1/p' | head -1)

        # Best-effort log — never let a missing/slow python or a logging failure affect the relay.
        _CXRUN_DIR=$(cd "$(dirname "$0")" && pwd)
        for _CXRUN_PY in python3 python; do
            command -v "$_CXRUN_PY" >/dev/null 2>&1 || continue
            # `break` only on a real success: on Windows, "python3" can resolve to the Microsoft
            # Store's App Execution Alias stub, which is ON PATH but exits non-zero without running
            # anything (no Python actually installed under that name) — falling through to "python"
            # in that case is what makes this work on such machines.
            "$_CXRUN_PY" "$_CXRUN_DIR/cx_log.py" scan_decision \
                "decision=$_CXRUN_DECISION" "tool_name=$_CXRUN_TOOL" "reason_code=$_CXRUN_REASON" \
                >/dev/null 2>&1 && break
        done

        printf '%s\n' "$_CXRUN_OUTPUT"
        exit "$_CXRUN_STATUS"
    fi
    if [ "$_CXRUN_MCP" = 1 ]; then
        _CXRUN_DIR=$(cd "$(dirname "$0")" && pwd)
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

        # Best-effort log — same python3/python fallback loop as the scan_decision log above; never
        # let a missing/slow python or a logging failure affect the connection outcome. `tier`
        # records which resolution tier supplied $CX_RESOLVED, so the log can explain (via
        # cx_log.py's message synthesis) why a CX_BINARY-pinned denial won't self-heal from a
        # bootstrap upgrade — see the matching stderr note below.
        for _CXRUN_PY in python3 python; do
            command -v "$_CXRUN_PY" >/dev/null 2>&1 || continue
            "$_CXRUN_PY" "$_CXRUN_DIR/cx_log.py" mcp_connect \
                "result=$_CXRUN_MCP_RESULT" "reason_code=$_CXRUN_MCP_REASON" \
                "version_have=$_CXRUN_MCP_HAVE" "version_min=$_CXRUN_MCP_MIN" \
                "tier=$_CX_RESOLVED_TIER" \
                >/dev/null 2>&1 && break
        done

        if [ "$_CXRUN_MCP_RESULT" = denied ]; then
            # Refuse to exec a subcommand this build can't run — that is what corrupts the stdio
            # transport into today's opaque -32000. stdout stays untouched (no partial MCP framing);
            # the reason goes to stderr (captured in Claude Code's own MCP log, per references/mcp.md)
            # AND to checkmarx-devassist.jsonl above, so a connect failure always has an exact cause on disk.
            case "$_CXRUN_MCP_REASON" in
                below)
                    printf 'checkmarx-devassist: Checkmarx MCP bridge unavailable: cx v%s is below the required v%s. Run /checkmarx-cli-setup to upgrade.\n' \
                        "$_CXRUN_MCP_HAVE" "$_CXRUN_MCP_MIN" >&2
                    ;;
                incapable)
                    printf "checkmarx-devassist: Checkmarx MCP bridge unavailable: cx v%s is missing the 'mcp bridge' subcommand (capability-incomplete build). Run /checkmarx-cli-setup.\\n" \
                        "$_CXRUN_MCP_HAVE" >&2
                    ;;
                unrunnable)
                    printf 'checkmarx-devassist: Checkmarx MCP bridge unavailable: cx version did not run or returned no usable version. Run /checkmarx-cli-setup.\n' >&2
                    ;;
                *)
                    printf 'checkmarx-devassist: Checkmarx MCP bridge unavailable (%s). Run /checkmarx-cli-setup.\n' "$_CXRUN_MCP_REASON" >&2
                    ;;
            esac
            # CX_BINARY takes priority over the canonical store in this exact resolution — re-running
            # the bootstrap upgrade only writes the canonical store, so it would silently NOT fix a
            # CX_BINARY-pinned denial. Say so explicitly instead of leaving a confusing "I upgraded
            # but it's still broken" loop.
            if [ "$_CX_RESOLVED_TIER" = "binary" ]; then
                printf 'checkmarx-devassist: Note: CX_BINARY is pinned to this exact binary and takes priority over the canonical store, so running the bootstrap will NOT fix this. Unset CX_BINARY, replace the binary at that exact path, or repoint CX_BINARY at the canonical store after upgrading.\n' >&2
            fi
            exit 1
        fi
        # ok / dev / guard-unavailable — fall through to the plain exec below.
    fi
    exec "$CX_RESOLVED" "$@"
fi

# --- cx could not be resolved anywhere: pick a fail mode that never silently opens the scan path. ---
case "${1:-} ${2:-}" in
    *pre-tool-use* | *pre-file-write*)
        # Bootstrap carve-out: the sanctioned self-install must pass even though cx is absent — that
        # is the whole POINT of running it. Stage-1 (cx_check) already allows this exact command; but
        # every hook in a matcher must allow, so without the SAME carve-out HERE this stage's deny
        # would override that allow and the documented `bash "<bootstrap>" install` recovery could
        # never run through the Bash tool (the deadlock). Read stdin ONLY now — safe because cx was
        # never exec'd (resolution failed above), so nothing downstream consumes it. The shared matcher
        # (mirroring cx_check.sh / cx_check.py) keeps the two shell stages from drifting.
        _CXRUN_INPUT=$(cat)
        _CXRUN_DIR=$(cd "$(dirname "$0")" && pwd)
        if [ -n "$_CXRUN_DIR" ] && [ -f "$_CXRUN_DIR/_cx_bootstrap_match.sh" ]; then
            . "$_CXRUN_DIR/_cx_bootstrap_match.sh"
            cx_is_bootstrap_command "$_CXRUN_INPUT" "$_CXRUN_DIR" && exit 0
        fi
        # Detect Copilot CLI context from the subcommand name (contains "copilot-cli").
        # Copilot CLI reads a flat JSON with permissionDecision at the top level; Claude Code
        # reads the nested hookSpecificOutput wrapper. Emit the correct shape per client.
        case "$*" in
            *copilot-cli*)
                printf '{"permissionDecision":"deny","permissionDecisionReason":"The Checkmarx security scanner could not run: cx CLI not found (not in CX_BINARY, canonical store, or PATH). This operation is BLOCKED fail-closed. Run /checkmarx-cli-setup to install cx, then retry."}\n'
                ;;
            *)
                cat <<'JSON'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"The Checkmarx security scanner could not run: the cx CLI could not be resolved (not found via CX_BINARY, the canonical store, or PATH). This operation is BLOCKED fail-closed.","additionalContext":"Run /checkmarx-cli-setup to install and authenticate the cx CLI, then retry. The gate resolves cx from the canonical store (%LOCALAPPDATA%\\Checkmarx\\cx\\cx.exe on Windows, ~/.checkmarx/bin/cx on Unix) by absolute path — this deny means it could not be found there or on PATH. All agent actions remain blocked until cx is available."}}
JSON
                ;;
        esac
        exit 0
        ;;
    *stop* | *idle* | *prompt*)
        # Advisory lifecycle hook (stop / idle / user-prompt-submit) — stay non-blocking when cx is
        # genuinely absent; blocking a prompt-submit here would deadlock the user before install.
        exit 0
        ;;
    *)
        if [ "$_CXRUN_MCP" = 1 ]; then
            _CXRUN_DIR=$(cd "$(dirname "$0")" && pwd)
            for _CXRUN_PY in python3 python; do
                command -v "$_CXRUN_PY" >/dev/null 2>&1 || continue
                "$_CXRUN_PY" "$_CXRUN_DIR/cx_log.py" mcp_connect \
                    "result=denied" "reason_code=cx_absent" >/dev/null 2>&1 && break
            done
        fi
        printf 'checkmarx-devassist: cx CLI not found (looked at CX_BINARY, the canonical store, and PATH). Run /checkmarx-cli-setup to install it.\n' >&2
        exit 1
        ;;
esac
