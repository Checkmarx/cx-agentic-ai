#!/bin/sh
# Shared trusted-bootstrap/auth/setup command matcher for the SHELL stages of the gate.
#
# PREFERRED PATH — delegate to hooks/cx_check.py `--match-trusted-setup` (see
# cx_is_trusted_setup_command at the bottom of this file). That is the ONE authoritative
# implementation: it understands every shell's spelling of the same command (PowerShell's `&` call
# operator and single-quoted paths, `%VAR%` / `$env:VAR` / `$VAR` / `~` references, cmd's doubled
# quotes, bash/sh/powershell/cmd `-c` wrappers) because it shares hooks/cx_shell.py with the gate
# itself. Delegating instead of re-implementing is what guarantees stage-1 (cx_check) and stage-2
# (cx_run) can never disagree about the same command — a disagreement BLOCKS the tool call, since
# every hook in a Cursor matcher must allow.
#
# The POSIX-sh matchers below remain ONLY as the no-Python fallback (and are deliberately coarser).
# On a machine with no Python 3, cx_check.py cannot run at all, so the gate denies everything anyway
# — the one thing that still has to work there is allowing the bundled bootstrap so the developer can
# recover, which is exactly what these cover.
#
# Legacy fallback recognizes:
#   1. bash "<bundled scripts/cx-bootstrap.sh>" install|upgrade   (the original, narrowest shape)
#   2. bash|sh "<any *.sh file inside this plugin's scripts/ or hooks/ directory>" <any args>
# so the plugin's self-install AND its other bundled helper scripts (cx-asset-resolver.sh,
# cx-path-probe.sh, cx-mcp-guard.sh, …) can run while the gate is otherwise blocking. These are
# first-party, SHIPPED content — not agent/user-authored — so an attacker able to alter them has
# already achieved local code execution the gate cannot prevent anyway; gating their execution buys
# no real security and only breaks legitimate cx-cli-setup workflows.
#
# Used by BOTH:
#   - cx_check.sh   (stage-1, ALWAYS — before the Python gate, so stage-1 and stage-2 cannot
#                    disagree on the same input), and
#   - cx_run.sh     (stage-2, its cx-ABSENT deny branch — ALWAYS, regardless of Python — the case
#                    that caused the original bootstrap deadlock),
# so the two shell stages cannot drift into disagreeing about what's allowed (one allowing, the
# other denying → the tool call blocked because every hook must allow).
#
# Coarse ON PURPOSE — the AUTHORITATIVE matcher is hooks/cx_check.py `_is_bootstrap_command` /
# `_is_plugin_script_command`, run whenever a Python 3 interpreter is present (the normal case).
# Keep this in lockstep with them. Still deliberately narrow on ONE axis: Shell tool only, NO shell
# chaining/substitution/redirects anywhere in the command — only WHICH script + arguments are now
# broader. Anything that doesn't match returns 1 so the caller falls through to its fail-CLOSED
# deny. Source this file; do not execute it. POSIX sh (no bashisms) — mirrors the launchers that
# source it.

# _cxbm_extract_command_py <hook_json_file>
# Parse the shell command from a hook JSON FILE (never a shell variable holding JSON).
# Reading via stdin redirect avoids Git Bash expanding `$null` / `$env:…` inside the JSON when the
# old `printf '%s' "$INPUT"` path was used — that corruption broke every PowerShell OAuth
# `1>$null` auth-login line in cx_check.sh while cx_run.sh still allowed via the native scanner.
_cxbm_extract_command_py() {
    _cxbm_json_f="$1"
    [ -r "$_cxbm_json_f" ] || return 1
    _cxbm_py_snippet='
import json, sys
raw = sys.stdin.buffer.read()
d = None
for enc in ("utf-8-sig", "utf-16"):
    try:
        d = json.loads(raw.decode(enc))
        break
    except (UnicodeDecodeError, LookupError, ValueError, TypeError):
        continue
if not isinstance(d, dict):
    sys.exit(1)
cmd = d.get("command")
if isinstance(cmd, str) and cmd.strip():
    sys.stdout.write(cmd)
    sys.exit(0)
ti = d.get("tool_input")
if isinstance(ti, dict):
    cmd = ti.get("command")
    if isinstance(cmd, str) and cmd.strip():
        sys.stdout.write(cmd)
        sys.exit(0)
sys.exit(1)
'
    for _cxbm_py in python3 python; do
        if command -v "$_cxbm_py" >/dev/null 2>&1; then
            _cxbm_out=$("$_cxbm_py" -c "$_cxbm_py_snippet" < "$_cxbm_json_f" 2>/dev/null) || true
            if [ -n "$_cxbm_out" ]; then
                printf '%s' "$_cxbm_out"
                return 0
            fi
        fi
    done
    if command -v py >/dev/null 2>&1; then
        _cxbm_out=$(py -3 -c "$_cxbm_py_snippet" < "$_cxbm_json_f" 2>/dev/null) || true
        if [ -n "$_cxbm_out" ]; then
            printf '%s' "$_cxbm_out"
            return 0
        fi
    fi
    return 1
}

# _cxbm_extract_command_to_file <hook_json_file> <command_out_file>
# Write the extracted command to <command_out_file> without ever echoing it through a double-quoted
# shell variable (which would expand `$null` in `1>$null`).
_cxbm_extract_command_to_file() {
    _cxbm_json_f="$1"
    _cxbm_cmd_f="$2"
    [ -r "$_cxbm_json_f" ] || return 1
    _cxbm_py_snippet='
import json, sys
raw = sys.stdin.buffer.read()
d = None
for enc in ("utf-8-sig", "utf-16"):
    try:
        d = json.loads(raw.decode(enc))
        break
    except (UnicodeDecodeError, LookupError, ValueError, TypeError):
        continue
if not isinstance(d, dict):
    sys.exit(1)
cmd = d.get("command")
if not (isinstance(cmd, str) and cmd.strip()):
    ti = d.get("tool_input")
    if isinstance(ti, dict):
        cmd = ti.get("command")
if not (isinstance(cmd, str) and cmd.strip()):
    sys.exit(1)
with open(sys.argv[1], "w", encoding="utf-8", newline="") as out:
    out.write(cmd)
'
    for _cxbm_py in python3 python; do
        if command -v "$_cxbm_py" >/dev/null 2>&1 && \
           "$_cxbm_py" -c "$_cxbm_py_snippet" "$_cxbm_cmd_f" < "$_cxbm_json_f" 2>/dev/null; then
            [ -s "$_cxbm_cmd_f" ] && return 0
        fi
    done
    if command -v py >/dev/null 2>&1 && \
       py -3 -c "$_cxbm_py_snippet" "$_cxbm_cmd_f" < "$_cxbm_json_f" 2>/dev/null; then
        [ -s "$_cxbm_cmd_f" ] && return 0
    fi
    return 1
}

# Legacy name — $1 must be a readable hook JSON file path (not inline JSON text).
_cxbm_extract_command() {
    _cxbm_extract_command_py "$1"
}

# _cxbm_normalize_path <path>
# Case-insensitive, slash-normalized absolute path for comparison on Windows (C: vs c:, \ vs /).
_cxbm_normalize_path() {
    _cxbm_p="$1"
    [ -n "$_cxbm_p" ] || return 1
    # Normalize Windows backslashes before cygpath/Git-Bash aliasing — `C:\Users\…` from PowerShell
    # JSON must not reach bare `[ -f ]` or cygpath -u (they fail on unconverted backslash paths).
    _cxbm_p=$(printf '%s' "$_cxbm_p" | tr '\\' '/')
    case "$_cxbm_p" in
        /[A-Za-z]/* | /[A-Za-z])
            _cxbm_drive=$(printf '%s' "$_cxbm_p" | cut -c2 | tr '[:lower:]' '[:upper:]')
            _cxbm_rest=$(printf '%s' "$_cxbm_p" | cut -c3-)
            _cxbm_p="${_cxbm_drive}:${_cxbm_rest}"
            ;;
    esac
    if command -v cygpath >/dev/null 2>&1; then
        _cxbm_m=$(cygpath -m "$_cxbm_p" 2>/dev/null) || _cxbm_m=""
        if [ -n "$_cxbm_m" ]; then
            _cxbm_p="$_cxbm_m"
        fi
    fi
    printf '%s' "$_cxbm_p" | tr '\\' '/' | tr '[:upper:]' '[:lower:]'
}

# _cxbm_is_existing_bootstrap_script <path>
# True when <path> is a real …/scripts/cx-bootstrap.sh on disk (deny-message copy-paste safety net).
_cxbm_is_existing_bootstrap_script() {
    _cxbm_p="$1"
    [ -n "$_cxbm_p" ] || return 1
    [ -f "$_cxbm_p" ] || return 1
    case "$_cxbm_p" in
        */scripts/cx-bootstrap.sh | */scripts/CX-BOOTSTRAP.SH) return 0 ;;
    esac
    _cxbm_base=$(basename "$_cxbm_p" 2>/dev/null) || return 1
    _cxbm_parent=$(basename "$(dirname "$_cxbm_p")" 2>/dev/null) || return 1
    case "$_cxbm_base" in
        cx-bootstrap.sh | CX-BOOTSTRAP.SH) ;;
        *) return 1 ;;
    esac
    case "$_cxbm_parent" in
        scripts | SCRIPTS) return 0 ;;
    esac
    return 1
}

# Pull the script path out of `bash "/path" …` / `bash '/path' …` / `bash /path …` — mirrors
# cx_check.py's _PLUGIN_SCRIPT_RE (double-, single-, and bare-quoted paths).
_cxbm_extract_script_path() {
    _cxbm_cmd="$1"
    _cxbm_path=$(printf '%s' "$_cxbm_cmd" | sed -n 's/^[[:space:]]*\(bash\|sh\)[[:space:]]*"\([^"]*\)".*/\2/p')
    if [ -n "$_cxbm_path" ]; then
        printf '%s' "$_cxbm_path"
        return 0
    fi
    _cxbm_path=$(printf '%s' "$_cxbm_cmd" | sed -n "s/^[[:space:]]*\\(bash\\|sh\\)[[:space:]]*'\\([^']*\\)'.*/\\2/p")
    if [ -n "$_cxbm_path" ]; then
        printf '%s' "$_cxbm_path"
        return 0
    fi
    _cxbm_path=$(printf '%s' "$_cxbm_cmd" | sed -n 's/^[[:space:]]*\(bash\|sh\)[[:space:]]\+\([^[:space:]]*\).*/\2/p')
    [ -n "$_cxbm_path" ] || return 1
    printf '%s' "$_cxbm_path"
}

# _cxbm_legacy_substring_match <normalized_json> <hooks_dir>
# Original tr-based substring matcher — kept as a no-Python fallback for forward-slash paths only.
_cxbm_legacy_substring_match() {
    _cxbm_norm="$1"
    _cxbm_hooks_dir="$2"
    _cxbm_scripts_dir=$(cd "${_cxbm_hooks_dir}/../scripts" 2>/dev/null && pwd) || return 1
    _cxbm_have_cygpath=0
    command -v cygpath >/dev/null 2>&1 && _cxbm_have_cygpath=1
    for _cxbm_dir in "$_cxbm_scripts_dir" "$_cxbm_hooks_dir"; do
        for _cxbm_f in "$_cxbm_dir"/*.sh; do
            [ -f "$_cxbm_f" ] || continue
            _cxbm_win=""
            if [ "$_cxbm_have_cygpath" = 1 ]; then
                _cxbm_win=$(cygpath -m "$_cxbm_f" 2>/dev/null)
            fi
            for _cxbm_bp in "$_cxbm_f" "$_cxbm_win"; do
                [ -n "$_cxbm_bp" ] || continue
                case "$_cxbm_norm" in
                    *'"command":"bash /"'"$_cxbm_bp"'/"'*  | \
                    *'"command": "bash /"'"$_cxbm_bp"'/"'* | \
                    *'"command":"sh /"'"$_cxbm_bp"'/"'*    | \
                    *'"command": "sh /"'"$_cxbm_bp"'/"'*)
                        return 0 ;;
                esac
            done
        done
    done
    return 1
}

# _cxbm_canonical_cx_path
# Print the expected canonical per-OS cx path (mirrors cx_check.py _canonical_cx_path).
_cxbm_canonical_cx_path() {
    case "$(uname -s 2>/dev/null)" in
        MINGW*|MSYS*|CYGWIN*)
            if [ -n "${LOCALAPPDATA:-}" ]; then
                printf '%s' "$LOCALAPPDATA/Checkmarx/cx/cx.exe"
            elif [ -n "${USERPROFILE:-}" ]; then
                printf '%s' "$USERPROFILE/AppData/Local/Checkmarx/cx/cx.exe"
            else
                printf '%s' "${HOME:-}/AppData/Local/Checkmarx/cx/cx.exe"
            fi
            ;;
        *)
            printf '%s' "${HOME:-}/.checkmarx/bin/cx"
            ;;
    esac
}

# _cxbm_extract_cx_exe_path <bare_command>
# Pull the cx path from `"<path>" auth|configure|hooks check-auth …` (quoted), `'…'` (single-quoted),
# or `<path> auth|…` (unquoted — only when <path> has no spaces). Not bare `cx auth`.
_cxbm_extract_cx_exe_path() {
    _cxbm_cmd="$1"
    case "$_cxbm_cmd" in
        cx\ auth*|cx\ configure*|cx\ hooks\ check-auth*) return 1 ;;
    esac
    _cxbm_exe=$(printf '%s' "$_cxbm_cmd" | sed -n 's/^[[:space:]]*"\([^"]*\)"[[:space:]]\+\(auth\|configure\|hooks check-auth\).*/\1/p')
    if [ -z "$_cxbm_exe" ]; then
        _cxbm_exe=$(printf '%s' "$_cxbm_cmd" | sed -n "s/^[[:space:]]*'\\([^']*\\)'[[:space:]]\\+\\(auth\\|configure\\|hooks check-auth\\).*/\\1/p")
    fi
    if [ -z "$_cxbm_exe" ]; then
        _cxbm_exe=$(printf '%s' "$_cxbm_cmd" | sed -n 's/^[[:space:]]*\([A-Za-z]:[^[:space:]"]*\|\/[^[:space:]"]*\|~[^[:space:]"]*\)[[:space:]]\+\(auth\|configure\|hooks check-auth\).*/\1/p')
    fi
    [ -n "$_cxbm_exe" ] || return 1
    printf '%s' "$_cxbm_exe"
}

# _cxbm_is_shell_event <hook_json_file>
# True for beforeShellExecution, preToolUse Shell, and related payloads. Operates on a FILE so
# `$null` / `$env:…` inside the JSON are never expanded by the shell.
_cxbm_is_shell_event() {
    _cxbm_f="$1"
    [ -r "$_cxbm_f" ] || return 1
    grep -qE '"tool_name"[[:space:]]*:[[:space:]]*"Shell"' "$_cxbm_f" && return 0
    grep -qE '"hook_event_name"[[:space:]]*:[[:space:]]*"beforeShellExecution"' "$_cxbm_f" && return 0
    grep -qE '"hook_event_name"[[:space:]]*:[[:space:]]*"beforeMCPExecution"' "$_cxbm_f" && return 1
    grep -q '"command"' "$_cxbm_f" || return 1
    grep -qE '"cwd"|"sandbox"' "$_cxbm_f" && return 0
    return 1
}

# _cxbm_is_existing_cx_exe <raw_path>
# True when <raw_path> is an absolute, existing cx / cx.exe (deny-message / PowerShell path safety net).
_cxbm_is_existing_cx_exe() {
    _cxbm_p="$1"
    [ -n "$_cxbm_p" ] || return 1
    case "$_cxbm_p" in
        [A-Za-z]:*) ;;
        /*) ;;
        *) return 1 ;;
    esac
    _cxbm_base=$(basename "$_cxbm_p" 2>/dev/null) || return 1
    case "$_cxbm_base" in
        cx | cx.exe | CX | CX.EXE) ;;
        *) return 1 ;;
    esac
    # Git Bash: `C:\Users\…\cx.exe` fails bare `[ -f ]` — convert to a Unix path first.
    if command -v cygpath >/dev/null 2>&1; then
        _cxbm_fwd=$(printf '%s' "$_cxbm_p" | tr '\\' '/')
        _cxbm_unix=$(cygpath -u "$_cxbm_fwd" 2>/dev/null) || _cxbm_unix=""
        if [ -n "$_cxbm_unix" ] && [ -f "$_cxbm_unix" ]; then
            return 0
        fi
    fi
    [ -f "$_cxbm_p" ] && return 0
    return 1
}

# _cxbm_cx_path_is_trusted <normalized_path> [<raw_path>]
# True when the path matches the canonical store, CX_BINARY pin, or an existing absolute cx binary.
_cxbm_cx_path_is_trusted() {
    _cxbm_norm="$1"
    _cxbm_raw="${2:-}"
    [ -n "$_cxbm_norm" ] || return 1
    _cxbm_canon=$(_cxbm_normalize_path "$(_cxbm_canonical_cx_path)") || return 1
    [ "$_cxbm_norm" = "$_cxbm_canon" ] && return 0
    if [ -n "${CX_BINARY:-}" ]; then
        _cxbm_pin=$(_cxbm_normalize_path "$CX_BINARY") || return 1
        [ "$_cxbm_norm" = "$_cxbm_pin" ] && return 0
    fi
    if [ -n "$_cxbm_raw" ]; then
        _cxbm_is_existing_cx_exe "$_cxbm_raw" && return 0
    fi
    return 1
}

# _cxbm_prep_carveout_cmd_file <command_in_file> <command_out_file>
# Unwrap interpreter wrappers and strip a leading PowerShell `&` — file-to-file so `$null` in
# `1>$null` is never expanded by the shell.
_cxbm_prep_carveout_cmd_file() {
    _cxbm_in_f="$1"
    _cxbm_out_f="$2"
    [ -r "$_cxbm_in_f" ] || return 1
    _cxbm_py_snippet='
import re, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as f:
    cmd = f.read()
bash_dq = re.compile(r"^(bash|sh)\s+-c\s+\"(.*)\"$", re.S)
bash_sq = re.compile(r"^(bash|sh)\s+-c\s+\x27(.*)\x27$", re.S)
ps_dq = re.compile(r"^(?:powershell|pwsh)(?:\.exe)?\b.*?-(?:Command|c)\s+\"(.*)\"$", re.I | re.S)
cmd_c = re.compile(r"^cmd(?:\.exe)?\b.*?/c\s+\"(.*)\"$", re.I | re.S)
for _ in range(3):
    m = bash_dq.match(cmd)
    if m and "\"" not in m.group(1).replace("\\\\\"", ""):
        cmd = m.group(1).replace("\\\\\"", "\"")
        continue
    m = bash_sq.match(cmd)
    if m and "\x27" not in m.group(1):
        cmd = m.group(1)
        continue
    m = ps_dq.match(cmd)
    if m:
        inner = m.group(1).replace("\\\\\"", "\"")
        cmd = re.sub(r"^\s*&\s+", "", inner)
        continue
    m = cmd_c.match(cmd)
    if m:
        cmd = m.group(1)
        continue
    break
cmd = re.sub(r"^\s*&\s+", "", cmd)
with open(dst, "w", encoding="utf-8", newline="") as f:
    f.write(cmd)
'
    for _cxbm_py in python3 python; do
        if command -v "$_cxbm_py" >/dev/null 2>&1 && \
           "$_cxbm_py" -c "$_cxbm_py_snippet" "$_cxbm_in_f" "$_cxbm_out_f" 2>/dev/null; then
            [ -s "$_cxbm_out_f" ] && return 0
        fi
    done
    if command -v py >/dev/null 2>&1 && \
       py -3 -c "$_cxbm_py_snippet" "$_cxbm_in_f" "$_cxbm_out_f" 2>/dev/null; then
        [ -s "$_cxbm_out_f" ] && return 0
    fi
    return 1
}

# _cxbm_prep_carveout_cmd <command>
# Legacy in-memory prep — only safe when <command> contains no unquoted `$` tokens.
_cxbm_prep_carveout_cmd() {
    _cxbm_cmd="$1"
    _cxbm_unwrapped=$(_cxbm_unwrap_bash_c "$_cxbm_cmd") && _cxbm_cmd="$_cxbm_unwrapped"
    _cxbm_unwrapped=$(_cxbm_unwrap_powershell "$_cxbm_cmd") && _cxbm_cmd="$_cxbm_unwrapped"
    _cxbm_unwrapped=$(_cxbm_unwrap_cmd_c "$_cxbm_cmd") && _cxbm_cmd="$_cxbm_unwrapped"
    _cxbm_strip_call_operator "$_cxbm_cmd"
}

# _cxbm_match_auth_on_cmd_file <bare_command_file>
# POSIX fallback auth/configure carve-out matcher — reads the command from a file (grep/sed) so
# PowerShell `$null` / `$env:…` tokens are not expanded by the shell.
_cxbm_match_auth_on_cmd_file() {
    _cxbm_f="$1"
    [ -r "$_cxbm_f" ] || return 1
    grep -qF ';' "$_cxbm_f" && return 1
    grep -qF '|' "$_cxbm_f" && return 1
    grep -qF '$(' "$_cxbm_f" && return 1
    grep -qF '`' "$_cxbm_f" && return 1
    grep -qF '^' "$_cxbm_f" && return 1
    grep -qF '%' "$_cxbm_f" && return 1
    grep -qF '&' "$_cxbm_f" && return 1
    grep -qE 'auth|configure' "$_cxbm_f" || return 1
    if grep -qE '^[[:space:]]*cx[[:space:]]+(auth|configure|hooks[[:space:]]+check-auth)' "$_cxbm_f"; then
        return 0
    fi
    _cxbm_exe=$(sed -n 's/^[[:space:]]*"\([^"]*\)"[[:space:]]\+\(auth\|configure\|hooks check-auth\).*/\1/p' "$_cxbm_f")
    if [ -z "$_cxbm_exe" ]; then
        _cxbm_exe=$(sed -n "s/^[[:space:]]*'\\([^']*\\)'[[:space:]]\\+\\(auth\\|configure\\|hooks check-auth\\).*/\\1/p" "$_cxbm_f")
    fi
    if [ -z "$_cxbm_exe" ]; then
        _cxbm_exe=$(sed -n 's/^[[:space:]]*\([A-Za-z]:[^[:space:]"]*\|\/[^[:space:]"]*\|~[^[:space:]"]*\)[[:space:]]\+\(auth\|configure\|hooks check-auth\).*/\1/p' "$_cxbm_f")
    fi
    [ -n "$_cxbm_exe" ] || return 1
    _cxbm_exe_norm=$(_cxbm_normalize_path "$_cxbm_exe") || return 1
    _cxbm_cx_path_is_trusted "$_cxbm_exe_norm" "$_cxbm_exe"
}

# _cxbm_unwrap_bash_c <command>
# If <command> is exactly `bash -c '<inner>'` / `sh -c '<inner>'` (single-quoted) or
# `bash -c "<inner>"` / `sh -c "<inner>"` (double-quoted), print <inner> and return 0. An embedded
# quote of the same kind that opened the wrapper ends the shell string early, so refuse rather than
# guess. This is the shape Cursor's beforeShellExecution sends whenever the agent's command needs
# shell interpretation (e.g. the oauth.md-mandated `1>/dev/null` redirect on cx auth/configure
# commands) — without unwrapping it, the auth-recovery carve-out below never matches a real Cursor
# auth-login command, which is the cx_run.sh-allows/cx_check.sh-denies deadlock this function exists
# to prevent. Mirrors hooks/cx_shell.py's _UNWRAPPERS bash/sh -c patterns.
_cxbm_unwrap_bash_c() {
    _cxbm_wrapped="$1"
    case "$_cxbm_wrapped" in
        "bash -c '"*"'") _cxbm_prefix="bash -c '" ; _cxbm_quote="'" ;;
        "sh -c '"*"'")   _cxbm_prefix="sh -c '"   ; _cxbm_quote="'" ;;
        'bash -c "'*'"') _cxbm_prefix='bash -c "' ; _cxbm_quote='"' ;;
        'sh -c "'*'"')   _cxbm_prefix='sh -c "'   ; _cxbm_quote='"' ;;
        *) return 1 ;;
    esac
    _cxbm_inner="${_cxbm_wrapped#"$_cxbm_prefix"}"
    _cxbm_inner="${_cxbm_inner%"$_cxbm_quote"}"
    case "$_cxbm_inner" in
        *"$_cxbm_quote"*) return 1 ;;
    esac
    printf '%s' "$_cxbm_inner"
}

# _cxbm_unwrap_powershell <command>
# Cursor on Windows (default shell: PowerShell) wraps Shell-tool commands as
# `powershell[.exe] [-NoProfile …] -Command "& \"<cx>\" auth …"` — the outer `&` is PowerShell's
# call operator, NOT shell chaining. Without unwrapping to the inner cx auth/configure command first,
# the auth-recovery carve-out rejects the whole string on `&` and blocks the very login that fixes auth.
#
# The prefix before `-Command`/`-c` is matched LAZILY (`.*?`), not as a run of bare `-flag` tokens:
# real PowerShell switches like `-ExecutionPolicy Bypass` / `-WindowStyle Hidden` take a SEPARATE
# value token with no leading `-`, and a bare-flags-only pattern fails to unwrap that — leaving the
# WHOLE wrapped string unrecognized and every carve-out denied. Mirrors cx_shell.py's _UNWRAPPERS.
_cxbm_unwrap_powershell() {
    _cxbm_wrapped="$1"
    _cxbm_py_snippet='
import re, sys
cmd = sys.stdin.read()
dq = re.compile(r"^(?:powershell(?:\\.exe)?|pwsh(?:\\.exe)?)\\b.*?-(?:Command|c)\\s+\"(?P<inner>.*)\"$", re.I | re.S)
sq = re.compile(r"^(?:powershell(?:\\.exe)?|pwsh(?:\\.exe)?)\\b.*?-(?:Command|c)\\s+" + chr(39) + r"(?P<inner>.*)" + chr(39) + r"$", re.I | re.S)
for pat, reject in ((dq, None), (sq, chr(39))):
    m = pat.match(cmd)
    if not m:
        continue
    inner = m.group("inner").replace("\\\\\"", "\"")
    if reject and reject in inner:
        sys.exit(1)
    inner = re.sub(r"^\\s*&\\s+", "", inner)
    sys.stdout.write(inner)
    sys.exit(0)
sys.exit(1)
'
    for _cxbm_py in python3 python; do
        if command -v "$_cxbm_py" >/dev/null 2>&1; then
            _cxbm_out=$(printf '%s' "$_cxbm_wrapped" | "$_cxbm_py" -c "$_cxbm_py_snippet" 2>/dev/null) || true
            if [ -n "$_cxbm_out" ]; then
                printf '%s' "$_cxbm_out"
                return 0
            fi
        fi
    done
    if command -v py >/dev/null 2>&1; then
        _cxbm_out=$(printf '%s' "$_cxbm_wrapped" | py -3 -c "$_cxbm_py_snippet" 2>/dev/null) || true
        if [ -n "$_cxbm_out" ]; then
            printf '%s' "$_cxbm_out"
            return 0
        fi
    fi
    return 1
}

# _cxbm_unwrap_cmd_c <command>
# If <command> is exactly `cmd /c "<inner>"` / `cmd.exe /c "<inner>"` — cmd.exe's own doubled-quote
# wrapping, e.g. the ""<path>" auth … 1>NUL" shape cmd emits for a quoted absolute path — print
# <inner>. cmd's own quoting convention allows <inner> to start with a literal quote, so (unlike
# _cxbm_unwrap_bash_c's single-quote wrapper) no embedded-quote rejection is needed: any
# chaining/redirect risk in <inner> is still caught by the metacharacter check that runs after
# unwrapping. Mirrors cx_check.py's _unwrap_cmd_c.
_cxbm_unwrap_cmd_c() {
    _cxbm_wrapped="$1"
    case "$_cxbm_wrapped" in
        'cmd /c "'*'"')     _cxbm_prefix='cmd /c "' ;;
        'cmd.exe /c "'*'"') _cxbm_prefix='cmd.exe /c "' ;;
        *) return 1 ;;
    esac
    _cxbm_inner="${_cxbm_wrapped#"$_cxbm_prefix"}"
    _cxbm_inner="${_cxbm_inner%\"}"
    printf '%s' "$_cxbm_inner"
}

# _cxbm_strip_call_operator <command>
# Strip a LEADING PowerShell call operator (`& `) from a bare (unwrapped) command — required
# PowerShell syntax to invoke a quoted/absolute path directly, not shell chaining. Only the
# leading occurrence is stripped; a `&` anywhere else in the command is still rejected by the
# metacharacter check below. Mirrors cx_check.py's _strip_call_operator.
_cxbm_strip_call_operator() {
    case "$1" in
        "& "*) printf '%s' "${1#"& "}" ;;
        *) printf '%s' "$1" ;;
    esac
}

# cx_is_auth_recovery_command <hook_json_file> [<cx_check.py>]
# True for `"<canonical cx>" auth|configure …` or bare `cx auth|configure …` pinned to trusted cx.
# $1 must be a readable hook JSON FILE — never inline JSON in a shell variable (see header above).
cx_is_auth_recovery_command() {
    _cxbm_json_f="$1"
    _cxbm_gate="${2:-}"
    [ -r "$_cxbm_json_f" ] || return 1
    if [ -n "$_cxbm_gate" ] && [ -f "$_cxbm_gate" ] && _cxbm_py=$(_cxbm_find_python); then
        if command -v cygpath >/dev/null 2>&1; then
            _cxbm_gate=$(cygpath -w "$_cxbm_gate" 2>/dev/null) || _cxbm_gate="${2:-}"
        fi
        if command -v timeout >/dev/null 2>&1; then
            PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 \
                timeout 10 $_cxbm_py "$_cxbm_gate" --match-auth-recovery < "$_cxbm_json_f" >/dev/null 2>&1
        else
            PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 \
                $_cxbm_py "$_cxbm_gate" --match-auth-recovery < "$_cxbm_json_f" >/dev/null 2>&1
        fi
        case "$?" in
            0) return 0 ;;
        esac
    fi
    _cxbm_is_shell_event "$_cxbm_json_f" || return 1
    _cxbm_cmd_f="${_cxbm_json_f}.cxcmd.$$"
    _cxbm_prep_f="${_cxbm_json_f}.cxprep.$$"
    _cxbm_extract_command_to_file "$_cxbm_json_f" "$_cxbm_cmd_f" || return 1
    if ! _cxbm_prep_carveout_cmd_file "$_cxbm_cmd_f" "$_cxbm_prep_f"; then
        rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"
        return 1
    fi
    rm -f "$_cxbm_cmd_f"
    _cxbm_match_auth_on_cmd_file "$_cxbm_prep_f"
    _cxbm_rc=$?
    rm -f "$_cxbm_prep_f"
    return "$_cxbm_rc"
}

# cx_is_ignore_vulnerability_command <hook_json_file> [<cx_check.py>]
# True for `"<canonical cx>" ignore-vulnerability …` or bare `cx ignore-vulnerability …` pinned to
# trusted cx — see cx_check.py's _IGNORE_VULN_SUBCOMMAND comment for why this carve-out exists (a
# Stage-2 reliability fix, not a security-scope change: Stage 1's own auth/version/scanner-licensing
# gates still apply to this command exactly as before).
# $1 must be a readable hook JSON FILE — never inline JSON in a shell variable (see header above).
#
# PYTHON-ONLY on purpose, unlike the other matchers in this file: a real ignore-vulnerability
# command's `--data`/`--optional-flags` values legitimately contain characters (`;`, `%`, …) that
# this file's naive grep-based fallback matchers (see _cxbm_match_auth_on_cmd_file) cannot tell
# apart from actual shell chaining, because they scan the raw command text with no quoting
# awareness. cx_check.py's --match-ignore-vulnerability instead scans the command with its embedded
# argument values quote-stripped first (cx_shell.command_skeleton) — replicating that in POSIX sh
# would mean re-implementing real quote parsing here. Rather than risk a coarse fallback that is
# either too strict (never matches, no worse than today) or too loose (accepts real chaining), a
# missing Python 3 simply means this ONE optimization is unavailable: the command falls through to
# the existing default path exactly as it did before this carve-out existed — never a security
# regression, only a missed optimization on an already-rare (no working Python 3) machine.
cx_is_ignore_vulnerability_command() {
    _cxbm_json_f="$1"
    _cxbm_gate="${2:-}"
    [ -r "$_cxbm_json_f" ] || return 1
    [ -n "$_cxbm_gate" ] && [ -f "$_cxbm_gate" ] || return 1
    _cxbm_py=$(_cxbm_find_python) || return 1
    if command -v cygpath >/dev/null 2>&1; then
        _cxbm_gate=$(cygpath -w "$_cxbm_gate" 2>/dev/null) || _cxbm_gate="${2:-}"
    fi
    if command -v timeout >/dev/null 2>&1; then
        PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 \
            timeout 10 $_cxbm_py "$_cxbm_gate" --match-ignore-vulnerability < "$_cxbm_json_f" >/dev/null 2>&1
    else
        PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 \
            $_cxbm_py "$_cxbm_gate" --match-ignore-vulnerability < "$_cxbm_json_f" >/dev/null 2>&1
    fi
    [ "$?" -eq 0 ]
}

# cx_is_checkmarx_ignore_prep_command <hook_json_file> [<cx_check.py>]
# True for `.checkmarx` directory/file prep (New-Item / Set-Content / mkdir) — PYTHON-ONLY for the
# same quoting-awareness reasons as cx_is_ignore_vulnerability_command above.
cx_is_checkmarx_ignore_prep_command() {
    _cxbm_json_f="$1"
    _cxbm_gate="${2:-}"
    [ -r "$_cxbm_json_f" ] || return 1
    [ -n "$_cxbm_gate" ] && [ -f "$_cxbm_gate" ] || return 1
    _cxbm_py=$(_cxbm_find_python) || return 1
    if command -v cygpath >/dev/null 2>&1; then
        _cxbm_gate=$(cygpath -w "$_cxbm_gate" 2>/dev/null) || _cxbm_gate="${2:-}"
    fi
    if command -v timeout >/dev/null 2>&1; then
        PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 \
            timeout 10 $_cxbm_py "$_cxbm_gate" --match-checkmarx-prep < "$_cxbm_json_f" >/dev/null 2>&1
    else
        PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 \
            $_cxbm_py "$_cxbm_gate" --match-checkmarx-prep < "$_cxbm_json_f" >/dev/null 2>&1
    fi
    [ "$?" -eq 0 ]
}

# cx_is_bootstrap_command <hook_json_file> <hooks_dir>
#   $1 = path to the hook JSON file Cursor sent on stdin
#   $2 = the sourcing launcher's OWN directory (…/plugins/cx-devassist-cursor/hooks), used to resolve
#        the plugin's own scripts/ and hooks/ directories by absolute path so a foreign script
#        elsewhere on disk cannot match.
#   returns 0 (allow — it is a sanctioned plugin-owned script) or 1 (not a match → caller denies).
cx_is_bootstrap_command() {
    _cxbm_json_f="$1"
    _cxbm_hooks_dir=$(cd "${2:-}" 2>/dev/null && pwd) || return 1
    [ -n "$_cxbm_hooks_dir" ] || return 1
    [ -r "$_cxbm_json_f" ] || return 1
    _cxbm_scripts_dir=$(cd "${2:-}/../scripts" 2>/dev/null && pwd) || return 1
    [ -n "$_cxbm_scripts_dir" ] || return 1

    if grep -qE '"tool_name"[[:space:]]*:[[:space:]]*"Shell"' "$_cxbm_json_f" || \
       grep -qE '"hook_event_name"[[:space:]]*:[[:space:]]*"beforeShellExecution"' "$_cxbm_json_f"; then
        :
    elif grep -q '"command"' "$_cxbm_json_f"; then
        if grep -qE '"hook_event_name"[[:space:]]*:[[:space:]]*"beforeMCPExecution"' "$_cxbm_json_f"; then
            return 1
        fi
        grep -qE '"cwd"|"sandbox"' "$_cxbm_json_f" || return 1
    else
        return 1
    fi

    _cxbm_cmd_f="${_cxbm_json_f}.cxcmd.$$"
    _cxbm_prep_f="${_cxbm_json_f}.cxprep.$$"
    if _cxbm_extract_command_to_file "$_cxbm_json_f" "$_cxbm_cmd_f" && \
       _cxbm_prep_carveout_cmd_file "$_cxbm_cmd_f" "$_cxbm_prep_f"; then
        grep -qF ';' "$_cxbm_prep_f" && { rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"; return 1; }
        grep -qF '|' "$_cxbm_prep_f" && { rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"; return 1; }
        grep -qF '&' "$_cxbm_prep_f" && { rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"; return 1; }
        grep -qF '`' "$_cxbm_prep_f" && { rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"; return 1; }
        grep -qF '$(' "$_cxbm_prep_f" && { rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"; return 1; }
        grep -qF '<' "$_cxbm_prep_f" && { rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"; return 1; }
        grep -qF '>' "$_cxbm_prep_f" && { rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"; return 1; }
        _cxbm_script=$(sed -n 's/^[[:space:]]*\(bash\|sh\)[[:space:]]*"\([^"]*\)".*/\2/p' "$_cxbm_prep_f")
        if [ -z "$_cxbm_script" ]; then
            _cxbm_script=$(sed -n "s/^[[:space:]]*\\(bash\\|sh\\)[[:space:]]*'\\([^']*\\)'.*/\\2/p" "$_cxbm_prep_f")
        fi
        if [ -z "$_cxbm_script" ]; then
            _cxbm_script=$(sed -n 's/^[[:space:]]*\(bash\|sh\)[[:space:]]\+\([^[:space:]]*\).*/\2/p' "$_cxbm_prep_f")
        fi
        rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"
        if [ -n "$_cxbm_script" ]; then
            _cxbm_script_norm=$(_cxbm_normalize_path "$_cxbm_script") || return 1
            if _cxbm_is_existing_bootstrap_script "$_cxbm_script"; then
                return 0
            fi
            for _cxbm_dir in "$_cxbm_scripts_dir" "$_cxbm_hooks_dir"; do
                for _cxbm_f in "$_cxbm_dir"/*.sh; do
                    [ -f "$_cxbm_f" ] || continue
                    _cxbm_f_norm=$(_cxbm_normalize_path "$_cxbm_f") || continue
                    if [ "$_cxbm_script_norm" = "$_cxbm_f_norm" ]; then
                        return 0
                    fi
                done
            done
        fi
    else
        rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"
    fi

    # No Python — legacy forward-slash substring matcher (cannot safely parse JSON backslashes).
    if command -v tr >/dev/null 2>&1; then
        _cxbm_norm=$(tr -s '\\' '/' < "$_cxbm_json_f")
    else
        _cxbm_norm=$(cat "$_cxbm_json_f")
    fi
    case "$_cxbm_norm" in
        *';'* | *'|'* | *'&'* | *'`'* | *'$('* | *'<'* | *'>'*) return 1 ;;
    esac
    _cxbm_legacy_substring_match "$_cxbm_norm" "$_cxbm_hooks_dir"
}

# --- Authoritative matcher (delegates to hooks/cx_check.py) ---------------------------------------

# Interpreter used for the delegation, probed at most ONCE per shell process (both cx_check.sh and
# cx_run.sh may ask more than once). Must be Python 3: a Python-2 `python` would crash on
# cx_check.py's Python-3-only syntax and exit 1, which the exit-code mapping below would otherwise
# read as a decision.
_CXBM_PY=""
_CXBM_PY_PROBED=0
_cxbm_find_python() {
    if [ "$_CXBM_PY_PROBED" = 1 ]; then
        [ -n "$_CXBM_PY" ] || return 1
        printf '%s' "$_CXBM_PY"
        return 0
    fi
    _CXBM_PY_PROBED=1
    for _cxbm_c in python3 python; do
        if command -v "$_cxbm_c" >/dev/null 2>&1 && \
           "$_cxbm_c" -c "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)" >/dev/null 2>&1
        then
            _CXBM_PY="$_cxbm_c"
            printf '%s' "$_CXBM_PY"
            return 0
        fi
    done
    # Windows `py` launcher: `py -3` is always Python 3.
    if command -v py >/dev/null 2>&1 && py -3 -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
        _CXBM_PY="py -3"
        printf '%s' "$_CXBM_PY"
        return 0
    fi
    return 1
}

# cx_is_trusted_setup_command <hook_input_json> <hooks_dir>
# Returns 0 when the proposed command is TRUSTED BOOTSTRAP/AUTH/SETUP work that must ALWAYS be
# allowed regardless of cx's state: the bundled plugin scripts (component download + install),
# `cx auth …` (login/logout/validate/register), `cx configure …` (API key), `cx hooks check-auth`
# (session/licence validation), and `cx version` / `cx utils env` (pre-scan initialization). Returns 1
# for anything else, so the caller falls through to its own gate.
#
# The Python delegation reports three distinct exit codes: 0 = trusted (allow immediately). 1 = not
# trusted according to Python — fall through to the POSIX matchers below (Python may disagree with
# the shell-resolved plugin tree when the agent runs a deny-message path from another install copy).
# Anything else (3 = internal error, spawn/timeout) = undecided — same fall-through.
cx_is_trusted_setup_command() {
    _cxbm_json_f="$1"
    _cxbm_dir="${2:-}"
    _cxbm_gate="$_cxbm_dir/cx_check.py"
    [ -r "$_cxbm_json_f" ] || return 1
    if [ -n "$_cxbm_dir" ] && [ -f "$_cxbm_gate" ] && _cxbm_py=$(_cxbm_find_python); then
        # python.exe on Windows cannot open a /c/... MSYS path — hand it the native form.
        if command -v cygpath >/dev/null 2>&1; then
            _cxbm_gate=$(cygpath -w "$_cxbm_gate" 2>/dev/null) || _cxbm_gate="$_cxbm_dir/cx_check.py"
        fi
        # Bound the spawn: a wedged interpreter must not burn the hook's whole timeout budget (a
        # KILLED Cursor hook risks being treated as non-blocking = fail OPEN). Where coreutils
        # `timeout` is absent (stock macOS ships none) the call is made unbounded — no worse than
        # the pure-sh matchers this replaces, which also had no watchdog.
        # PYTHONDONTWRITEBYTECODE keeps this probe from littering __pycache__ into the plugin.
        if command -v timeout >/dev/null 2>&1; then
            PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 \
                timeout 10 $_cxbm_py "$_cxbm_gate" --match-trusted-setup < "$_cxbm_json_f" >/dev/null 2>&1
        else
            PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 \
                $_cxbm_py "$_cxbm_gate" --match-trusted-setup < "$_cxbm_json_f" >/dev/null 2>&1
        fi
        case "$?" in
            0) return 0 ;;
            *) : ;;  # not trusted or undecided — fall through to POSIX matchers
        esac
    fi
    cx_is_bootstrap_command "$_cxbm_json_f" "$_cxbm_dir" && return 0
    cx_is_auth_recovery_command "$_cxbm_json_f" "$_cxbm_gate" && return 0
    cx_is_setup_diagnostic_command "$_cxbm_json_f" && return 0
    return 1
}

# cx_is_setup_diagnostic_command <hook_json_file>
# True for bare `cx version` / `cx utils env` (or the resolved-absolute-path form) — mirrors
# cx_check.py's _is_setup_diagnostic_command for the no-Python fallback path.
cx_is_setup_diagnostic_command() {
    _cxbm_json_f="$1"
    [ -r "$_cxbm_json_f" ] || return 1
    _cxbm_is_shell_event "$_cxbm_json_f" || return 1
    _cxbm_cmd_f="${_cxbm_json_f}.cxcmd.$$"
    _cxbm_prep_f="${_cxbm_json_f}.cxprep.$$"
    _cxbm_extract_command_to_file "$_cxbm_json_f" "$_cxbm_cmd_f" || return 1
    if ! _cxbm_prep_carveout_cmd_file "$_cxbm_cmd_f" "$_cxbm_prep_f"; then
        rm -f "$_cxbm_cmd_f" "$_cxbm_prep_f"
        return 1
    fi
    rm -f "$_cxbm_cmd_f"
    grep -qF ';' "$_cxbm_prep_f" && { rm -f "$_cxbm_prep_f"; return 1; }
    grep -qF '|' "$_cxbm_prep_f" && { rm -f "$_cxbm_prep_f"; return 1; }
    grep -qF '&' "$_cxbm_prep_f" && { rm -f "$_cxbm_prep_f"; return 1; }
    grep -qF '`' "$_cxbm_prep_f" && { rm -f "$_cxbm_prep_f"; return 1; }
    grep -qF '$(' "$_cxbm_prep_f" && { rm -f "$_cxbm_prep_f"; return 1; }
    if grep -qE '^[[:space:]]*cx[[:space:]]+(version|utils[[:space:]]+env)[[:space:]]*$' "$_cxbm_prep_f"; then
        rm -f "$_cxbm_prep_f"
        return 0
    fi
    _cxbm_exe=$(sed -n 's/^[[:space:]]*"\([^"]*\)"[[:space:]]\+\(version\|utils env\).*/\1/p' "$_cxbm_prep_f")
    if [ -z "$_cxbm_exe" ]; then
        _cxbm_exe=$(sed -n "s/^[[:space:]]*'\\([^']*\\)'[[:space:]]\\+\\(version\\|utils env\\).*/\\1/p" "$_cxbm_prep_f")
    fi
    if [ -z "$_cxbm_exe" ]; then
        _cxbm_exe=$(sed -n 's/^[[:space:]]*\([A-Za-z]:[^[:space:]"]*\|\/[^[:space:]"]*\|~[^[:space:]"]*\)[[:space:]]\+\(version\|utils env\).*/\1/p' "$_cxbm_prep_f")
    fi
    rm -f "$_cxbm_prep_f"
    [ -n "$_cxbm_exe" ] || return 1
    _cxbm_exe_norm=$(_cxbm_normalize_path "$_cxbm_exe") || return 1
    _cxbm_cx_path_is_trusted "$_cxbm_exe_norm" "$_cxbm_exe"
}
