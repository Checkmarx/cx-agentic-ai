#!/usr/bin/env bash
# Integration test: hooks/cx_run.sh's `mcp bridge` dispatch — the exact command .mcp.json spawns as
# the MCP server subprocess, OUTSIDE the PreToolUse hook system. Verifies the version+capability
# guard (scripts/cx-mcp-guard.sh) refuses to exec an unfit cx instead of corrupting the stdio
# transport, that a capable cx still execs through unchanged, and that every outcome is recorded to
# cx-devassist.jsonl via cx_log.py's mcp_connect event. Sandboxed via HOME/LOCALAPPDATA/USERPROFILE
# (mirrors test_cx_resolution_contract.sh) so this never touches a real cx installed on this
# machine. Run: bash tests/scripts/test_cx_run_mcp_guard.sh
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CXRUN="$DIR/../../plugins/copilot/checkmarx-devassist/hooks/cx_run.sh"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$1"; }

# A real python is required to exercise the logging assertions; the guard/exec assertions below do
# NOT depend on it (best-effort logging must never affect the connect/deny outcome).
PY=""
for _cand in python3 python; do
    if command -v "$_cand" >/dev/null 2>&1 \
       && "$_cand" -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' >/dev/null 2>&1; then
        PY="$(command -v "$_cand")"; break
    fi
done

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/home" "$tmp/store" "$tmp/logs"

make_stub() { # $1=path $2=version_output $3=bridge_help_exit
    cat > "$1" <<STUB
#!/bin/sh
if [ "\$1" = "version" ]; then echo "$2"; exit 0; fi
if [ "\$1 \$2 \$3" = "mcp bridge --help" ]; then exit $3; fi
echo "EXECED: \$@"
exit 0
STUB
    chmod +x "$1"
}

make_stub "$tmp/cx_ok" "2.9.0" 0
make_stub "$tmp/cx_old" "2.0.0" 0
make_stub "$tmp/cx_incapable" "2.9.0" 1

# Runs cx_run.sh mcp bridge fully sandboxed (no real HOME/LOCALAPPDATA/cx on PATH leaks in) and
# prints "<exit-code>|<stdout>|<stderr>" on one line for easy assertions.
run_guarded() { # $1 = CX_BINARY (or "" to leave cx entirely unresolved)
    local cxbin="$1" out err rc penv
    penv="/usr/bin:/bin"
    [[ -n "$PY" ]] && penv="$(dirname "$PY"):$penv"
    out="$tmp/out.$$"; err="$tmp/err.$$"
    ( CX_BINARY="$cxbin" HOME="$tmp/home" LOCALAPPDATA="$tmp/store" USERPROFILE="$tmp/home" \
      PATH="$penv" CX_LOG_DIR="$tmp/logs" \
      sh "$CXRUN" mcp bridge </dev/null >"$out" 2>"$err" )
    rc=$?
    printf '%s|%s|%s' "$rc" "$(cat "$out")" "$(cat "$err")"
    rm -f "$out" "$err"
}

rm -f "$tmp/logs/cx-devassist.jsonl"

# 1. Capable + current cx -> execs through untouched, exit 0, real stdout, no stderr diagnostic.
result="$(run_guarded "$tmp/cx_ok")"
rc="${result%%|*}"; rest="${result#*|}"; out="${rest%%|*}"; err="${rest#*|}"
[[ "$rc" == "0" && "$out" == "EXECED: mcp bridge" ]] \
    && ok "capable cx: execs through, exit 0" || bad "capable cx: expected exec+exit0, got rc=$rc out='$out'"
[[ -z "$err" ]] && ok "capable cx: no stderr diagnostic" || bad "capable cx: unexpected stderr '$err'"

# 2. Below-minimum cx -> refused (non-zero, no stdout at all — never exec's the broken subcommand).
result="$(run_guarded "$tmp/cx_old")"
rc="${result%%|*}"; rest="${result#*|}"; out="${rest%%|*}"; err="${rest#*|}"
[[ "$rc" != "0" ]] && ok "below-min cx: refused (non-zero exit)" || bad "below-min cx: should not exit 0"
[[ -z "$out" ]] && ok "below-min cx: stdout untouched (no corrupted MCP framing)" \
    || bad "below-min cx: stdout should be empty, got '$out'"
[[ "$err" == *"below the required"* ]] && ok "below-min cx: stderr names the exact reason" \
    || bad "below-min cx: expected a 'below the required' diagnostic, got '$err'"
[[ "$err" == *"CX_BINARY is pinned to this exact binary"* ]] \
    && ok "below-min cx via CX_BINARY: pin note present (tier=binary)" \
    || bad "below-min cx via CX_BINARY: expected the CX_BINARY pin note, got '$err'"

# 3. Numerically fine but missing `mcp bridge` -> refused, diagnostic names the capability gap.
result="$(run_guarded "$tmp/cx_incapable")"
rc="${result%%|*}"; rest="${result#*|}"; out="${rest%%|*}"; err="${rest#*|}"
[[ "$rc" != "0" && -z "$out" ]] && ok "incapable cx: refused, stdout untouched" \
    || bad "incapable cx: expected refusal with clean stdout, got rc=$rc out='$out'"
[[ "$err" == *"mcp bridge"* ]] && ok "incapable cx: stderr names the missing subcommand" \
    || bad "incapable cx: expected a 'mcp bridge' diagnostic, got '$err'"

# 4. cx entirely absent -> refused via the pre-existing absent-cx path, now also logged.
result="$(run_guarded "")"
rc="${result%%|*}"; rest="${result#*|}"; out="${rest%%|*}"; err="${rest#*|}"
[[ "$rc" != "0" && -z "$out" ]] && ok "cx absent: refused, stdout untouched" \
    || bad "cx absent: expected refusal with clean stdout, got rc=$rc out='$out'"
[[ "$err" == *"not found"* ]] && ok "cx absent: stderr says cx was not found" \
    || bad "cx absent: expected a 'not found' diagnostic, got '$err'"

# 5. Below-min cx resolved via the CANONICAL STORE (not CX_BINARY) -> refused for the same reason,
#    but the CX_BINARY-pin note must be ABSENT since nothing is pinning it here. Proves the note in
#    test 2 above is genuinely tier-conditional, not just always-on.
mkdir -p "$tmp/store/Checkmarx/cx"
cp "$tmp/cx_old" "$tmp/store/Checkmarx/cx/cx.exe"
chmod +x "$tmp/store/Checkmarx/cx/cx.exe"
result="$(run_guarded "")"
rc="${result%%|*}"; rest="${result#*|}"; out="${rest%%|*}"; err="${rest#*|}"
[[ "$rc" != "0" && -z "$out" ]] && ok "canonical-tier below-min: refused, stdout untouched" \
    || bad "canonical-tier below-min: expected refusal with clean stdout, got rc=$rc out='$out'"
[[ "$err" == *"below the required"* ]] && ok "canonical-tier below-min: stderr names the reason" \
    || bad "canonical-tier below-min: expected 'below the required' diagnostic, got '$err'"
[[ "$err" != *"CX_BINARY"* ]] && ok "canonical-tier below-min: CX_BINARY pin note correctly ABSENT" \
    || bad "canonical-tier below-min: unexpected CX_BINARY note in '$err'"
rm -f "$tmp/store/Checkmarx/cx/cx.exe"

# --- logging assertions (only meaningful if a real python was found) ---------------------------
if [[ -z "$PY" ]]; then
    printf 'skip - no python 3 found; skipping mcp_connect log assertions\n'
else
    log="$tmp/logs/cx-devassist.jsonl"
    if [[ -f "$log" ]]; then
        n="$(grep -c '"event":"mcp_connect"' "$log" || true)"
        [[ "$n" -eq 5 ]] && ok "mcp_connect logged once per attempt (5 attempts above)" \
            || bad "expected 5 mcp_connect records, found $n"
        grep -q '"reason_code":"ok"' "$log" && ok "log: ok case recorded" || bad "log: missing ok record"
        grep -q '"reason_code":"below"' "$log" && ok "log: below case recorded" || bad "log: missing below record"
        grep -q '"reason_code":"incapable"' "$log" && ok "log: incapable case recorded" || bad "log: missing incapable record"
        grep -q '"reason_code":"cx_absent"' "$log" && ok "log: cx_absent case recorded" || bad "log: missing cx_absent record"
        grep -q '"message":"cx v2.0.0 is below the required v2.3.55' "$log" \
            && ok "log: exact human-readable message present for the below case" \
            || bad "log: expected exact below-case message in $log"
        grep -q '"tier":"binary".*CX_BINARY is pinned to this exact binary' "$log" \
            && ok "log: tier=binary denial carries the CX_BINARY pin note" \
            || bad "log: expected a tier=binary record with the pin note in $log"
        grep -q '"tier":"canonical"' "$log" && ok "log: tier=canonical recorded for the canonical-store case" \
            || bad "log: expected a tier=canonical record in $log"
        ! grep -q '"tier":"canonical".*CX_BINARY is pinned' "$log" \
            && ok "log: tier=canonical record does NOT carry the CX_BINARY pin note" \
            || bad "log: tier=canonical record should not carry the CX_BINARY pin note"
    else
        bad "expected $log to exist after logged attempts"
    fi
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
