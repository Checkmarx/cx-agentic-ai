#!/usr/bin/env bash
# Unit tests for scripts/cx-mcp-guard.sh — the shared version+capability decision for `cx mcp
# bridge`, sourced by both hooks/cx_run.sh (before spawning the MCP bridge) and
# scripts/cx-bootstrap.sh's verify() (after placing a freshly downloaded cx). Run:
#   bash tests/scripts/test_cx_mcp_guard.sh
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$DIR/../../plugins/copilot-devassist/scripts/cx-mcp-guard.sh"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$1"; }

# shellcheck source=../../plugins/copilot-devassist/scripts/cx-mcp-guard.sh
. "$GUARD"

# --- cx_mcp_parse_semver -----------------------------------------------------------------------
v=$(cx_mcp_parse_semver "2.3.54"); [[ "$v" == "2.3.54" ]] \
    && ok "parse_semver: bare version (no prefix)" || bad "parse_semver: bare version, got '$v'"

v=$(cx_mcp_parse_semver "Checkmarx CLI version 2.10.3 (commit abc123)"); [[ "$v" == "2.10.3" ]] \
    && ok "parse_semver: version embedded in text" || bad "parse_semver: embedded version, got '$v'"

cx_mcp_parse_semver "no version here" >/dev/null 2>&1
[[ $? -ne 0 ]] && ok "parse_semver: no digits → failure, not a false match" \
    || bad "parse_semver: should fail when no semver is present"

# --- cx_mcp_version_ge --------------------------------------------------------------------------
[[ "$(cx_mcp_version_ge 2.3.54 2.3.54)" == "ok" ]] && ok "version_ge: equal versions" \
    || bad "version_ge: equal versions should be ok"
[[ "$(cx_mcp_version_ge 2.4.0 2.3.54)" == "ok" ]] && ok "version_ge: newer minor" \
    || bad "version_ge: newer minor should be ok"
[[ "$(cx_mcp_version_ge 3.0.0 2.3.54)" == "ok" ]] && ok "version_ge: newer major" \
    || bad "version_ge: newer major should be ok"
[[ "$(cx_mcp_version_ge 2.3.10 2.3.54)" == "below" ]] && ok "version_ge: lower patch" \
    || bad "version_ge: lower patch should be below"
[[ "$(cx_mcp_version_ge 1.9.9 2.3.54)" == "below" ]] && ok "version_ge: lower major" \
    || bad "version_ge: lower major should be below"
[[ "$(cx_mcp_version_ge 2.3 2.3.54)" == "below" ]] && ok "version_ge: missing patch component treated as 0" \
    || bad "version_ge: missing patch should default to 0 and compare below"

# --- cx_mcp_load_min_version ---------------------------------------------------------------------
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

printf '# comment\n\n9.9.9\n' > "$tmp/minver"
v=$(cx_mcp_load_min_version "$tmp/minver" "0.0.1")
[[ "$v" == "9.9.9" ]] && ok "load_min_version: skips comments/blank lines" \
    || bad "load_min_version: expected 9.9.9, got '$v'"

v=$(cx_mcp_load_min_version "$tmp/does-not-exist" "1.2.3")
[[ "$v" == "1.2.3" ]] && ok "load_min_version: missing file falls back" \
    || bad "load_min_version: expected fallback 1.2.3, got '$v'"

printf 'garbage no version\n' > "$tmp/garbled"
v=$(cx_mcp_load_min_version "$tmp/garbled" "4.5.6")
[[ "$v" == "4.5.6" ]] && ok "load_min_version: garbled first line falls back (fail-closed)" \
    || bad "load_min_version: expected fallback 4.5.6, got '$v'"

# --- cx_mcp_guard_state (the orchestrated decision) ---------------------------------------------
make_stub() { # $1=path $2=version_output $3=bridge_help_exit
    cat > "$1" <<STUB
#!/bin/sh
if [ "\$1" = "version" ]; then echo "$2"; exit 0; fi
if [ "\$1 \$2 \$3" = "mcp bridge --help" ]; then exit $3; fi
exit 0
STUB
    chmod +x "$1"
}

make_stub "$tmp/cx_ok" "2.9.0" 0
make_stub "$tmp/cx_old" "2.0.0" 0
make_stub "$tmp/cx_incapable" "2.9.0" 1
make_stub "$tmp/cx_dev" "dev-build" 0
cat > "$tmp/cx_broken" <<'STUB'
#!/bin/sh
exit 1
STUB
chmod +x "$tmp/cx_broken"

printf '2.3.54\n' > "$tmp/minver_real"

[[ "$(cx_mcp_guard_state "$tmp/cx_ok" "$tmp/minver_real")" == "ok" ]] \
    && ok "guard_state: capable + current -> ok" || bad "guard_state: expected ok"
[[ "$(cx_mcp_guard_state "$tmp/cx_old" "$tmp/minver_real")" == "below" ]] \
    && ok "guard_state: below-min version -> below" || bad "guard_state: expected below"
[[ "$(cx_mcp_guard_state "$tmp/cx_incapable" "$tmp/minver_real")" == "incapable" ]] \
    && ok "guard_state: numerically fine but no 'mcp bridge' -> incapable" || bad "guard_state: expected incapable"
[[ "$(cx_mcp_guard_state "$tmp/cx_dev" "$tmp/minver_real")" == "dev" ]] \
    && ok "guard_state: 'dev' sentinel bypasses numeric floor -> dev" || bad "guard_state: expected dev"
[[ "$(cx_mcp_guard_state "$tmp/cx_broken" "$tmp/minver_real")" == "unrunnable" ]] \
    && ok "guard_state: cx exits non-zero with no parseable output -> unrunnable" || bad "guard_state: expected unrunnable"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
