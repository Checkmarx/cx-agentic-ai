#!/usr/bin/env bash
# Offline tests for cx-bootstrap.sh checksum verification. No network, no install.
# Run: bash tests/scripts/test_cx_bootstrap.sh
#
# Sources cx-bootstrap.sh (its `main` is guarded, so sourcing does NOT install anything) and
# exercises the pure checksum functions against local fixtures.

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$DIR/../../plugins/cx-devassist/scripts/cx-bootstrap.sh"
set +e  # cx-bootstrap.sh enables `set -e`; turn it off so we can assert on failing calls

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$1"; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
archive="$tmp/ast-cli_linux_x64.tar.gz"
printf 'pretend-cx-binary' > "$archive"
real="$(compute_sha256 "$archive")"
sums="$tmp/sums.txt"
zero="0000000000000000000000000000000000000000000000000000000000000000"

# 1. compute_sha256 yields a 64-char lowercase hex digest.
if [[ "$real" =~ ^[0-9a-f]{64}$ ]]; then ok "compute_sha256 returns 64-hex"; else bad "compute_sha256 format: '$real'"; fi

# 1b. Windows regression: GNU coreutils prepend a leading backslash to the checksum LINE when the
#     file path contains backslashes (Windows %TEMP%), so the first field becomes "\<hash>".
#     compute_sha256 must strip it — else every Windows install fails verification as a FALSE
#     mismatch (the bug a colleague hit on final-flow-v2). Stub sha256sum to emit the escaped line.
sha256sum() { printf '\\%s  staged-archive\n' "$real"; }
escaped="$(compute_sha256 "$archive")"
unset -f sha256sum
if [[ "$escaped" == "$real" ]]; then ok "compute_sha256 strips coreutils backslash escape (Windows)"; else bad "escape strip: got '$escaped' want '$real'"; fi

# 1c. End-to-end: the previously-false mismatch now VERIFIES against the published digest.
sha256sum() { printf '\\%s  staged-archive\n' "$real"; }
printf '%s  ast-cli_linux_x64.tar.gz\n' "$real" > "$sums"
( verify_checksum_against "$archive" "ast-cli_linux_x64.tar.gz" "$sums" ) >/dev/null 2>&1; rc=$?
unset -f sha256sum
if [[ $rc -eq 0 ]]; then ok "escaped digest verifies (no false mismatch)"; else bad "escaped digest should verify"; fi

# 2. Matching checksum PASSES (returns 0).
printf '%s  ast-cli_linux_x64.tar.gz\n' "$real" > "$sums"
( verify_checksum_against "$archive" "ast-cli_linux_x64.tar.gz" "$sums" ) >/dev/null 2>&1
if [[ $? -eq 0 ]]; then ok "matching checksum passes"; else bad "matching checksum should pass"; fi

# 3. Matching is case-insensitive (uppercase fixture still passes).
printf '%s  ast-cli_linux_x64.tar.gz\n' "$(printf '%s' "$real" | tr 'a-f' 'A-F')" > "$sums"
( verify_checksum_against "$archive" "ast-cli_linux_x64.tar.gz" "$sums" ) >/dev/null 2>&1
if [[ $? -eq 0 ]]; then ok "uppercase checksum still matches"; else bad "case-insensitive compare failed"; fi

# 4. Mismatch DIES (non-zero exit; die→exit 1).
printf '%s  ast-cli_linux_x64.tar.gz\n' "$zero" > "$sums"
( verify_checksum_against "$archive" "ast-cli_linux_x64.tar.gz" "$sums" ) >/dev/null 2>&1
if [[ $? -ne 0 ]]; then ok "mismatch dies"; else bad "mismatch must die"; fi

# 5. Exact-name match only — a versioned line must NOT satisfy the unversioned asset.
printf '%s  ast-cli_9.9.9_linux_x64.tar.gz\n' "$real" > "$sums"
( verify_checksum_against "$archive" "ast-cli_linux_x64.tar.gz" "$sums" ) >/dev/null 2>&1
if [[ $? -eq 1 ]]; then ok "no exact entry → returns 1 (unverifiable, not a false pass)"; else bad "loose name match leaked a pass"; fi

# 6. Unavailable: FATAL by default (fail-closed for a security tool); warn+proceed only when the
#    developer explicitly opts out with CX_REQUIRE_CHECKSUM=0.
( _checksum_unavailable "test reason" ) >/dev/null 2>&1
if [[ $? -ne 0 ]]; then ok "unavailable is fatal by default (fail-closed)"; else bad "unavailable should die by default"; fi
( CX_REQUIRE_CHECKSUM=0; _checksum_unavailable "test reason" ) >/dev/null 2>&1
if [[ $? -eq 0 ]]; then ok "CX_REQUIRE_CHECKSUM=0 downgrades to warn+proceed"; else bad "explicit opt-out should proceed"; fi

# 7. install_unix places the ONE canonical copy at ~/.checkmarx/bin/cx — the absolute path the gate
#    resolves — regardless of PATH, and does NOT scatter a second copy into an on-PATH dir.
staged="$tmp/staged-cx"; printf '#!/bin/sh\n' > "$staged"

home1="$tmp/home1"; mkdir -p "$home1"
dest="$( export HOME="$home1" PATH="/usr/bin:/bin"; install_unix "$staged" 2>/dev/null )"
if [[ "$dest" == "$home1/.checkmarx/bin/cx" && -f "$dest" ]]; then ok "install_unix installs to the canonical ~/.checkmarx/bin/cx"
else bad "install_unix canonical placement got '$dest'"; fi

fb="$tmp/fbdir"; mkdir -p "$fb"
home2="$tmp/home2"; mkdir -p "$home2"
dest="$( export HOME="$home2" PATH="$fb:/usr/bin:/bin"; install_unix "$staged" 2>/dev/null )"
if [[ "$dest" == "$home2/.checkmarx/bin/cx" && ! -e "$fb/cx" ]]; then ok "install_unix does not scatter a copy onto PATH"
else bad "install_unix scattered or misplaced: dest='$dest'"; fi

# 7b. upgrade_unix targets the SAME canonical store (upgrade == install for canonical placement).
home3="$tmp/home3"; mkdir -p "$home3"
dest="$( export HOME="$home3" PATH="/usr/bin:/bin"; upgrade_unix "$staged" 2>/dev/null )"
if [[ "$dest" == "$home3/.checkmarx/bin/cx" && -f "$dest" ]]; then ok "upgrade_unix targets the canonical store"
else bad "upgrade_unix canonical placement got '$dest'"; fi

# 8. install_binary_atomically: places an executable via stage+rename, leaving no temp file behind.
atom="$tmp/atom"; mkdir -p "$atom"
install_binary_atomically "$staged" "$atom/cx" 2>/dev/null
leftover="$(find "$atom" -maxdepth 1 -name '.cx.tmp.*' 2>/dev/null)"
if [[ -f "$atom/cx" && -x "$atom/cx" && -z "$leftover" ]]; then ok "install_binary_atomically places exec, no temp leftover"
else bad "atomic install: exec/leftover check failed (leftover='$leftover')"; fi

# 9. verify() requires CAPABILITY, not just a version string. Stub a cx whose `mcp bridge` /
#    `hooks` either succeed (capable) or fail (incapable, like public 2.3.54).
capdir="$tmp/cap"; mkdir -p "$capdir"
cat > "$capdir/cx" <<'STUB'
#!/bin/sh
[ "$1" = "version" ] && { echo "99.0.0"; exit 0; }
[ "$1" = "mcp" ] && [ "$2" = "bridge" ] && exit 0
[ "$1" = "hooks" ] && exit 0
exit 0
STUB
chmod +x "$capdir/cx"
( verify "$capdir/cx" "2.3.54" ) >/dev/null 2>&1
if [[ $? -eq 0 ]]; then ok "verify passes a capable cx"; else bad "verify should pass a capable cx"; fi

incap="$tmp/incap"; mkdir -p "$incap"
cat > "$incap/cx" <<'STUB'
#!/bin/sh
[ "$1" = "version" ] && { echo "99.0.0"; exit 0; }
[ "$1" = "mcp" ] && [ "$2" = "bridge" ] && exit 1
[ "$1" = "hooks" ] && exit 1
exit 0
STUB
chmod +x "$incap/cx"
( verify "$incap/cx" "2.3.54" ) >/dev/null 2>&1
if [[ $? -ne 0 ]]; then ok "verify dies for an incapable cx (no mcp bridge / hooks)"; else bad "verify must reject incapable cx"; fi

# 10. verify_checksum with an empty tag (caller couldn't resolve it) is UNAVAILABLE → now FATAL by
#     default (fail-closed); proceeds only when the developer opts out with CX_REQUIRE_CHECKSUM=0.
( verify_checksum "$archive" "" ) >/dev/null 2>&1
if [[ $? -ne 0 ]]; then ok "verify_checksum empty tag → fatal by default (fail-closed)"; else bad "empty tag should be fatal by default"; fi
( CX_REQUIRE_CHECKSUM=0; verify_checksum "$archive" "" ) >/dev/null 2>&1
if [[ $? -eq 0 ]]; then ok "verify_checksum empty tag proceeds under CX_REQUIRE_CHECKSUM=0"; else bad "explicit opt-out empty tag should proceed"; fi

# 11. ensure_dir_on_path_profile CREATES a login profile on a fresh account (no dotfiles) so bare cx
#     resolves in future sessions — B7 (fresh zsh/bash_profile users were silently skipped before).
ph="$tmp/prof_home"; mkdir -p "$ph"
( export HOME="$ph" SHELL="/bin/bash" PATH="/usr/bin:/bin"; ensure_dir_on_path_profile "$ph/.checkmarx/bin" >/dev/null 2>&1 )
if grep -rqF "cx-devassist (cx-bootstrap)" "$ph" 2>/dev/null; then ok "ensure_dir_on_path_profile creates a profile on a fresh account"
else bad "ensure_dir_on_path_profile wrote no profile on a fresh account"; fi

# 11b. Idempotent — a second call must not duplicate the marker.
( export HOME="$ph" SHELL="/bin/bash" PATH="/usr/bin:/bin"; ensure_dir_on_path_profile "$ph/.checkmarx/bin" >/dev/null 2>&1 )
n="$(grep -rhF "cx-devassist (cx-bootstrap)" "$ph" 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$n" == "1" ]]; then ok "ensure_dir_on_path_profile is idempotent (marker written once)"
else bad "ensure_dir_on_path_profile duplicated the marker (found $n)"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
