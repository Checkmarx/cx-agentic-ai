#!/usr/bin/env bash
# Table-driven tests for cursor-devassist cx-asset-resolver.sh (versioned release assets).
# No network. Run: bash tests/scripts/test_cx_asset_resolver_cursor.sh
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$DIR/../../plugins/cursor-devassist/scripts/cx-asset-resolver.sh"
set +e

pass=0; fail=0
TAG="2.3.59-Cursor-CLI"

want() {
    local got; got="$(resolve_cx_asset "$3" "$4" "$TAG" 2>/dev/null)"
    if [[ "$got" == "$2" ]]; then pass=$((pass + 1)); printf 'ok   - %s\n' "$1"
    else fail=$((fail + 1)); printf 'FAIL - %s (got "%s" want "%s")\n' "$1" "$got" "$2"; fi
}

want "linux x64 versioned"   "ast-cli_${TAG}_linux_x64.tar.gz"   "Linux"  "x86_64"
want "darwin arm64 versioned" "ast-cli_${TAG}_darwin_x64.tar.gz" "Darwin" "arm64"
want "windows versioned"     "ast-cli_${TAG}_windows_x64.zip"    "Windows_NT" "x86_64"

got="$(resolve_cx_asset "Linux" "x86_64" 2>/dev/null)"
if [[ "$got" == "ast-cli_linux_x64.tar.gz" ]]; then pass=$((pass + 1)); printf 'ok   - unversioned fallback\n'
else fail=$((fail + 1)); printf 'FAIL - unversioned fallback (got "%s")\n' "$got"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
