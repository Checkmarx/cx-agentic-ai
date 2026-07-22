#!/usr/bin/env bash
# Table-driven tests for cx-asset-resolver.sh. No network. Run: bash tests/scripts/test_cx_asset_resolver.sh
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$DIR/../../plugins/copilot/checkmarx-devassist/scripts/cx-asset-resolver.sh"
set +e  # cx-asset-resolver.sh sets `set -e`; turn it off so we can assert on failing calls

pass=0; fail=0

want() {  # desc  expected_asset  uname_s  uname_m
    local got; got="$(resolve_cx_asset "$3" "$4" 2>/dev/null)"
    if [[ "$got" == "$2" ]]; then pass=$((pass + 1)); printf 'ok   - %s\n' "$1"
    else fail=$((fail + 1)); printf 'FAIL - %s (got "%s" want "%s")\n' "$1" "$got" "$2"; fi
}

unsupported() {  # desc  uname_s  uname_m
    resolve_cx_asset "$2" "$3" >/dev/null 2>&1
    if [[ $? -ne 0 ]]; then pass=$((pass + 1)); printf 'ok   - %s\n' "$1"
    else fail=$((fail + 1)); printf 'FAIL - %s (expected unsupported signal)\n' "$1"; fi
}

# Each expected asset below is a real published release artifact.
want "linux x86_64"        "ast-cli_linux_x64.tar.gz"   "Linux"            "x86_64"
want "linux amd64 alias"   "ast-cli_linux_x64.tar.gz"   "Linux"            "amd64"
want "linux aarch64"       "ast-cli_linux_arm64.tar.gz" "Linux"            "aarch64"
want "linux arm64 alias"   "ast-cli_linux_arm64.tar.gz" "Linux"            "arm64"
want "linux armv7"         "ast-cli_linux_armv6.tar.gz" "Linux"            "armv7l"
want "darwin x86_64"       "ast-cli_darwin_x64.tar.gz"  "Darwin"           "x86_64"
want "darwin arm64→x64"    "ast-cli_darwin_x64.tar.gz"  "Darwin"           "arm64"
want "windows mingw"       "ast-cli_windows_x64.zip"    "MINGW64_NT-10.0"  "x86_64"
want "windows msys"        "ast-cli_windows_x64.zip"    "MSYS_NT-10.0"     "x86_64"
want "windows_nt"          "ast-cli_windows_x64.zip"    "Windows_NT"       "x86_64"
want "windows arm64→x64"   "ast-cli_windows_x64.zip"    "Windows_NT"       "arm64"
unsupported "unknown OS"   "Plan9"  "x86_64"
unsupported "unknown arch" "Linux"  "sparc64"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
