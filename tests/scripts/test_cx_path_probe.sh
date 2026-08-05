#!/usr/bin/env bash
# Tests for cx-path-probe.sh. No network. Run: bash tests/scripts/test_cx_path_probe.sh
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$DIR/../../plugins/copilot/checkmarx-devassist/scripts/cx-path-probe.sh"
set +e  # cx-path-probe.sh sets `set -e`; turn it off so we can assert on failing calls

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$1"; }

tmp="$(mktemp -d)"; trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
mkdir -p "$tmp/a" "$tmp/b"

# 1. Skips a non-existent earlier entry; returns the first existing+writable dir.
got="$(first_writable_path_dir "/no/such/dir:$tmp/a")"
[[ "$got" == "$tmp/a" ]] && ok "skips non-existent, returns first writable" || bad "got '$got'"

# 2. Skips empty entries.
got="$(first_writable_path_dir "::$tmp/b")"
[[ "$got" == "$tmp/b" ]] && ok "skips empty entries" || bad "got '$got'"

# 3. First writable wins (PATH order preserved).
got="$(first_writable_path_dir "$tmp/a:$tmp/b")"
[[ "$got" == "$tmp/a" ]] && ok "first writable wins" || bad "got '$got'"

# 4. None writable → return 1 with no output (explicit "none").
got="$(first_writable_path_dir "/no/such/x:/no/such/y")"; rc=$?
[[ $rc -ne 0 && -z "$got" ]] && ok "no writable dir → return 1, empty output" || bad "rc=$rc got='$got'"

# 5. A non-writable dir is skipped for a later writable one (POSIX perms; chmod is unreliable on
#    Windows/MSYS, so skip there).
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        printf 'skip - non-writable-skip (chmod unreliable on Windows)\n' ;;
    *)
        if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
            # root bypasses 0555 perms, so a read-only dir still tests as writable — skip.
            printf 'skip - non-writable-skip (running as root: bypasses 0555)\n'
        else
            mkdir -p "$tmp/ro"; chmod 555 "$tmp/ro"
            got="$(first_writable_path_dir "$tmp/ro:$tmp/a")"
            [[ "$got" == "$tmp/a" ]] && ok "skips read-only dir for a later writable one" || bad "got '$got'"
            chmod u+w "$tmp/ro"
        fi ;;
esac

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
