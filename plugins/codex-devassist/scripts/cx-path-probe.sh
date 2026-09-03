#!/usr/bin/env bash
# cx-path-probe.sh — find the first writable directory on a PATH, so a binary dropped there is
# usable in the CURRENT session. (A running process can't pick up a NEW PATH entry, but files in
# an already-on-PATH directory are live — so the trick is to place cx into a dir already on PATH.)
#
# A small, single-purpose, testable module:
#   - SOURCE it to get `first_writable_path_dir <path_string>` (used by cx-bootstrap.sh and tests).
#   - RUN it directly to probe the current $PATH (or a PATH passed as $1).
set -euo pipefail

# first_writable_path_dir <path_string>
#   stdout: the first existing, writable directory in <path_string> (colon-separated); return 0.
#   return 1 with NO output when none qualifies — callers signal "none" explicitly, never guess.
first_writable_path_dir() {
    local path_str="${1:-}" dir
    local IFS=:
    for dir in $path_str; do
        [ -n "$dir" ] || continue
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            printf '%s\n' "$dir"
            return 0
        fi
    done
    return 1
}

# Run directly → probe $PATH (or an explicit PATH argument).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    first_writable_path_dir "${1:-$PATH}" \
        || { printf 'none: no writable directory on PATH\n' >&2; exit 1; }
fi
