#!/usr/bin/env bash
# cx-asset-resolver.sh — map an OS/arch to the Checkmarx ast-cli GitHub release asset name.
#
# A small, single-purpose, testable module:
#   - SOURCE it to get `resolve_cx_asset <uname_s> <uname_m>` (used by cx-bootstrap.sh and tests).
#   - RUN it directly to print the asset for THIS machine (handy for the manual-install docs).
#
# Asset names are pinned to what the ast-cli releases actually publish (verified against the
# release): linux x64/arm64/armv6, a single darwin asset (ast-cli_<tag>_darwin_x64 — a UNIVERSAL
# amd64+arm64 binary that runs NATIVELY on Apple Silicon, no Rosetta), windows x64. An unsupported
# OS/arch is signalled explicitly (stderr + non-zero), never guessed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Synced fail-closed fallback with scripts/cx-bootstrap.sh (search: CX_RELEASE_TAG).
RELEASE_TAG_FALLBACK="2.3.59-Cursor-CLI"

# load_release_tag — first non-comment line from scripts/cx-release-tag.
load_release_tag() {
    local f="$SCRIPT_DIR/cx-release-tag" line
    if [[ -r "$f" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line#"${line%%[![:space:]]*}"}"   # ltrim
            [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
            printf '%s' "$line"
            return 0
        done < "$f"
    fi
    printf '%s' "$RELEASE_TAG_FALLBACK"
}

# resolve_cx_asset <uname_s> <uname_m> [release_tag]
#   stdout: "ast-cli_<tag>_<os>_<arch>.<ext>" and return 0 on success
#   stderr: "unsupported: <reason>" and return 1 when the OS or arch has no published asset
resolve_cx_asset() {
    local uname_s="${1:-}" uname_m="${2:-}" release_tag="${3:-}" os arch ext
    [[ -n "$release_tag" ]] || release_tag="$(load_release_tag)"
    case "$uname_s" in
        Darwin)                            os="darwin" ;;
        Linux)                             os="linux" ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)   os="windows" ;;
        *) printf 'unsupported: OS %s\n' "$uname_s" >&2; return 1 ;;
    esac
    case "$uname_m" in
        x86_64|amd64)    arch="x64" ;;
        aarch64|arm64)   arch="arm64" ;;
        armv6*|armv7*)   arch="armv6" ;;
        *) printf 'unsupported: architecture %s\n' "$uname_m" >&2; return 1 ;;
    esac
    # The darwin asset (ast-cli_..._darwin_x64) is a UNIVERSAL amd64+arm64 binary, so Apple Silicon
    # runs it NATIVELY (no Rosetta); Windows-on-ARM runs the x64 build via built-in x64 emulation.
    # Neither ships a separate ast-cli_<os>_arm64 asset, so remap arm64 → x64 on BOTH (which selects
    # the darwin universal / the windows x64 build) rather than build a URL for a non-existent asset.
    case "$os" in
        darwin)  arch="x64" ;;
        windows) [ "$arch" = "arm64" ] && arch="x64" ;;
    esac
    if [ "$os" = "windows" ]; then ext="zip"; else ext="tar.gz"; fi
    printf 'ast-cli_%s_%s_%s.%s\n' "$release_tag" "$os" "$arch" "$ext"
}

# Run directly → resolve for the current machine.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    resolve_cx_asset "$(uname -s)" "$(uname -m)"
fi
