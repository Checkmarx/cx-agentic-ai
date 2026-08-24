#!/usr/bin/env bash
# cx-asset-resolver.sh — map an OS/arch to the Checkmarx ast-cli GitHub release asset name.
#
# A small, single-purpose, testable module:
#   - SOURCE it to get `resolve_cx_asset <uname_s> <uname_m>` (used by cx-bootstrap.sh and tests).
#   - RUN it directly to print the asset for THIS machine (handy for the manual-install docs).
#
# Asset names are pinned to what the ast-cli releases actually publish (verified against the
# release): linux x64/arm64/armv6, a single darwin asset (ast-cli_..._darwin_x64 — a UNIVERSAL
# amd64+arm64 binary that runs NATIVELY on Apple Silicon, no Rosetta), windows x64. An unsupported
# OS/arch is signalled explicitly (stderr + non-zero), never guessed.
set -euo pipefail

# resolve_cx_asset <uname_s> <uname_m> [<release_tag>]
#   stdout: "ast-cli_<os>_<arch>.<ext>" (or "ast-cli_<tag>_<os>_<arch>.<ext>" when <release_tag>
#   is set) and return 0 on success
#   stderr: "unsupported: <reason>" and return 1 when the OS or arch has no published asset
resolve_cx_asset() {
    local uname_s="${1:-}" uname_m="${2:-}" release_tag="${3:-}" os arch ext
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
    if [[ -n "$release_tag" ]]; then
        # GitHub release tags may be v-prefixed (e.g. v2.3.63-gemini-cliprerelease) but Goreleaser
        # asset names embed the version WITHOUT the leading v (ast-cli_2.3.63-gemini-cliprerelease_...).
        release_tag="${release_tag#v}"
        printf 'ast-cli_%s_%s_%s.%s\n' "$release_tag" "$os" "$arch" "$ext"
    else
        printf 'ast-cli_%s_%s.%s\n' "$os" "$arch" "$ext"
    fi
}

# Run directly → resolve for the current machine.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    resolve_cx_asset "$(uname -s)" "$(uname -m)"
fi
