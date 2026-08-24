#!/usr/bin/env bash
# cx-bootstrap.sh — self-install / self-upgrade the Checkmarx One `cx` CLI.
#
# This is the ONE command the checkmarx-devassist gate allows through while it is blocking (see
# hooks/cx_check.py `_is_bootstrap_command` and hooks/cx_check.sh's shell carve-out). It is
# whitelisted by its resolved absolute path and accepts at most one argument:
#
#     bash "<this script>" [install|upgrade]
#
# It deliberately understands NOTHING beyond that allowlist — any other argument is an
# error — so the carve-out can never be used to smuggle an arbitrary command.
#
# Runs on macOS and Linux natively, and on Windows under Git Bash (it shells out to
# powershell.exe for Windows-specific PATH/placement logic). It needs NO Python.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Shared asset-name resolver (uname → release asset). Its own module so it is unit-tested in
# isolation (scripts/test_cx_asset_resolver.sh) and reused here instead of duplicated. log()/die()
# are not defined yet, so report a missing helper with a raw message.
# shellcheck source=cx-asset-resolver.sh
. "$SCRIPT_DIR/cx-asset-resolver.sh" 2>/dev/null \
    || { printf 'ERROR: missing helper beside this script: cx-asset-resolver.sh\n' >&2; exit 1; }

# Shared writable-PATH probe (first writable dir on PATH). Same rationale — own unit-tested
# module (scripts/test_cx_path_probe.sh), reused here instead of duplicated.
# shellcheck source=cx-path-probe.sh
. "$SCRIPT_DIR/cx-path-probe.sh" 2>/dev/null \
    || { printf 'ERROR: missing helper beside this script: cx-path-probe.sh\n' >&2; exit 1; }

# Shared version + capability decision for `cx mcp bridge` — the SAME decision hooks/cx_run.sh
# makes before spawning the MCP bridge, so install-time verification and MCP-spawn-time gating can
# never drift into disagreeing about what counts as a capable cx. POSIX `sh` (sourced fine under
# bash too) — own unit-tested module (scripts/test_cx_mcp_guard.sh).
# shellcheck source=cx-mcp-guard.sh
. "$SCRIPT_DIR/cx-mcp-guard.sh" 2>/dev/null \
    || { printf 'ERROR: missing helper beside this script: cx-mcp-guard.sh\n' >&2; exit 1; }

# Numeric floor only (capability is decided by the gate's probe, not this number). Keep IDENTICAL
# to scripts/cx-min-version and the fallback in hooks/cx_check.py. (search marker: CX_MIN_VERSION)
MIN_CX_VERSION_FALLBACK="2.3.59"

# Pinned GitHub release tag for install/upgrade downloads. Keep IDENTICAL to scripts/cx-release-tag.
# (search marker: CX_RELEASE_TAG)
MIN_CX_RELEASE_TAG_FALLBACK="2.3.63-Gemini-CLI"

GITHUB_RELEASES="https://github.com/Checkmarx/ast-cli/releases"

# Temp base for download staging and the transient checksums file (NOT for persistent state).
TMP_BASE="${TMPDIR:-${TEMP:-${TMP:-/tmp}}}"

# Mirror hooks/cx_check.py _agent_log_dir(): the version cache lives under
# ~/.checkmarx/agent-logs/<assistant> (or $CX_LOG_DIR), NOT the OS temp dir. Clearing it after a
# place lets the next hook fire re-probe the just-installed/upgraded cx immediately.
# Bootstrap is client-agnostic — clear caches for BOTH claude and gemini-cli so whichever client
# fired the bootstrap sees the fresh version on its next hook call.
_LOG_BASE="${CX_LOG_DIR:-$HOME/.checkmarx/agent-logs}"
AGENT_LOG_DIR="$_LOG_BASE/claude"
VERSION_CACHE_FILE="$AGENT_LOG_DIR/cx_version_cache"
_GEMINI_VERSION_CACHE="$_LOG_BASE/gemini-cli/cx_version_cache"

log()  { printf '%s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Route downloads through the SAME proxy cx uses — no new plugin variable. Precedence mirrors cx's own
# binding: CX_HTTP_PROXY, then HTTP_PROXY/http_proxy, then the persisted `http_proxy:` key in
# ~/.checkmarx/checkmarxcli.yaml (so `cx configure set --prop-name http_proxy` covers the download too).
# Exported as http_proxy/https_proxy (both cases) so curl AND wget honor it natively — including HTTPS
# (GitHub), which needs https_proxy, not just http_proxy. The value may carry credentials → never logged.
apply_proxy() {
    local p="${CX_HTTP_PROXY:-${HTTP_PROXY:-${http_proxy:-}}}"
    if [[ -z "$p" ]]; then
        local cfg="$HOME/.checkmarx/checkmarxcli.yaml"
        [[ -r "$cfg" ]] && p="$(sed -n 's/^[[:space:]]*http_proxy:[[:space:]]*//p' "$cfg" 2>/dev/null | head -1 | tr -d "[:space:]\"'")"
    fi
    [[ -z "$p" ]] && return 0
    export http_proxy="$p" https_proxy="$p" HTTP_PROXY="$p" HTTPS_PROXY="$p"
    log "Routing downloads through the configured HTTP proxy."
}

# ---------------------------------------------------------------------------------------
# Minimum version (single source of truth: scripts/cx-min-version; first non-comment line).
# ---------------------------------------------------------------------------------------
load_min_version() {
    local f="$SCRIPT_DIR/cx-min-version" line
    if [[ -r "$f" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line#"${line%%[![:space:]]*}"}"   # ltrim
            [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
            if [[ "$line" =~ ([0-9]+\.[0-9]+\.[0-9]+) ]]; then
                printf '%s' "${BASH_REMATCH[1]}"
                return 0
            fi
            break
        done < "$f"
    fi
    printf '%s' "$MIN_CX_VERSION_FALLBACK"
}

# ---------------------------------------------------------------------------------------
# Pinned release tag (single source of truth: scripts/cx-release-tag; first non-comment line).
# ---------------------------------------------------------------------------------------
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
    printf '%s' "$MIN_CX_RELEASE_TAG_FALLBACK"
}

# ---------------------------------------------------------------------------------------
# OS / arch detection → GitHub release asset name.
# ---------------------------------------------------------------------------------------
OS=""; ASSET=""; EXT=""
detect_os_arch() {
    local uname_s uname_m release_tag
    uname_s="$(uname -s)"
    uname_m="$(uname -m)"
    release_tag="$(load_release_tag)"
    # Single source of truth for the asset name: resolve_cx_asset (cx-asset-resolver.sh).
    ASSET="$(resolve_cx_asset "$uname_s" "$uname_m" "$release_tag" 2>/dev/null)" \
        || die "Unsupported platform: $uname_s / $uname_m. No published cx asset — see the releases page."
    case "$uname_s" in
        Darwin)                            OS="darwin" ;;
        Linux)                             OS="linux" ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)   OS="windows" ;;
        *) die "Unsupported platform: $uname_s" ;;
    esac
    case "$ASSET" in
        *.tar.gz) EXT="tar.gz" ;;
        *.zip)    EXT="zip" ;;
    esac
}

# ---------------------------------------------------------------------------------------
# Download + extract `cx` into a staging dir; echoes the staged binary path.
# ---------------------------------------------------------------------------------------
download_and_extract() {
    # $1 = the pinned release tag from scripts/cx-release-tag. Downloading from the pinned tag URL
    # (and verifying against THAT tag's checksums) closes a TOCTOU window where GitHub could flip
    # `latest` between the download and the checksum fetch, making us verify one release's archive
    # against another's checksums.
    local tag="${1:-}"
    local url staging archive bin
    [[ -n "$tag" ]] || die "no release tag configured (scripts/cx-release-tag is missing or empty)"
    url="$GITHUB_RELEASES/download/$tag/$ASSET"
    staging="$_CX_STAGING"   # created by main() BEFORE the EXIT trap, so cleanup actually reaches it
    archive="$staging/$ASSET"

    log "Downloading $url"
    if command -v curl &>/dev/null; then
        curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused "$url" -o "$archive" \
            || die "download failed (curl) from $url"
    elif command -v wget &>/dev/null; then
        wget -qO "$archive" "$url" || die "download failed (wget) from $url"
    else
        die "neither curl nor wget is available to download $url"
    fi

    # Integrity gate: verify the download against the SAME release's published SHA-256 BEFORE
    # extracting/placing it. A mismatch is FATAL (corruption or tampering). If the checksums
    # can't be fetched (offline) or no hashing tool exists, warn and proceed — unless
    # CX_REQUIRE_CHECKSUM=1. This binary becomes the trusted scanner, so verify it first.
    verify_checksum "$archive" "$tag"

    log "Extracting $ASSET"
    if [[ "$EXT" == "zip" ]]; then
        if command -v unzip &>/dev/null; then
            unzip -oq "$archive" -d "$staging" || die "unzip failed"
        else
            local archive_w staging_w
            archive_w="$(cygpath -w "$archive")"; archive_w=${archive_w//\'/\'\'}
            staging_w="$(cygpath -w "$staging")"; staging_w=${staging_w//\'/\'\'}
            powershell.exe -NoProfile -Command \
                "Expand-Archive -Path '$archive_w' -DestinationPath '$staging_w' -Force" \
                || die "Expand-Archive failed"
        fi
    else
        tar -xzf "$archive" -C "$staging" || die "tar extract failed"
    fi

    if [[ "$OS" == "windows" ]]; then bin="$staging/cx.exe"; else bin="$staging/cx"; fi
    [[ -f "$bin" ]] || die "extracted archive did not contain $(basename "$bin")"
    chmod +x "$bin" 2>/dev/null || true
    printf '%s' "$bin"
}

# ---------------------------------------------------------------------------------------
# Checksum verification (supply-chain integrity for the downloaded binary).
# ---------------------------------------------------------------------------------------

# SHA-256 of a file → lowercase hex on stdout; return 1 if no hashing tool is available.
# NB (Windows): GNU coreutils (sha256sum / shasum, shipped with Git for Windows) escape the
# checksum LINE with a leading backslash when the file path contains a backslash or newline — and
# the staging path comes from the Windows %TEMP%, which is full of backslashes. That makes the
# first field "\<hash>" instead of "<hash>", which then fails verification as a FALSE mismatch and
# blocks EVERY Windows install. Strip a single leading backslash so the bare 64-hex digest is
# returned; this is harmless on POSIX (a real digest never starts with '\') and does not weaken
# verification — a genuinely different digest still mismatches and aborts.
compute_sha256() {
    local f="$1" out hash
    if command -v sha256sum >/dev/null 2>&1; then
        out="$(sha256sum "$f" 2>/dev/null)" && { hash="${out%% *}"; printf '%s' "${hash#\\}"; return 0; }
    elif command -v shasum >/dev/null 2>&1; then
        out="$(shasum -a 256 "$f" 2>/dev/null)" && { hash="${out%% *}"; printf '%s' "${hash#\\}"; return 0; }
    elif command -v openssl >/dev/null 2>&1; then
        out="$(openssl dgst -sha256 "$f" 2>/dev/null)" && { printf '%s' "${out##* }"; return 0; }
    elif command -v certutil >/dev/null 2>&1; then
        out="$(certutil -hashfile "$(cygpath -w "$f" 2>/dev/null || printf '%s' "$f")" SHA256 2>/dev/null \
               | sed -n 2p | tr -d '[:space:]\r')" && { printf '%s' "$out"; return 0; }
    fi
    return 1
}

# Compare $archive's SHA-256 to the expected entry for $asset in $checksums (a sha256sum-format
# file). DIES on a real mismatch. Returns 1 (no die) when verification can't be performed —
# no entry for the asset, or no hashing tool — so the caller can decide warn-vs-fatal.
verify_checksum_against() {
    local archive="$1" asset="$2" checksums="$3" expected actual
    expected="$(awk -v f="$asset" '$2 == f { print $1; exit }' "$checksums" 2>/dev/null)"
    [[ -n "$expected" ]] || { log "WARNING: no checksum entry for $asset"; return 1; }
    actual="$(compute_sha256 "$archive")" \
        || { log "WARNING: no SHA-256 tool available; cannot verify $asset"; return 1; }
    expected="$(printf '%s' "$expected" | tr 'A-F' 'a-f')"
    actual="$(printf '%s' "$actual" | tr 'A-F' 'a-f')"
    if [[ "$expected" != "$actual" ]]; then
        die "checksum MISMATCH for $asset: expected $expected, got $actual. Refusing to install a \
binary that does not match the published checksum (possible corruption or tampering)."
    fi
    log "Verified SHA-256 of $asset against the published checksums."
    return 0
}

# cx becomes the trusted scanner binary, so checksum verification is REQUIRED by default: any
# inability to verify (no tag / no curl / no checksums file / no entry / no hashing tool) is FATAL
# (fail-closed). Set CX_REQUIRE_CHECKSUM=0 to explicitly downgrade to warn-and-proceed (e.g. an
# air-gapped mirror with no published checksums) — NOT recommended for a security tool. A real hash
# MISMATCH always dies inside verify_checksum_against regardless of this setting.
_checksum_unavailable() {
    local why="$1"
    if [[ "${CX_REQUIRE_CHECKSUM:-1}" != "0" ]]; then
        die "checksum verification is required but $why. (Set CX_REQUIRE_CHECKSUM=0 to override — NOT recommended for a security tool.)"
    fi
    log "WARNING: proceeding WITHOUT checksum verification ($why) because CX_REQUIRE_CHECKSUM=0."
    return 0
}

# Orchestrate verification of $archive against the pinned release's published checksums.
# Strict on MISMATCH (always dies via verify_checksum_against); tolerant of UNAVAILABILITY
# (resolve/fetch/tool/entry) unless CX_REQUIRE_CHECKSUM=1.
verify_checksum() {
    # $2 = the tag the caller already resolved (so download + checksum use the SAME release).
    local archive="$1" tag="${2:-}" ver sums tag_url
    [[ -n "$tag" ]] || { _checksum_unavailable "no release tag configured (scripts/cx-release-tag)"; return $?; }
    ver="${tag#v}"
    sums="$(mktemp "${TMP_BASE%/}/cx-sums.XXXXXX")" || { _checksum_unavailable "could not create a temp file"; return $?; }
    tag_url="https://github.com/Checkmarx/ast-cli/releases/download/${tag}/ast-cli_${ver}_checksums.txt"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused "$tag_url" -o "$sums" 2>/dev/null \
            || { rm -f "$sums"; _checksum_unavailable "could not download the checksums file"; return $?; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q --tries=3 -O "$sums" "$tag_url" 2>/dev/null \
            || { rm -f "$sums"; _checksum_unavailable "could not download the checksums file"; return $?; }
    else
        rm -f "$sums"; _checksum_unavailable "neither curl nor wget is available to fetch checksums"; return $?
    fi
    if verify_checksum_against "$archive" "$ASSET" "$sums"; then
        rm -f "$sums"; return 0
    fi
    # A real mismatch already died inside verify_checksum_against; reaching here means it was
    # only UNVERIFIABLE (no entry / no tool).
    rm -f "$sums"
    _checksum_unavailable "no usable checksum entry for $ASSET"; return $?
}

# ---------------------------------------------------------------------------------------
# Placement.
# ---------------------------------------------------------------------------------------

# NOTE: no Rosetta step is needed. The published macOS asset (ast-cli_<ver>_darwin_x64.tar.gz) is a
# UNIVERSAL binary — goreleaser lipo-merges the amd64 AND arm64 slices into one file (verified against
# the 2.3.54 release: the single darwin asset is ~110 MB, vs ~28 MB for a single-arch build) — so it
# runs NATIVELY on Apple Silicon; Rosetta 2 is NOT required. cx-asset-resolver.sh deliberately maps
# darwin/arm64 → that darwin_x64 universal asset, which is why the old x86_64-only Rosetta gate that
# used to live here has been removed.

# Is a directory already on this shell's PATH?
on_path() {
    case ":$PATH:" in *":$1:"*) return 0 ;; *) return 1 ;; esac
}

# Place $staged at $dest ATOMICALLY: stage into the destination directory, then `mv` (a rename)
# into place — so a hook or `cx mcp bridge` resolving cx mid-install never sees a half-written
# (truncated) binary, and an interrupted copy can't leave no working binary behind. Falls back to
# a direct copy only when the destination directory isn't writable for staging (then atomicity
# isn't possible, but the existing behavior is preserved).
install_binary_atomically() {
    local staged="$1" dest="$2" dir tmp
    dir="$(dirname "$dest")"
    if tmp="$(mktemp "$dir/.cx.tmp.XXXXXX" 2>/dev/null)"; then
        cp -f "$staged" "$tmp"
        chmod +x "$tmp" 2>/dev/null || true
        if mv -f "$tmp" "$dest"; then return 0; fi
        rm -f "$tmp" 2>/dev/null || true
    fi
    cp -f "$staged" "$dest"
    chmod +x "$dest" 2>/dev/null || true
}

# Ensure $1 is on PATH for FUTURE login shells (so bare `cx` resolves in new terminals) by appending
# an idempotent, marked export line to the user's shell profile(s). Best-effort: the GATE does NOT
# need this (it resolves the canonical store by absolute path), and after B2 neither does the MCP
# (it runs via cx_run.sh) — this is purely developer convenience. If NO existing profile is found
# (fresh account), CREATE the login file for the user's shell (zsh -> ~/.zprofile, else ~/.profile)
# so a brand-new account still gets it. Never fails the install.
ensure_dir_on_path_profile() {
    local dir="$1" marker="# added by checkmarx-devassist (cx-bootstrap)" prof wrote=""
    on_path "$dir" && return 0
    for prof in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.zprofile"; do
        [[ -f "$prof" ]] || continue
        if grep -qF "$marker" "$prof" 2>/dev/null; then wrote=1; continue; fi
        printf '\n%s\nexport PATH="%s:$PATH"\n' "$marker" "$dir" >> "$prof" 2>/dev/null && wrote=1
    done
    if [[ -z "$wrote" ]]; then
        case "${SHELL:-}" in
            *zsh) prof="$HOME/.zprofile" ;;
            *)    prof="$HOME/.profile" ;;
        esac
        printf '\n%s\nexport PATH="%s:$PATH"\n' "$marker" "$dir" >> "$prof" 2>/dev/null || true
    fi
    return 0
}

# Unix/macOS: install cx to the ONE canonical store (~/.checkmarx/bin/cx). The GATE resolves it by
# absolute path (usable in THIS session), and the dir is added to PATH via the profile for the
# remediation MCP / future sessions. Echoes the canonical path.
install_unix() {
    local staged="$1" dir="$HOME/.checkmarx/bin" dest
    dest="$dir/cx"
    mkdir -p "$dir" || die "could not create $dir"
    install_binary_atomically "$staged" "$dest"
    ensure_dir_on_path_profile "$dir"
    log "Installed cx -> $dest"
    printf '%s' "$dest"
}

# Placement is canonical-store-based, so upgrade == install (overwrite the canonical cx).
upgrade_unix() {
    install_unix "$1"
}

# Windows: install cx.exe to the ONE canonical store (%LOCALAPPDATA%\Checkmarx\cx\cx.exe) and add
# that dir to the USER PATH for future sessions + the remediation MCP. No second "scatter" copy: the
# GATE resolves the canonical store by absolute path (hooks/cx_run.sh + cx_check.py), so it works in
# THIS session immediately without needing a writable on-PATH dir. If a running `cx mcp bridge` holds
# a handle on the existing canonical cx.exe, rename it aside first so the copy can't fail on a lock.
# Echoes the resolved (canonical) cx path.
place_windows() {
    local staged="$1" staged_w
    staged_w="$(cygpath -w "$staged")"; staged_w=${staged_w//\'/\'\'}
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
\$ErrorActionPreference = 'Stop'
\$staged = '$staged_w'
\$store  = Join-Path \$env:LOCALAPPDATA 'Checkmarx\\cx'
\$dest   = Join-Path \$store 'cx.exe'
New-Item -ItemType Directory -Force -Path \$store | Out-Null

# Copy into the canonical store; if a running bridge locks the old exe, rename it aside then copy.
if (Test-Path \$dest) {
    try { Copy-Item \$staged \$dest -Force }
    catch {
        \$old = \$dest + '.old'
        if (Test-Path \$old) { Remove-Item \$old -Force -ErrorAction SilentlyContinue }
        Rename-Item \$dest \$old -Force
        Copy-Item \$staged \$dest -Force
    }
} else {
    Copy-Item \$staged \$dest -Force
}

# Persist the canonical store on the USER PATH for FUTURE sessions + the MCP (idempotent; does not
# affect THIS session, whose PATH is frozen — the gate does not need it). Read AND write the User
# scope ONLY via the .NET API — never \$env:PATH (the merged System+User+session copy) with setx,
# which truncates at 1024 chars and permanently folds System entries into the User PATH.
# Best-effort: on WDAC / AppLocker / policy-locked machines the User-PATH write can be blocked. cx is
# already placed and the GATE resolves it by absolute path regardless, so a blocked PATH write must
# NOT abort the install — warn and continue (matches the Unix profile write, which is best-effort too).
try {
    \$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
    if (-not \$userPath) { \$userPath = '' }
    if ((\$userPath -split ';' | Where-Object { \$_ }) -notcontains \$store) {
        \$newPath = (\$userPath.TrimEnd(';') + ';' + \$store).Trim(';')
        [Environment]::SetEnvironmentVariable('PATH', \$newPath, 'User')
    }
} catch {
    Write-Warning ('Could not persist the canonical store on your User PATH: ' + \$_.Exception.Message + '. cx is installed and the security gate resolves it by absolute path regardless; only bare \`cx\` in a new terminal is affected (add ' + \$store + ' to PATH manually if you want it).')
}
Write-Output \$dest
" | tr -d '\r'
}

invalidate_version_cache() {
    rm -f "$VERSION_CACHE_FILE" 2>/dev/null || true
    rm -f "$_GEMINI_VERSION_CACHE" 2>/dev/null || true
}

verify() {
    local cx_path="$1" min="$2" cx_bin have state
    # Prefer the just-placed binary; fall back to PATH resolution.
    if [[ -n "$cx_path" && -x "$cx_path" ]]; then
        cx_bin="$cx_path"
    else
        cx_bin="cx"
    fi
    # Version + `cx mcp bridge` capability: the SAME decision hooks/cx_run.sh makes before spawning
    # the MCP bridge (cx-mcp-guard.sh, sourced above) — one source of truth instead of a second,
    # driftable copy of the version-compare + capability-probe logic.
    have="$(cx_mcp_parse_semver "$("$cx_bin" version 2>&1)" || true)"
    state="$(cx_mcp_guard_state "$cx_bin" "$SCRIPT_DIR/cx-min-version" "$min")"
    case "$state" in
        ok | dev)
            : # numeric floor cleared (or a `dev` build, which bypasses it) — fall through
            ;;
        below)
            die "placed cx reports ${have:-an unparseable version}, still below required $min — check the release asset."
            ;;
        incapable)
            # A numeric/dev match does NOT guarantee the agent-security subcommands exist: a PUBLIC
            # min-version build can still lack `cx mcp bridge`. Without this check the bootstrap would
            # report SUCCESS, then the fail-closed gate would classify cx 'incapable' and block every
            # tool call with no obvious cause. Fail LOUDLY here instead.
            die "placed cx is missing 'cx mcp bridge' — this build cannot run the remediation MCP. \
A capability-complete cx release is required (the public release may predate it; see scripts/cx-min-version)."
            ;;
        *)
            die "could not verify cx version after placement (state: $state)."
            ;;
    esac
    "$cx_bin" hooks gemini-before-file-tool --help >/dev/null 2>&1 \
        || die "placed cx is missing 'cx hooks gemini-before-file-tool' — this build cannot run the \
security scanner. A capability-complete cx release is required."
    log "Verified cx version + capability after placement."
    return 0
}

main() {
    # Clean up the download staging dir on ANY exit (success or die()), so repeated installs/upgrades
    # don't leak the full binary into TMPDIR/%TEMP% (matters on quota'd temp volumes). _CX_STAGING is
    # created below in THIS scope (NOT inside the download_and_extract command-substitution subshell,
    # whose assignment would never reach this trap); the checksums temp is removed inside verify_checksum.
    trap 'rm -rf "${_CX_STAGING:-}" 2>/dev/null || true' EXIT

    # Argument allowlist — the ONLY values this script accepts (must match the carve-outs).
    local explicit_mode=""
    if [[ $# -gt 1 ]]; then die "too many arguments; usage: cx-bootstrap.sh [install|upgrade]"; fi
    if [[ $# -eq 1 ]]; then
        case "$1" in
            install|upgrade) explicit_mode="$1" ;;
            *) die "unknown argument '$1'; usage: cx-bootstrap.sh [install|upgrade]" ;;
        esac
    fi

    local min mode
    min="$(load_min_version)"
    detect_os_arch
    apply_proxy   # route downloads through cx's proxy (env or checkmarxcli.yaml http_proxy) if configured

    if [[ -n "$explicit_mode" ]]; then
        mode="$explicit_mode"
    elif command -v cx &>/dev/null; then
        # Auto-mode: only UPGRADE in place when the existing cx (or its directory) is writable.
        # A package-managed / root-owned cx is NOT writable; forcing `upgrade` there would hard-fail
        # even though install_unix could still place a usable user-level copy and unblock the gate.
        local existing
        existing="$(command -v cx)"
        if [[ -w "$existing" || -w "$(dirname "$existing")" ]]; then
            mode="upgrade"
        else
            mode="install"
        fi
    else
        mode="install"
    fi
    log "Mode: $mode  |  asset: $ASSET  |  min version: $min  |  release: $(load_release_tag)"

    # Create the staging dir HERE (in main's scope, so the EXIT trap actually sees it — an assignment
    # inside the download_and_extract command-substitution subshell would not), then thread the
    # pinned release tag through download + checksum (TOCTOU-safe).
    _CX_STAGING="$(mktemp -d "${TMP_BASE%/}/cx-bootstrap.XXXXXX")" || die "could not create a staging directory"
    local staged tag resolved=""
    tag="$(load_release_tag)"
    staged="$(download_and_extract "$tag")"

    # Verify the STAGED binary (version + capability) BEFORE placing it or touching PATH, so a
    # below-min / incapable / unrunnable build never lands on disk or on the User PATH — a failed
    # verify die()s here with nothing to roll back.
    verify "$staged" "$min"

    if [[ "$OS" == "windows" ]]; then
        resolved="$(place_windows "$staged")"
    elif [[ "$mode" == "upgrade" ]]; then
        resolved="$(upgrade_unix "$staged")"
    else
        resolved="$(install_unix "$staged")"
    fi

    invalidate_version_cache

    # Post-placement sanity: capability was already proven on the STAGED binary above, but confirm the
    # binary actually ON DISK still runs — catches a corrupt/partial/locked copy so we never report
    # "installed" over a broken cx that the runtime gate would then deny.
    if [[ -n "$resolved" && "$resolved" != "cx" ]]; then
        "$resolved" version >/dev/null 2>&1 \
            || die "cx was placed at $resolved but does not run (the copy may be corrupt or locked) — re-run install."
    fi

    log ""
    log "Done. cx is installed at: ${resolved}"
    log "Activation:"
    log "  - The security GATE resolves this canonical cx by ABSOLUTE path, so your NEXT tool call is"
    log "    gated live — no restart needed, even though this session's PATH has not changed."
    log "  - The Checkmarx remediation MCP also resolves cx by absolute path (via cx_run.sh), so it"
    log "    activates after ONE /restart — no full reinstall needed. (cx was also added to your PATH"
    log "    for convenience in new terminals.)"
}

# Run only when executed directly — not when sourced (e.g. by scripts/test_cx_bootstrap.sh).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
