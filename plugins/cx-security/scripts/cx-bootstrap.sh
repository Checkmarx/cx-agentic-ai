#!/usr/bin/env bash
# cx-bootstrap.sh — self-install / self-upgrade the Checkmarx One `cx` CLI.
#
# This is the ONE command the cx-security gate allows through while it is blocking (see
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

# Numeric floor only (capability is decided by the gate's probe, not this number). Keep IDENTICAL
# to scripts/cx-min-version and the fallback in hooks/cx_check.py. (search marker: CX_MIN_VERSION)
MIN_CX_VERSION_FALLBACK="2.3.54"

GITHUB_RELEASES="https://github.com/Checkmarx/ast-cli/releases"
GITHUB_LATEST="$GITHUB_RELEASES/latest/download"

# Temp base for download staging and the transient checksums file (NOT for persistent state).
TMP_BASE="${TMPDIR:-${TEMP:-${TMP:-/tmp}}}"

# Mirror hooks/cx_check.py _agent_log_dir(): the version cache lives under
# ~/.checkmarx/agent-logs/claude (or $CX_LOG_DIR), NOT the OS temp dir. Clearing it after a
# place lets the next hook fire re-probe the just-installed/upgraded cx immediately.
AGENT_LOG_DIR="${CX_LOG_DIR:-$HOME/.checkmarx/agent-logs/claude}"
VERSION_CACHE_FILE="$AGENT_LOG_DIR/cx_version_cache"

log()  { printf '%s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

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

# Compare dotted versions: prints "ok" if $1 >= $2, else "below".
version_ge() {
    local have="$1" want="$2" IFS=.
    local -a h=($have) w=($want)
    local i
    for i in 0 1 2; do
        local hv="${h[i]:-0}" wv="${w[i]:-0}"
        ((10#$hv > 10#$wv)) && { printf 'ok'; return; }
        ((10#$hv < 10#$wv)) && { printf 'below'; return; }
    done
    printf 'ok'
}

# ---------------------------------------------------------------------------------------
# OS / arch detection → GitHub release asset name.
# ---------------------------------------------------------------------------------------
OS=""; ASSET=""; EXT=""
detect_os_arch() {
    # Single source of truth for the asset name: resolve_cx_asset (cx-asset-resolver.sh).
    ASSET="$(resolve_cx_asset "$(uname -s)" "$(uname -m)" 2>/dev/null)" \
        || die "Unsupported platform: $(uname -s) / $(uname -m). No published cx asset — see the releases page."
    # Derive OS (placement branching) and EXT (zip vs tar.gz) from the resolved name
    # ast-cli_<os>_<arch>.<ext>, so they always agree with the resolver.
    OS="${ASSET#ast-cli_}"; OS="${OS%%_*}"
    case "$ASSET" in
        *.tar.gz) EXT="tar.gz" ;;
        *.zip)    EXT="zip" ;;
    esac
}

# ---------------------------------------------------------------------------------------
# Download + extract `cx` into a staging dir; echoes the staged binary path.
# ---------------------------------------------------------------------------------------
download_and_extract() {
    # $1 = the release tag resolved ONCE by the caller. Downloading from the pinned tag URL (and
    # verifying against THAT tag's checksums) closes a TOCTOU window where GitHub could flip
    # `latest` between the download and the checksum fetch, making us verify one release's archive
    # against another's checksums. An empty tag (no curl) falls back to the latest/download URL.
    local tag="${1:-}"
    local url staging archive bin
    if [[ -n "$tag" ]]; then
        url="$GITHUB_RELEASES/download/$tag/$ASSET"
    else
        url="$GITHUB_LATEST/$ASSET"
    fi
    staging="$(mktemp -d "${TMP_BASE%/}/cx-bootstrap.XXXXXX")"
    archive="$staging/$ASSET"

    log "Downloading $url"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$archive" || die "download failed (curl) from $url"
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

# Resolve the tag the `latest` release points at (e.g. 2.3.54), via the redirect of the
# releases/latest URL. Needs curl; returns 1 if it can't be resolved.
resolve_latest_tag() {
    command -v curl >/dev/null 2>&1 || return 1
    local eff
    eff="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
           "https://github.com/Checkmarx/ast-cli/releases/latest" 2>/dev/null)" || return 1
    eff="${eff%/}"
    [[ -n "$eff" && "$eff" != *"/releases/latest" ]] || return 1
    printf '%s' "${eff##*/}"
}

# Warn-and-proceed when verification can't be performed — unless CX_REQUIRE_CHECKSUM=1, which
# makes any inability to verify FATAL (fail-closed for high-assurance environments).
_checksum_unavailable() {
    local why="$1"
    if [[ "${CX_REQUIRE_CHECKSUM:-0}" == "1" ]]; then
        die "checksum verification is required (CX_REQUIRE_CHECKSUM=1) but $why."
    fi
    log "WARNING: proceeding WITHOUT checksum verification ($why). Set CX_REQUIRE_CHECKSUM=1 to make this fatal."
    return 0
}

# Orchestrate verification of $archive against the latest release's published checksums.
# Strict on MISMATCH (always dies via verify_checksum_against); tolerant of UNAVAILABILITY
# (resolve/fetch/tool/entry) unless CX_REQUIRE_CHECKSUM=1.
verify_checksum() {
    # $2 = the tag the caller already resolved (so download + checksum use the SAME release).
    local archive="$1" tag="${2:-}" ver sums tag_url
    [[ -n "$tag" ]] || { _checksum_unavailable "could not resolve the latest release tag"; return $?; }
    ver="${tag#v}"
    command -v curl >/dev/null 2>&1 || { _checksum_unavailable "curl is unavailable to fetch checksums"; return $?; }
    sums="$(mktemp "${TMP_BASE%/}/cx-sums.XXXXXX")" || { _checksum_unavailable "could not create a temp file"; return $?; }
    tag_url="https://github.com/Checkmarx/ast-cli/releases/download/${tag}/ast-cli_${ver}_checksums.txt"
    if ! curl -fsSL "$tag_url" -o "$sums" 2>/dev/null; then
        rm -f "$sums"; _checksum_unavailable "could not download the checksums file"; return $?
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

# Apple Silicon: the published cx is x86_64 and needs Rosetta 2 to execute. Fail fast with an
# actionable hint rather than dying later at `cx version` with a cryptic exec error. No-op on
# Linux, Windows, and Intel macs.
ensure_rosetta_if_needed() {
    [[ "$OS" == "darwin" && "$(uname -m)" == "arm64" ]] || return 0
    # Modern macOS ships THIN arm64 system binaries (no x86_64 slice), so `arch -x86_64
    # /usr/bin/true` returns "Bad CPU type" even WHEN Rosetta is installed — a false negative that
    # would wrongly block the install. Detect the Rosetta runtime on disk (or its daemon) instead.
    if [[ -f /Library/Apple/usr/libexec/oah/libRosettaRuntime ]] \
       || [[ -d /Library/Apple/usr/share/rosetta ]] \
       || /usr/bin/pgrep -q oahd 2>/dev/null; then
        return 0
    fi
    die "Apple Silicon detected and the cx build is x86_64 — it needs Rosetta 2 to run. Install it \
with:  softwareupdate --install-rosetta --agree-to-license   then retry."
}

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

install_unix() {
    local staged="$1" dest="" cand writable
    # Prefer a canonical, persistent dir that is BOTH on PATH and writable, so cx is usable in
    # THIS session and lives somewhere sensible. /opt/homebrew/bin covers Apple Silicon Homebrew;
    # ~/.local/bin and ~/bin are created on demand. Then fall back to ANY writable on-PATH dir.
    for cand in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin" "$HOME/bin"; do
        on_path "$cand" || continue
        case "$cand" in
            "$HOME/.local/bin"|"$HOME/bin") mkdir -p "$cand" 2>/dev/null || true ;;
        esac
        if [[ -d "$cand" && -w "$cand" ]]; then dest="$cand/cx"; break; fi
    done
    if [[ -z "$dest" ]] && writable="$(first_writable_path_dir "$PATH")"; then
        dest="$writable/cx"
    fi
    [[ -n "$dest" ]] || die "no writable directory found on PATH. Create ~/.local/bin and add it to \
PATH (e.g. add 'export PATH=\"\$HOME/.local/bin:\$PATH\"' to your shell profile), then retry."
    install_binary_atomically "$staged" "$dest"
    log "Installed cx -> $dest"
    printf '%s' "$dest"
}

upgrade_unix() {
    local staged="$1" target
    target="$(command -v cx)" || die "upgrade mode but cx not found on PATH"
    [[ -w "$target" || -w "$(dirname "$target")" ]] || die "cannot overwrite $target (not writable)"
    install_binary_atomically "$staged" "$target"
    log "Upgraded cx -> $target"
    printf '%s' "$target"
}

# Windows: place cx.exe into the first writable folder already on PATH (so THIS session's
# hooks pick it up without a restart), keep a canonical copy, and persist for future
# sessions. On upgrade, rename the running exe aside first (the live `cx mcp bridge` holds a
# handle; the old bridge keeps old code until /reload-plugins). Echoes the resolved cx path.
place_windows() {
    local staged="$1" mode="$2" staged_w
    staged_w="$(cygpath -w "$staged")"; staged_w=${staged_w//\'/\'\'}
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
\$ErrorActionPreference = 'Stop'
\$staged = '$staged_w'
\$mode   = '$mode'
\$store  = Join-Path \$env:LOCALAPPDATA 'Checkmarx\\cx'
New-Item -ItemType Directory -Force -Path \$store | Out-Null
Copy-Item \$staged (Join-Path \$store 'cx.exe') -Force

if (\$mode -eq 'upgrade') {
    \$existing = (Get-Command cx -ErrorAction SilentlyContinue).Source
    if (\$existing) {
        \$old = \$existing + '.old'
        if (Test-Path \$old) { Remove-Item \$old -Force -ErrorAction SilentlyContinue }
        Rename-Item \$existing \$old -Force -ErrorAction SilentlyContinue
        Copy-Item \$staged \$existing -Force
        Write-Output \$existing
        exit 0
    }
}

# install (or upgrade with no resolvable existing path): drop into first writable on-PATH dir.
\$target = \$env:PATH -split ';' |
  Where-Object { \$_ -and (Test-Path \$_) -and (\$_ -notlike '*\\WindowsApps') } |
  Where-Object {
    try { \$p = Join-Path \$_ ('.cxw_' + [guid]::NewGuid()); New-Item \$p -ItemType File -Force -EA Stop | Out-Null; Remove-Item \$p -Force; \$true } catch { \$false }
  } | Select-Object -First 1
# Persist the canonical store on the USER PATH for FUTURE sessions (idempotent; does not
# affect THIS session, which already captured its PATH). Read AND write the User scope ONLY
# via the .NET API — never \$env:PATH (the merged System+User+session copy) with setx, which
# truncates at 1024 chars and permanently folds System entries into the User PATH.
\$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if (-not \$userPath) { \$userPath = '' }
if ((\$userPath -split ';' | Where-Object { \$_ }) -notcontains \$store) {
    \$newPath = (\$userPath.TrimEnd(';') + ';' + \$store).Trim(';')
    [Environment]::SetEnvironmentVariable('PATH', \$newPath, 'User')
}
if (\$target) {
    Copy-Item \$staged (Join-Path \$target 'cx.exe') -Force
    Write-Output (Join-Path \$target 'cx.exe')
} else {
    # No writable on-PATH dir: report the canonical store copy (now on the User PATH).
    Write-Output (Join-Path \$store 'cx.exe')
}
" | tr -d '\r'
}

invalidate_version_cache() {
    rm -f "$VERSION_CACHE_FILE" 2>/dev/null || true
}

verify() {
    local cx_path="$1" min="$2" out parsed cx_bin
    # Prefer the just-placed binary; fall back to PATH resolution.
    if [[ -n "$cx_path" && -x "$cx_path" ]]; then
        out="$("$cx_path" version 2>&1 || true)"; cx_bin="$cx_path"
    else
        out="$(cx version 2>&1 || true)"; cx_bin="cx"
    fi
    if [[ "$out" =~ ([0-9]+\.[0-9]+\.[0-9]+) ]]; then
        parsed="${BASH_REMATCH[1]}"
        [[ "$(version_ge "$parsed" "$min")" == "ok" ]] \
            || die "placed cx reports $parsed, still below required $min — check the release asset."
    elif printf '%s' "$out" | grep -qiw dev; then
        : # dev build — numeric gate bypassed
    else
        die "could not verify cx version after placement. Output was: $out"
    fi
    # CAPABILITY check — a numeric/dev match does NOT guarantee the agent-security subcommands
    # exist: a PUBLIC min-version build can still lack `cx mcp bridge` / `cx hooks claude-*`. Without
    # this check the bootstrap would report SUCCESS, then the fail-closed gate would classify cx
    # 'incapable' and block every tool call with no obvious cause. Fail LOUDLY here instead.
    "$cx_bin" mcp bridge --help >/dev/null 2>&1 \
        || die "placed cx is missing 'cx mcp bridge' — this build cannot run the remediation MCP. \
A capability-complete cx release is required (the public release may predate it; see scripts/cx-min-version)."
    "$cx_bin" hooks claude-pre-tool-use --help >/dev/null 2>&1 \
        || die "placed cx is missing 'cx hooks claude-pre-tool-use' — this build cannot run the \
security scanner. A capability-complete cx release is required."
    log "Verified cx version + capability after placement."
    return 0
}

main() {
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
    ensure_rosetta_if_needed

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
    log "Mode: $mode  |  asset: $ASSET  |  min version: $min"

    # Resolve the release tag ONCE and thread it through download + checksum (TOCTOU-safe).
    local staged resolved="" tag
    tag="$(resolve_latest_tag)" || tag=""
    staged="$(download_and_extract "$tag")"

    if [[ "$OS" == "windows" ]]; then
        resolved="$(place_windows "$staged" "$mode")"
    elif [[ "$mode" == "upgrade" ]]; then
        resolved="$(upgrade_unix "$staged")"
    else
        resolved="$(install_unix "$staged")"
    fi

    invalidate_version_cache
    verify "$resolved" "$min"

    log ""
    log "Done. cx is in place at: ${resolved:-<on PATH>}"
    log "Activation:"
    if command -v cx >/dev/null 2>&1; then
        log "  - The security hooks re-resolve cx on their next run — your next tool call is gated live."
        log "  - For the Checkmarx remediation MCP, run /reload-plugins (re-spawns the cx mcp bridge)."
    else
        log "  - cx was placed on your USER PATH but THIS running session cannot see it yet."
        log "    FULLY RESTART Claude Code (close and reopen) to activate the gate and the MCP —"
        log "    /reload-plugins alone will NOT pick it up until the new PATH is in the environment."
    fi
    if [[ "$OS" == "windows" ]]; then
        log "  - A canonical copy was saved to %LOCALAPPDATA%\\Checkmarx\\cx and added to PATH for future sessions."
    fi
}

# Run only when executed directly — not when sourced (e.g. by scripts/test_cx_bootstrap.sh).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
