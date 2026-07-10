#!/bin/sh
# cx-mcp-guard.sh — shared version + capability decision for anything that is about to run
# `cx mcp bridge`. A small, single-purpose, testable module, POSIX `sh` (no bashisms: no `local`,
# no `[[ ]]`, no arrays) so it can be SOURCED by both:
#   - hooks/cx_run.sh (POSIX `sh`, resolved via Git-Bash's sh.exe on Windows) — before spawning the
#     MCP bridge subprocess declared in .mcp.json.
#   - scripts/cx-bootstrap.sh (bash) — inside verify(), so the install-time and MCP-spawn-time
#     capability decision is the SAME code, not two copies that can drift.
#
# This module makes a DECISION only (ok / below / incapable / unrunnable / dev); it never prints a
# user-facing message or exits the caller's process — callers own their own wording and control flow
# (cx-bootstrap.sh dies loudly at install time; cx_run.sh must NOT die — it has to avoid exec'ing a
# broken subcommand while still leaving stdout clean for the MCP stdio transport).
#
# Uses only `sh`/POSIX-portable tools already required elsewhere in this plugin (sed, grep) — no
# python, no bash-only regex — since a broken guard must never become a NEW cause of MCP failures.

# cx_mcp_parse_semver <text>
#   stdout: the first "MAJOR.MINOR.PATCH" substring found in <text>; return 1 with no output if none.
#   `[^0-9]*` (not `.*[^0-9]`) as the prefix so a BARE version string with no leading text at all
#   (exactly what scripts/cx-min-version contains) still matches — a `.*[^0-9]` prefix would require
#   at least one non-digit character before the version and silently fail on a bare "2.3.54" line.
cx_mcp_parse_semver() {
    _CXMCP_SEMVER=$(printf '%s' "${1:-}" \
        | sed -n 's/[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n 1)
    [ -n "$_CXMCP_SEMVER" ] || return 1
    printf '%s' "$_CXMCP_SEMVER"
}

# cx_mcp_version_ge <have> <want>
#   stdout: "ok" if dotted-triple <have> >= <want>, else "below". Non-numeric/missing components
#   are treated as 0, mirroring cx-bootstrap.sh's own version_ge (kept in lockstep, not duplicated
#   logic — this IS the one copy now).
cx_mcp_version_ge() {
    _CXMCP_HAVE="${1:-0.0.0}"
    _CXMCP_WANT="${2:-0.0.0}"
    _CXMCP_HAVE_MAJ=$(printf '%s' "$_CXMCP_HAVE" | cut -d. -f1)
    _CXMCP_HAVE_MIN=$(printf '%s' "$_CXMCP_HAVE" | cut -d. -f2)
    _CXMCP_HAVE_PAT=$(printf '%s' "$_CXMCP_HAVE" | cut -d. -f3)
    _CXMCP_WANT_MAJ=$(printf '%s' "$_CXMCP_WANT" | cut -d. -f1)
    _CXMCP_WANT_MIN=$(printf '%s' "$_CXMCP_WANT" | cut -d. -f2)
    _CXMCP_WANT_PAT=$(printf '%s' "$_CXMCP_WANT" | cut -d. -f3)
    : "${_CXMCP_HAVE_MAJ:=0}" "${_CXMCP_HAVE_MIN:=0}" "${_CXMCP_HAVE_PAT:=0}"
    : "${_CXMCP_WANT_MAJ:=0}" "${_CXMCP_WANT_MIN:=0}" "${_CXMCP_WANT_PAT:=0}"
    if [ "$_CXMCP_HAVE_MAJ" -gt "$_CXMCP_WANT_MAJ" ] 2>/dev/null; then printf 'ok'; return 0; fi
    if [ "$_CXMCP_HAVE_MAJ" -lt "$_CXMCP_WANT_MAJ" ] 2>/dev/null; then printf 'below'; return 0; fi
    if [ "$_CXMCP_HAVE_MIN" -gt "$_CXMCP_WANT_MIN" ] 2>/dev/null; then printf 'ok'; return 0; fi
    if [ "$_CXMCP_HAVE_MIN" -lt "$_CXMCP_WANT_MIN" ] 2>/dev/null; then printf 'below'; return 0; fi
    if [ "$_CXMCP_HAVE_PAT" -lt "$_CXMCP_WANT_PAT" ] 2>/dev/null; then printf 'below'; return 0; fi
    printf 'ok'
}

# cx_mcp_load_min_version <min_version_file> <fallback>
#   stdout: the first MAJOR.MINOR.PATCH found on the first non-comment, non-blank line of
#   <min_version_file>; <fallback> if the file is missing/unreadable/garbled. Mirrors
#   cx_check.py's _load_min_version / cx-bootstrap.sh's load_min_version — same fail-closed
#   fallback semantics (never silently drop to 0.0.0 = allow-everything). This is the ONE place in
#   this module the fallback constant is hardcoded — cx_mcp_guard_state below passes its own
#   <fallback_min> straight through here rather than repeating the literal, so there is exactly one
#   copy to keep in sync with scripts/cx-min-version (search marker: CX_MIN_VERSION).
cx_mcp_load_min_version() {
    _CXMCP_MINFILE="${1:-}"
    _CXMCP_FALLBACK="${2:-2.3.55}"
    if [ -n "$_CXMCP_MINFILE" ] && [ -r "$_CXMCP_MINFILE" ]; then
        while IFS= read -r _CXMCP_LINE || [ -n "$_CXMCP_LINE" ]; do
            case "$_CXMCP_LINE" in
                ''|'#'*) continue ;;
            esac
            if _CXMCP_PARSED=$(cx_mcp_parse_semver "$_CXMCP_LINE"); then
                printf '%s' "$_CXMCP_PARSED"
                return 0
            fi
            break
        done < "$_CXMCP_MINFILE"
    fi
    printf '%s' "$_CXMCP_FALLBACK"
}

# cx_mcp_capable <cx_exe>
#   return 0 iff `<cx_exe> mcp bridge --help` exits 0 — the same capability probe
#   cx-bootstrap.sh's verify() and cx_check.py's _capabilities_present() already use for the
#   MCP-bridge subcommand specifically.
cx_mcp_capable() {
    "${1:-cx}" mcp bridge --help >/dev/null 2>&1
}

# cx_mcp_guard_state <cx_exe> <min_version_file> [<fallback_min>]
#   stdout: one of "ok" | "dev" | "below" | "incapable" | "unrunnable" — the single decision every
#   caller needs. Never prints a message and never exits; the caller decides what to do with it.
#   Mirrors cx_check.py's _version_state_uncached exactly (numeric floor first, then the REAL gate:
#   the `mcp bridge --help` capability probe — a build can satisfy the numeric floor and still lack
#   the subcommand).
cx_mcp_guard_state() {
    _CXMCP_EXE="${1:-cx}"
    _CXMCP_MINFILE="${2:-}"
    # No hardcoded default here — an empty/omitted <fallback_min> falls through to
    # cx_mcp_load_min_version's own single default, so the constant lives in exactly one place.
    _CXMCP_FALLBACK="${3:-}"
    _CXMCP_OUT=$("$_CXMCP_EXE" version 2>&1)
    _CXMCP_STATUS=$?
    if [ $_CXMCP_STATUS -ne 0 ] && [ -z "$_CXMCP_OUT" ]; then
        printf 'unrunnable'
        return 0
    fi
    if _CXMCP_HAVE=$(cx_mcp_parse_semver "$_CXMCP_OUT"); then
        _CXMCP_MIN=$(cx_mcp_load_min_version "$_CXMCP_MINFILE" "$_CXMCP_FALLBACK")
        if [ "$(cx_mcp_version_ge "$_CXMCP_HAVE" "$_CXMCP_MIN")" = "below" ]; then
            printf 'below'
            return 0
        fi
        _CXMCP_NUMERIC=ok
    elif printf '%s' "$_CXMCP_OUT" | grep -qiw dev; then
        _CXMCP_NUMERIC=dev
    else
        printf 'unrunnable'
        return 0
    fi
    if cx_mcp_capable "$_CXMCP_EXE"; then
        printf '%s' "$_CXMCP_NUMERIC"
    else
        printf 'incapable'
    fi
    return 0
}

# Run directly → decide for the current machine's resolved `cx` (handy for manual troubleshooting).
if [ "${0##*/}" = "cx-mcp-guard.sh" ]; then
    _CXMCP_SELF_DIR=$(cd "$(dirname "$0")" && pwd)
    cx_mcp_guard_state "${1:-cx}" "$_CXMCP_SELF_DIR/cx-min-version"
    printf '\n'
fi
