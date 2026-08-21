#!/usr/bin/env bash
# Contract test: the Python gate (_cx_exe) and the sh wrapper (cx_run.sh) MUST resolve cx to the SAME
# tier for the SAME environment (precedence: CX_BINARY -> canonical store -> PATH). The A2 fail-open
# this session was exactly these two adapters drifting; this test holds the seam so future drift
# breaks CI instead of shipping as a silent fail-open. Run: bash tests/scripts/test_cx_resolution_contract.sh
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS="$DIR/../../plugins/copilot-devassist/hooks"
CXRUN="$HOOKS/cx_run.sh"
# Pick a Python 3 (mirrors run-tests.sh / cx_check.sh — a python2 `python` would SyntaxError on
# cx_check.py's Py3-only syntax and spuriously fail every case).
PY=""
for _cand in python3 python; do
    if command -v "$_cand" >/dev/null 2>&1 \
       && "$_cand" -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' >/dev/null 2>&1; then
        PY="$(command -v "$_cand")"; break   # absolute path — it runs under the tests' restricted PATH
    fi
done

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$1"; }

if [[ -z "$PY" ]]; then printf 'skip - no python 3 found\n'; exit 0; fi

# Windows Python cannot import from a Git-Bash `/c/...` path — hand it a native path.
HOOKS_PY="$(cygpath -w "$HOOKS" 2>/dev/null || printf '%s' "$HOOKS")"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# OS-appropriate canonical store path (must match _canonical_cx / canonical_cx). Sandboxed via HOME
# and LOCALAPPDATA so both adapters look at OUR temp store, not the real one.
case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*) CANON="$tmp/store/Checkmarx/cx/cx.exe" ;;
    *)                    CANON="$tmp/home/.checkmarx/bin/cx" ;;
esac

make_stub() { mkdir -p "$(dirname "$1")"; printf '#!/bin/sh\necho %s\n' "$2" > "$1"; chmod +x "$1"; }

pathdir="$tmp/pathbin"; make_stub "$pathdir/cx" PATH
binfile="$tmp/cxbinary";  make_stub "$binfile" BINARY

# For one env (CX_BINARY, canonical present?, PATH cx present?), resolve via BOTH adapters and compare
# the tier they choose. sh: cx_run.sh execs the resolved stub, which echoes its tier. py: _cx_exe()
# returns a path we map to a tier.
contract() {
    local desc="$1" cxbin="$2" canon="$3" onpath="$4" expect="$5"
    rm -rf "$tmp/store" "$tmp/home"; mkdir -p "$tmp/home"
    [[ "$canon" == 1 ]] && make_stub "$CANON" CANONICAL
    local penv="/usr/bin:/bin"
    [[ "$onpath" == 1 ]] && penv="$pathdir:$penv"

    local sh_tier py_path py_tier
    sh_tier="$(CX_BINARY="$cxbin" HOME="$tmp/home" LOCALAPPDATA="$tmp/store" PATH="$penv" \
               sh "$CXRUN" version 2>/dev/null | head -1)"
    py_path="$(CX_BINARY="$cxbin" HOME="$tmp/home" LOCALAPPDATA="$tmp/store" PATH="$penv" \
               "$PY" -c "import sys;sys.path.insert(0,r'$HOOKS_PY');import cx_check;print(cx_check._cx_exe())" 2>/dev/null)"
    # Map by tier marker (path forms differ across MSYS/Windows): _cx_exe returns the bare literal 'cx'
    # for the PATH tier, the CX_BINARY path (distinctive basename 'cxbinary') for BINARY, else the
    # canonical-store abs path for CANONICAL.
    if [[ -z "$py_path" ]]; then py_tier=ERROR
    elif [[ "$py_path" == "cx" ]]; then py_tier=PATH
    elif [[ "$py_path" == *cxbinary* ]]; then py_tier=BINARY
    else py_tier=CANONICAL; fi

    if [[ "$sh_tier" == "$expect" && "$py_tier" == "$expect" ]]; then
        ok "$desc — both chose $expect"
    else
        bad "$desc — expected $expect, sh=$sh_tier py=$py_tier (py_path=$py_path)"
    fi
}

#         description                         CX_BINARY   canon  onPATH  expect
contract "CX_BINARY wins over all"            "$binfile"  1      1       BINARY
contract "CX_BINARY wins even when alone"     "$binfile"  0      0       BINARY
contract "canonical store over PATH"          ""          1      1       CANONICAL
contract "PATH last resort"                   ""          0      1       PATH

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
