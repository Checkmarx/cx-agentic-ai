import pathlib
script = """#!/usr/bin/env bash
set -u
run_one() {
  local name="$1" script="$2" json="$3"
  if [[ ! -f "$script" ]]; then
    echo "=== $name ==="
    echo "script: $script"
    echo "status: FILE_NOT_FOUND"
    echo ""
    return
  fi
  local start end out ec ms
  start=$(python -c "import time; print(time.perf_counter())")
  out=$(printf '%s' "$json" | sh "$script" 2>&1)
  ec=$?
  end=$(python -c "import time; print(time.perf_counter())")
  ms=$(python -c "print(int(($end - $start) * 1000))")
  perm=$(printf '%s' "$out" | grep -oE '"permission"[[:space:]]*:[[:space:]]*"(allow|deny)"' | head -1)
  echo "=== $name ==="
  echo "script: $script"
  echo "permission: ${perm:-UNKNOWN}"
  echo "exit_code: $ec"
  echo "elapsed_ms: $ms"
  echo "output:"
  printf '%s\n' "$out"
  echo ""
}

JSON1='{"tool_name":"Shell","tool_input":{"command":"& \\"C:\\\\\\\\Users\\\\\\\\kedarb\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Checkmarx\\\\\\\\cx\\\\\\\\cx.exe\\" auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant cx_seg 1>$null","cwd":"","timeout":300000},"hook_event_name":"preToolUse","cwd":""}'
JSON2='{"tool_name":"Shell","tool_input":{"command":"& \\"C:\\\\\\\\Users\\\\\\\\kedarb\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Checkmarx\\\\\\\\cx\\\\\\\\cx.exe\\" auth validate","cwd":"","timeout":30000},"hook_event_name":"preToolUse","cwd":""}'
INST="/c/Users/kedarb/.cursor/plugins/local/cursor-devassist/hooks/cx_check.sh"
REPO="/c/AST/Repos/cx-agentic-ai/plugins/cursor-devassist/hooks/cx_check.sh"

echo "--- grep _CX_HOOK_INPUT_FILE (installed) ---"
grep -n "_CX_HOOK_INPUT_FILE" "$INST" 2>&1 || echo "(no file or no matches)"
echo "--- grep _CX_HOOK_INPUT_FILE (repo) ---"
grep -n "_CX_HOOK_INPUT_FILE" "$REPO" 2>&1
echo "--- diff (first 25 lines) ---"
diff -u "$INST" "$REPO" 2>&1 | head -25
echo ""

run_one "INSTALLED: auth login with 1>\\$null" "$INST" "$JSON1"
run_one "INSTALLED: auth validate" "$INST" "$JSON2"
run_one "REPO: auth login with 1>\\$null" "$REPO" "$JSON1"
run_one "REPO: auth validate" "$REPO" "$JSON2"
"""
pathlib.Path(r"c:/AST/Repos/cx-agentic-ai/tests/_run_cx_check_win.sh").write_text(script, newline="\n")
print("ok")
