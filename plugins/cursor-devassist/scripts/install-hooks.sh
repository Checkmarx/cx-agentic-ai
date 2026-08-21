#!/usr/bin/env bash
# install-hooks.sh — wire cx-devassist-cursor into Cursor's user/project hooks and rules.
#
# Hooks: writes ~/.cursor/hooks.json (or <repo>/.cursor/hooks.json) by merging the plugin
# template with any existing hooks (see scripts/cx-hooks-merge.py).
#
# Rules: copies plugin rules/*.mdc into ~/.cursor/rules/ (or <repo>/.cursor/rules/), replacing
# only this plugin's own cx-*.mdc files (see scripts/cx-rules-install.py).
#
#   bash /plugins/cursor-devassist/scripts/install-hooks.sh
#
# Optional:
#   CX_CURSOR_HOOKS_TARGET=project  → write under CX_PROJECT_PATH/.cursor/ (hooks + rules)
#   CX_PROJECT_PATH=/path/to/repo   → project scope target dir; defaults to cwd when unset
#   CX_PLUGIN_ROOT=/path/to/plugin  → override plugin root detection
#
# The hooks target is MERGED, not overwritten: any hooks the developer already has for other tools
# are kept as-is; only this plugin's own prior entries are replaced.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="${CX_PLUGIN_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
TEMPLATE="$PLUGIN_ROOT/hooks/hooks.json.template"
MERGE_SCRIPT="$PLUGIN_ROOT/scripts/cx-hooks-merge.py"
RULES_SOURCE="$PLUGIN_ROOT/rules"
RULES_INSTALL_SCRIPT="$PLUGIN_ROOT/scripts/cx-rules-install.py"

if [[ ! -f "$TEMPLATE" ]]; then
  printf 'ERROR: missing template: %s\n' "$TEMPLATE" >&2
  exit 1
fi

if [[ ! -d "$RULES_SOURCE" ]]; then
  printf 'ERROR: missing rules directory: %s\n' "$RULES_SOURCE" >&2
  exit 1
fi

_plugin_root="${PLUGIN_ROOT//\\//}"
rendered="$(sed "s|__CURSOR_PLUGIN_ROOT__|$_plugin_root|g" "$TEMPLATE")"

if [[ "${CX_CURSOR_HOOKS_TARGET:-user}" == "project" ]]; then
  project_path="${CX_PROJECT_PATH:-$(pwd)}"
  target_dir="$project_path/.cursor"
  hooks_target="$target_dir/hooks.json"
  rules_target="$target_dir/rules"
else
  target_dir="${HOME}/.cursor"
  hooks_target="$target_dir/hooks.json"
  rules_target="$target_dir/rules"
fi

mkdir -p "$target_dir"

rendered_tmp="$(mktemp)"
trap 'rm -f "$rendered_tmp"' EXIT
printf '%s\n' "$rendered" > "$rendered_tmp"

# Python discovery mirrors hooks/cx_check.sh and hooks/_cx_bootstrap_match.sh: on Windows,
# `command -v python3` alone is NOT enough — the Microsoft Store App Execution Alias stub is on
# PATH but prints "Python was not found" and exits non-zero. Probe each candidate for a real Py3.
_find_python() {
  for _c in python3 python; do
    if command -v "$_c" >/dev/null 2>&1 && \
       "$_c" -c "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)" >/dev/null 2>&1; then
      printf '%s' "$_c"
      return 0
    fi
  done
  if command -v py >/dev/null 2>&1 && py -3 -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
    printf '%s' "py -3"
    return 0
  fi
  return 1
}

_run_python_script() {
  local _py="$1"
  local _script="$2"
  shift 2
  local _invoke_script _arg _win_arg _new_args=()
  _invoke_script="$_script"
  if command -v cygpath >/dev/null 2>&1; then
    _invoke_script=$(cygpath -w "$_script" 2>/dev/null) || _invoke_script="$_script"
    for _arg in "$@"; do
      case "$_arg" in
        --rendered|--target|--source)
          _new_args+=("$_arg")
          ;;
        --*)
          _new_args+=("$_arg")
          ;;
        *)
          if [[ -e "$_arg" ]]; then
            _win_arg=$(cygpath -w "$_arg" 2>/dev/null) || _win_arg="$_arg"
            _new_args+=("$_win_arg")
          else
            _new_args+=("$_arg")
          fi
          ;;
      esac
    done
    set -- "${_new_args[@]}"
  fi
  PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 \
    $_py "$_invoke_script" "$@"
}

_install_rules_shell_fallback() {
  local _rule _name _dst
  mkdir -p "$rules_target"
  printf 'WARNING: no working Python 3 found — rules install uses plain file copy into %s.\n' \
    "$rules_target" >&2
  for _rule in "$RULES_SOURCE"/cx-*.mdc; do
    [[ -f "$_rule" ]] || continue
    _name=$(basename "$_rule")
    _dst="$rules_target/$_name"
    if [[ -f "$_dst" ]]; then
      cp "$_dst" "${_dst}.bak"
      printf 'Backed up existing rule to %s.bak\n' "$_dst" >&2
    fi
    cp "$_rule" "$_dst"
    printf 'Installed rule: %s\n' "$_dst" >&2
  done
}

_py=""
_py=$(_find_python) || _py=""

# --- Hooks ---
if [[ -n "$_py" ]] && [[ -f "$MERGE_SCRIPT" ]]; then
  _run_python_script "$_py" "$MERGE_SCRIPT" --rendered "$rendered_tmp" --target "$hooks_target"
else
  printf 'WARNING: no working Python 3 found — merge skipped, overwriting %s wholesale.\n' \
    "$hooks_target" >&2
  if [[ -f "$hooks_target" ]]; then
    cp "$hooks_target" "${hooks_target}.bak"
    printf 'Backed up existing hooks to %s.bak\n' "$hooks_target" >&2
  fi
  cp "$rendered_tmp" "$hooks_target"
  printf 'Installed Cursor hooks: %s\n' "$hooks_target" >&2
fi

# --- Rules ---
if [[ -n "$_py" ]] && [[ -f "$RULES_INSTALL_SCRIPT" ]]; then
  _run_python_script "$_py" "$RULES_INSTALL_SCRIPT" --source "$RULES_SOURCE" --target "$rules_target"
else
  _install_rules_shell_fallback
fi

printf 'Plugin root: %s\n' "$PLUGIN_ROOT" >&2
printf 'Hooks target: %s\n' "$hooks_target" >&2
printf 'Rules target: %s\n' "$rules_target" >&2
printf 'Restart your Cursor CLI session so hooks and rules take effect: exit the agent (/exit or Ctrl+C), run agent again in this directory, or close and reopen the terminal.\n' >&2
