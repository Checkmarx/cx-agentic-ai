#!/usr/bin/env bash
# install-hooks.sh — wire cx-devassist-cursor into Cursor's user/project hooks.
#
# Writes ~/.cursor/hooks.json (visible in Cursor Settings → Hooks) with absolute
# paths to this plugin. The template uses __CURSOR_PLUGIN_ROOT__ as a sed placeholder
# ONLY — never put that literal string in plugin hooks/hooks.json; Cursor does not
# expand it. Plugin hooks.json should use ${CURSOR_PLUGIN_ROOT} (runtime injection).
#
#   bash /plugins/cursor-devassist/scripts/install-hooks.sh
#
# Optional:
#   CX_CURSOR_HOOKS_TARGET=project  → write .cursor/hooks.json in cwd
#   CX_PLUGIN_ROOT=/path/to/plugin  → override plugin root detection
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="${CX_PLUGIN_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
TEMPLATE="$PLUGIN_ROOT/hooks/hooks.json.template"

if [[ ! -f "$TEMPLATE" ]]; then
  printf 'ERROR: missing template: %s\n' "$TEMPLATE" >&2
  exit 1
fi

_plugin_root="${PLUGIN_ROOT//\\//}"
rendered="$(sed "s|__CURSOR_PLUGIN_ROOT__|$_plugin_root|g" "$TEMPLATE")"

if [[ "${CX_CURSOR_HOOKS_TARGET:-user}" == "project" ]]; then
  target_dir="$(pwd)/.cursor"
  target="$target_dir/hooks.json"
else
  target_dir="${HOME}/.cursor"
  target="$target_dir/hooks.json"
fi

mkdir -p "$target_dir"
if [[ -f "$target" ]]; then
  cp "$target" "${target}.bak"
  printf 'Backed up existing hooks to %s.bak\n' "$target" >&2
fi

printf '%s\n' "$rendered" > "$target"
printf 'Installed Cursor user hooks: %s\n' "$target" >&2

printf 'Plugin root: %s\n' "$PLUGIN_ROOT" >&2
printf 'Reload Cursor (Developer: Reload Window), then check Settings → Hooks and the Hooks output channel.\n' >&2
