#!/usr/bin/env bash
# Copy (or symlink) this plugin from the repo into Cursor's local plugin directory.
#
# Usage (from anywhere):
#   bash /plugins/cursor-devassist/scripts/sync-local-plugin.sh
#   bash /plugins/cursor-devassist/scripts/sync-local-plugin.sh --symlink
#
# After sync: Developer → Reload Window in Cursor (or restart Cursor).

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PLUGIN_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
MODE=copy

if [ "${1:-}" = "--symlink" ]; then
    MODE=symlink
elif [ -n "${1:-}" ]; then
    echo "Usage: $0 [--symlink]" >&2
    exit 2
fi

case "$(uname -s 2>/dev/null)" in
    MINGW* | MSYS* | CYGWIN*)
        if [ -n "${USERPROFILE:-}" ]; then
            DEST="$USERPROFILE/.cursor/plugins/local/cx-devassist-cursor"
        else
            DEST="${HOME:-}/.cursor/plugins/local/cx-devassist-cursor"
        fi
        ;;
    *)
        DEST="${HOME:-}/.cursor/plugins/local/cx-devassist-cursor"
        ;;
esac

mkdir -p "$(dirname "$DEST")"

if [ "$MODE" = symlink ]; then
    rm -rf "$DEST"
    ln -s "$PLUGIN_ROOT" "$DEST"
    echo "Symlinked: $DEST -> $PLUGIN_ROOT"
else
    mkdir -p "$DEST"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete \
            --exclude '__pycache__' \
            --exclude '.git' \
            "$PLUGIN_ROOT/" "$DEST/"
    else
        rm -rf "$DEST"
        cp -R "$PLUGIN_ROOT" "$DEST"
        find "$DEST" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    fi
    echo "Copied plugin to: $DEST"
fi

# Stale bytecode can shadow updated .py hook logic on Windows.
find "$DEST/hooks" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find "$DEST/hooks" -name '*.pyc' -delete 2>/dev/null || true

echo ""
echo "Next steps:"
echo "  1. Developer → Reload Window (or restart Cursor)"
echo "  2. Retry cx auth login — cx_check.sh should allow in <1s (not ~9s deny)"
