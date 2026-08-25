sudo bash <<'EOF'
set -euo pipefail

CONFIG_DIR="/Library/Application Support/ClaudeCode"
CONFIG_FILE="${CONFIG_DIR}/managed-settings.json"
TMP_OUT=""
PY_ERR=""
BACKUP_FILE=""

cleanup() {
  [[ -n "$TMP_OUT" && -f "$TMP_OUT" ]] && rm -f "$TMP_OUT"
  [[ -n "$PY_ERR" && -f "$PY_ERR" ]] && rm -f "$PY_ERR"
}
trap cleanup EXIT

fail() {
  echo "FAILED: $*"
  exit 1
}

if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 is required but was not found."
fi

mkdir -p "$CONFIG_DIR"

# Create a backup if the configuration file already exists.
if [[ -f "$CONFIG_FILE" ]]; then
  BACKUP_FILE="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
  cp -p "$CONFIG_FILE" "$BACKUP_FILE"
  echo "Backup created: $BACKUP_FILE"
fi

TMP_OUT="$(mktemp)"
PY_ERR="$(mktemp)"

if ! python3 - "$CONFIG_FILE" "$TMP_OUT" 2>"$PY_ERR" <<'PY'
import json
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])

if config_path.exists():
    raw = config_path.read_text(encoding="utf-8")
    if raw.strip():
        config = json.loads(raw)
        if not isinstance(config, dict):
            raise SystemExit("managed-settings.json must be a JSON object.")
    else:
        config = {}
else:
    config = {}

marketplaces = config.setdefault("extraKnownMarketplaces", {})
plugins = config.setdefault("enabledPlugins", {})

marketplaces["cx-devassist-marketplace"] = {
    "source": {
        "source": "github",
        "repo": "Checkmarx/cx-agentic-ai"
    }
}

plugins["cx-devassist@cx-devassist-marketplace"] = True

out_path.write_text(
    json.dumps(config, indent=2) + "\n",
    encoding="utf-8"
)
PY
then
    cat "$PY_ERR"
    exit 1
fi

install -m 644 -o root -g wheel "$TMP_OUT" "$CONFIG_FILE"

echo "SUCCESS: managed-settings.json updated successfully."

if [[ -n "$BACKUP_FILE" ]]; then
  echo "Backup saved at: $BACKUP_FILE"
fi
EOF