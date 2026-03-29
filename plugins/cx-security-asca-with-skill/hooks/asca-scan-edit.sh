#!/usr/bin/env bash
# PreToolUse hook for Edit tool.
# Runs ASCA scan before and after the edit, reports only new/changed vulnerabilities.

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)

if [[ -z "$FILE_PATH" || ! -f "$FILE_PATH" ]]; then
  exit 0
fi

CX="cx"
TMP_DIR="/tmp/asca-edit-$(uuidgen)"
mkdir -p "$TMP_DIR"
EXT="${FILE_PATH##*.}"

INPUT_FILE="${TMP_DIR}/input.json"
EDITED_FILE="${TMP_DIR}/edited.${EXT}"
SCAN_OLD_FILE="${TMP_DIR}/scan_old.json"
SCAN_NEW_FILE="${TMP_DIR}/scan_new.json"
DELTA_FILE="${TMP_DIR}/delta.json"

printf '%s' "$INPUT" > "$INPUT_FILE"

# Scan 1: original file (baseline)
"$CX" scan asca -s "$FILE_PATH" > "$SCAN_OLD_FILE" 2>/dev/null \
  || echo '{"scan_details":[]}' > "$SCAN_OLD_FILE"

# Build edited file by applying old_string -> new_string
INPUT_FILE="$INPUT_FILE" EDITED_FILE="$EDITED_FILE" SRC_FILE="$FILE_PATH" \
python3 <<'PYEOF'
import json, os, sys
data = json.load(open(os.environ['INPUT_FILE']))
old = data['tool_input'].get('old_string', '')
new = data['tool_input'].get('new_string', '')
if not old:
    sys.exit(0)
content = open(os.environ['SRC_FILE'], 'r', encoding='utf-8').read()
open(os.environ['EDITED_FILE'], 'w', encoding='utf-8').write(content.replace(old, new, 1))
PYEOF

if [[ ! -s "$EDITED_FILE" ]]; then
  rm -rf "$TMP_DIR"
  exit 0
fi

# Scan 2: edited file
"$CX" scan asca -s "$EDITED_FILE" > "$SCAN_NEW_FILE" 2>/dev/null \
  || echo '{"scan_details":[]}' > "$SCAN_NEW_FILE"

# Compare: delta = vulns in new scan with no exact match (rule_id + problematicLine) in old scan
SCAN_OLD_FILE="$SCAN_OLD_FILE" SCAN_NEW_FILE="$SCAN_NEW_FILE" DELTA_FILE="$DELTA_FILE" \
python3 <<'PYEOF'
import json, os

old_vulns = (json.load(open(os.environ['SCAN_OLD_FILE'])).get('scan_details') or [])
new_vulns = (json.load(open(os.environ['SCAN_NEW_FILE'])).get('scan_details') or [])

old_set = {(v['rule_id'], v.get('problematicLine', '').strip()) for v in old_vulns}

delta = [v for v in new_vulns
         if (v['rule_id'], v.get('problematicLine', '').strip()) not in old_set]

json.dump(delta, open(os.environ['DELTA_FILE'], 'w'))
PYEOF

DELTA=$(cat "$DELTA_FILE")
rm -rf "$TMP_DIR"

SCAN_OUTPUT=$(echo "$DELTA" | jq '{scan_details: .}' 2>/dev/null || echo '{"scan_details":[]}')

exec "$(dirname "$0")/asca-block.sh" "$FILE_PATH" "$SCAN_OUTPUT"
