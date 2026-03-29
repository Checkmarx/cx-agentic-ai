#!/usr/bin/env bash
# PreToolUse hook for Write tool.
# Scans content by writing to a temp file (avoids --raw-content ARG_MAX limits).

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
RAW_CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // empty' 2>/dev/null)

if [[ -z "$FILE_PATH" || -z "$RAW_CONTENT" ]]; then
  exit 0
fi

CX="cx"
EXT="${FILE_PATH##*.}"
TMP_DIR="/tmp/asca-write-$(uuidgen)"
mkdir -p "$TMP_DIR"
TMP_FILE="${TMP_DIR}/scan.${EXT}"
trap 'rm -rf "$TMP_DIR"' EXIT
printf '%s' "$RAW_CONTENT" > "$TMP_FILE"

SCAN_OUTPUT=$("$CX" scan asca -s "$TMP_FILE" 2>/dev/null || true)

exec "$(dirname "$0")/asca-block.sh" "$FILE_PATH" "$SCAN_OUTPUT"
