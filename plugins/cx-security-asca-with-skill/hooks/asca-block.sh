#!/usr/bin/env bash
# Shared helper: evaluates ASCA scan output and blocks if vulnerabilities found.
# Usage: asca-block.sh <file_path> <scan_output_json>

FILE_PATH="$1"
SCAN_OUTPUT="$2"

VULN_COUNT=$(echo "$SCAN_OUTPUT" | jq '(.scan_details // []) | length' 2>/dev/null || echo "0")

if [[ "$VULN_COUNT" -gt 0 ]]; then
  VULN_SUMMARY=$(echo "$SCAN_OUTPUT" | jq -r '
    (.scan_details // []) |
    map("  - Line \(.line): [\(.severity)] \(.rule_name) — \(.remediationAdvise // "No remediation provided")") |
    join("\n")
  ' 2>/dev/null || echo "  (could not parse vulnerability details)")

  jq -n \
    --arg summary "$VULN_SUMMARY" \
    --arg path "$FILE_PATH" \
    '{
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": ("ASCA security scan detected vulnerabilities in " + $path + ". You MUST now run /cx-security-asca to remediate all findings before retrying.\nFindings:\n" + $summary),
        "additionalContext": ("ASCA detected vulnerabilities in " + $path + ". IMMEDIATELY invoke the cx-security-asca skill (via /cx-security-asca) to fix all findings autonomously, then retry the write. Do NOT ask the user — run the skill now.\nFindings:\n" + $summary)
      }
    }'

  exit 2
fi

exit 0
