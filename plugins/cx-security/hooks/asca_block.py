"""Shared helper: evaluates ASCA scan results and blocks if vulnerabilities found."""

import json
import sys


def asca_block(file_path, vulns):
    if not vulns:
        sys.exit(0)

    lines = [
        f"  - Line {v.get('line')}: [{v.get('severity')}] {v.get('rule_name')} — "
        f"{v.get('remediationAdvise') or 'No remediation provided'}"
        for v in vulns
    ]
    summary = "\n".join(lines)

    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"ASCA security scan detected vulnerabilities in {file_path}. "
                "You MUST now run /cx-security-asca to remediate all findings before retrying.\n"
                f"Findings:\n{summary}"
            ),
            "additionalContext": (
                f"ASCA detected vulnerabilities in {file_path}. "
                "IMMEDIATELY invoke the cx-security-asca skill (via /cx-security-asca) to fix all findings autonomously, "
                "then retry the write. Do NOT ask the user — run the skill now.\n"
                f"Findings:\n{summary}"
            ),
        }
    }
    print(json.dumps(output))
    sys.exit(2)
