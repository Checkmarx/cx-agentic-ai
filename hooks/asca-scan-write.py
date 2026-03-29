#!/usr/bin/env python3
"""PreToolUse hook for Write tool. Scans content before writing."""

import json
import os
import subprocess
import sys
import tempfile
import uuid

CX = "cx"
HOOK_DIR = os.path.dirname(os.path.abspath(__file__))


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    file_path = data.get("tool_input", {}).get("file_path", "")
    content = data.get("tool_input", {}).get("content", "")

    if not file_path or not content:
        sys.exit(0)

    ext = os.path.splitext(file_path)[1]
    tmp_dir = os.path.join(tempfile.gettempdir(), f"asca-write-{uuid.uuid4().hex}")
    os.makedirs(tmp_dir, exist_ok=True)

    try:
        tmp_file = os.path.join(tmp_dir, f"scan{ext}")
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(content)

        result = subprocess.run(
            [CX, "scan", "asca", "-s", tmp_file],
            capture_output=True, text=True
        )
        scan_output = result.stdout.strip() or '{"scan_details":[]}'
    finally:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)

    try:
        scan_data = json.loads(scan_output)
    except json.JSONDecodeError:
        scan_data = {"scan_details": []}

    asca_block(file_path, scan_data)


def asca_block(file_path, scan_data):
    vulns = scan_data.get("scan_details") or []
    if not vulns:
        sys.exit(0)

    lines = [
        f"  - Line {v.get('line')}: [{v.get('severity')}] {v.get('rule_name')} — "
        f"{v.get('remediationAdvise') or 'No remediation provided'}"
        for v in vulns
    ]
    summary = "\n".join(lines)
    reason = (
        f"ASCA security scan detected vulnerabilities in {file_path}. "
        "You MUST fix the following vulnerabilities and retry the edit automatically. "
        "Do NOT ask the user for approval — fix them silently and proceed:\n"
        + summary
    )

    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(output))
    sys.exit(2)


if __name__ == "__main__":
    main()