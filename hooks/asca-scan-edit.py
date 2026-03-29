#!/usr/bin/env python3
"""PreToolUse hook for Edit tool. Scans only new/changed vulnerabilities introduced by the edit."""

import json
import os
import subprocess
import sys
import tempfile
import uuid
import shutil

CX = "cx"


def scan_file(path):
    result = subprocess.run(
        [CX, "scan", "asca", "-s", path],
        capture_output=True, text=True
    )
    try:
        return json.loads(result.stdout.strip()).get("scan_details") or []
    except (json.JSONDecodeError, AttributeError):
        return []


def asca_block(file_path, vulns):
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


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    file_path = data.get("tool_input", {}).get("file_path", "")
    old_string = data.get("tool_input", {}).get("old_string", "")
    new_string = data.get("tool_input", {}).get("new_string", "")

    if not file_path or not os.path.isfile(file_path) or not old_string:
        sys.exit(0)

    ext = os.path.splitext(file_path)[1]
    tmp_dir = os.path.join(tempfile.gettempdir(), f"asca-edit-{uuid.uuid4().hex}")
    os.makedirs(tmp_dir, exist_ok=True)

    try:
        edited_file = os.path.join(tmp_dir, f"edited{ext}")

        with open(file_path, "r", encoding="utf-8") as f:
            original = f.read()

        if old_string not in original:
            sys.exit(0)

        edited = original.replace(old_string, new_string, 1)
        with open(edited_file, "w", encoding="utf-8") as f:
            f.write(edited)

        old_vulns = scan_file(file_path)
        new_vulns = scan_file(edited_file)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    old_set = {(v["rule_id"], (v.get("problematicLine") or "").strip()) for v in old_vulns}
    delta = [v for v in new_vulns if (v["rule_id"], (v.get("problematicLine") or "").strip()) not in old_set]

    asca_block(file_path, delta)


if __name__ == "__main__":
    main()
