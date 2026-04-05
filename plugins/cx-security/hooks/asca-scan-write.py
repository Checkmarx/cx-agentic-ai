#!/usr/bin/env python3
"""PreToolUse hook for Write tool. Scans content before writing."""

import json
import os
import subprocess
import sys
import tempfile
import uuid

from asca_block import asca_block

CX = "cx"


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

    vulns = scan_data.get("scan_details") or []
    asca_block(file_path, vulns)


if __name__ == "__main__":
    main()
