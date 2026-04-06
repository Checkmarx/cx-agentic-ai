"""Shared helper: checks if the cx CLI is installed before running any scan."""

import json
import shutil
import sys


def cx_check():
    if shutil.which("cx") is not None:
        return  # cx is installed, nothing to do

    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "The Checkmarx CLI (cx) is not installed. "
                "Run /cx-cli-setup to get installation instructions, then retry."
            ),
            "additionalContext": (
                "cx CLI is not installed on this machine. "
                "IMMEDIATELY invoke the cx-cli-setup skill (via /cx-cli-setup) "
                "to show the user how to install it. "
                "Once the user confirms installation is complete, retry the original operation."
            ),
        }
    }
    print(json.dumps(output))
    sys.exit(2)
