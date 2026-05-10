"""Shared helper: checks if the cx CLI is installed before running any scan."""

import json
import logging
import shutil
import sys
import urllib.request
import urllib.error


# GitHub releases is the direct-download fallback for all platforms.
# On macOS, Homebrew is the primary install method, but if brew is unavailable
# the skill falls back to downloading from GitHub. Checking GitHub reachability
# is therefore a valid proxy for "can the CLI be installed right now" on all platforms.
_INSTALL_SOURCE = "https://github.com/Checkmarx/ast-cli/releases"
_INSTALL_SOURCE_TIMEOUT = 5


def _can_reach_install_source():
    try:
        response = urllib.request.urlopen(_INSTALL_SOURCE, timeout=_INSTALL_SOURCE_TIMEOUT)
        if not (200 <= response.status < 300):
            logging.error("Install source returned HTTP %s", response.status)
            return False
        return True
    except Exception as e:
        logging.error("Could not reach install source: %s", e)
        return False


def cx_check():
    if shutil.which("cx") is not None:
        return  # cx is installed, nothing to do

    if _can_reach_install_source():
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "The Checkmarx CLI (cx) is not installed. "
                    "Run /cx-cli-setup to install, configure, and authenticate it, then retry."
                ),
                "additionalContext": (
                    "cx CLI is not installed on this machine and the installation source is reachable. "
                    "IMMEDIATELY invoke the cx-cli-setup skill (via /cx-cli-setup) "
                    "to guide the user through installation, configuration, and authentication. "
                    "All agent actions remain blocked until setup completes successfully."
                ),
            }
        }
        print(json.dumps(output))
        sys.exit(2)
    else:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "additionalContext": (
                    "WARNING: The Checkmarx One CLI (cx) is not installed, and the installation source "
                    f"({_INSTALL_SOURCE}) could not be reached (offline or restricted network). "
                    "Security scanning is unavailable. This operation will proceed unscanned. "
                    "Once network connectivity is restored, run /cx-cli-setup to install the CLI."
                ),
            }
        }
        print(json.dumps(output))
        sys.exit(0)
