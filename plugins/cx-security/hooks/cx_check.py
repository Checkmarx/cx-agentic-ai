"""Shared helper: checks if the cx CLI is installed and authenticated before running any scan."""

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request


# GitHub releases is the direct-download fallback for all platforms.
# On macOS, Homebrew is the primary install method, but if brew is unavailable
# the skill falls back to downloading from GitHub. Checking GitHub reachability
# is therefore a valid proxy for "can the CLI be installed right now" on all platforms.
_INSTALL_SOURCE = "https://github.com/Checkmarx/ast-cli/releases"
_INSTALL_SOURCE_TIMEOUT = 5
# Keep auth validation fast: no retries, short network timeout.
_AUTH_VALIDATE_CMD = ["cx", "auth", "validate", "--retry", "0", "--timeout", "5s"]

_AUTH_CACHE_FILE = os.path.join(tempfile.gettempdir(), "cx_auth_cache")
_AUTH_CACHE_TTL = 30 * 60  # 30 minutes


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


def _auth_cache_valid():
    try:
        mtime = os.path.getmtime(_AUTH_CACHE_FILE)
        return (time.time() - mtime) < _AUTH_CACHE_TTL
    except OSError:
        return False


def _write_auth_cache():
    try:
        with open(_AUTH_CACHE_FILE, "w") as f:
            f.write(str(time.time()))
    except OSError:
        pass


def _is_authenticated():
    """Return True if cx can reach and authenticate with Checkmarx One."""
    if _auth_cache_valid():
        return True
    try:
        result = subprocess.run(
            _AUTH_VALIDATE_CMD,
            capture_output=True,
            timeout=10,
        )
        if result.returncode == 0:
            _write_auth_cache()
            return True
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _deny(reason: str, context: str) -> None:
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
            "additionalContext": context,
        }
    }
    print(json.dumps(output))
    sys.exit(2)


def _allow_with_warning(context: str) -> None:
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "additionalContext": context,
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def cx_check():
    if shutil.which("cx") is None:
        if _can_reach_install_source():
            _deny(
                reason=(
                    "The Checkmarx CLI (cx) is not installed. "
                    "Run /cx-cli-setup to install, configure, and authenticate it, then retry."
                ),
                context=(
                    "cx CLI is not installed on this machine and the installation source is reachable. "
                    "IMMEDIATELY invoke the cx-cli-setup skill (via /cx-cli-setup) "
                    "to guide the user through installation, configuration, and authentication. "
                    "All agent actions remain blocked until setup completes successfully."
                ),
            )
        else:
            _allow_with_warning(
                context=(
                    "WARNING: The Checkmarx One CLI (cx) is not installed, and the installation source "
                    f"({_INSTALL_SOURCE}) could not be reached (offline or restricted network). "
                    "Security scanning is unavailable. This operation will proceed unscanned. "
                    "Once network connectivity is restored, run /cx-cli-setup to install the CLI."
                ),
            )

    if not _is_authenticated():
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is installed but not authenticated. "
                "Run /cx-cli-setup to configure and authenticate, then retry."
            ),
            context=(
                "cx auth validate failed — the CLI could not reach Checkmarx One or credentials are "
                "expired/missing. IMMEDIATELY invoke the cx-cli-setup skill (via /cx-cli-setup) "
                "to re-authenticate. All agent actions remain blocked until authentication succeeds."
            ),
        )

    # cx is installed and authenticated — nothing to block.


if __name__ == "__main__":
    cx_check()
