"""Shared bootstrap and fixtures for the cx_check gate test suites.

Dependency-free (stdlib only). Not named test_*, so unittest discovery skips it; the suites import
it via the tests directory that discovery puts on sys.path.
"""

import json
import os
import sys
import tempfile
import unittest

# Import the shipped gate modules from the plugin's hooks/ directory (repo root is one level up).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOOKS_DIR = os.path.join(_REPO_ROOT, "plugins", "cx-devassist", "hooks")
sys.path.insert(0, _HOOKS_DIR)
import cx_check  # noqa: E402
import cx_log  # noqa: E402

# Keep unit-test _log calls out of the developer's real audit log. A test that needs a real write
# re-enables logging itself.
os.environ.setdefault("CX_LOG_DISABLE", "1")

_URL_EU = "https://eu.ast.checkmarx.net"
_URL_US = "https://ast.checkmarx.net"
_URL_ANZ = "https://anz.ast.checkmarx.net"
_URL_IND = "https://ind.ast.checkmarx.net"

_HOME = os.path.expanduser("~")
# A pin under the home dir so the documented "$HOME/.checkmarx/bin/cx" spelling can resolve to it.
_PIN = os.path.join(_HOME, ".checkmarx", "bin", "cx")


def _bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def _pwsh(cmd):
    return {"tool_name": "PowerShell", "tool_input": {"command": cmd}}


class _HistoryFileMixin(unittest.TestCase):
    """A fresh temp history path per test, plus a _credential_mtime override hook. Cooperative
    (calls super().setUp/tearDown) so it can be combined with other mixins."""

    def setUp(self):
        super().setUp()
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(self.path)  # functions must cope with a not-yet-existing file
        self._orig_cred_mtime = cx_check._credential_mtime
        self._set_cred_mtime(1000.0)  # hermetic default; tests override as needed

    def tearDown(self):
        cx_check._credential_mtime = self._orig_cred_mtime
        if os.path.exists(self.path):
            os.unlink(self.path)
        super().tearDown()

    def _set_cred_mtime(self, value):
        cx_check._credential_mtime = lambda: value

    def _write_raw(self, obj):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))

    def _entries(self, *rows):
        """[(url, tenant, status, last_used[, cred_before]), ...] → on-disk history file."""
        payload = []
        for row in rows:
            entry = {"base_auth_uri": row[0], "tenant": row[1],
                     "status": row[2], "last_used": row[3]}
            if len(row) > 4:
                entry["cred_before"] = row[4]
            payload.append(entry)
        self._write_raw({"version": 1, "entries": payload})


class _PinnedCxMixin(unittest.TestCase):
    """Pin the gate's resolved cx (and canonical store) to known paths for the duration.
    Patches _cx_exe_with_tier — the single resolution root _cx_exe and _pinned_cx_paths both
    delegate to — so every consumer sees the same pin. Cooperative like _HistoryFileMixin."""

    def setUp(self):
        super().setUp()
        self._orig_cx_tier = cx_check._cx_exe_with_tier
        self._orig_canonical = cx_check._canonical_cx
        self._pin_cx(_PIN)
        cx_check._canonical_cx = lambda: None

    def tearDown(self):
        cx_check._cx_exe_with_tier = self._orig_cx_tier
        cx_check._canonical_cx = self._orig_canonical
        super().tearDown()

    def _pin_cx(self, exe, tier="binary"):
        cx_check._cx_exe_with_tier = lambda: (exe, tier)
