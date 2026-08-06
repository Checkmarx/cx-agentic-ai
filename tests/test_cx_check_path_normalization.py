"""Regression tests for the Git-Bash POSIX-path bug in cx_check.py's path-equality carve-outs.

On Windows, `os.path.abspath("/c/AST/Repos/x.sh")` does NOT resolve "/c" as drive C: — it treats
the leading "/" as "root of the current drive" and "c" as an ordinary directory name, yielding the
bogus `C:\\c\\AST\\Repos\\x.sh`. But Git-Bash's own `pwd` / `$(dirname "$0")` — which is exactly
what the agent's Shell tool and this plugin's own scripts run under on Windows — naturally produce
paths in THAT POSIX form. Every path-equality carve-out in cx_check.py (the bootstrap install
command, the `cx auth`/`cx configure` recovery commands, and `cx version`/`cx utils env` setup
diagnostics) compares a path the agent's shell resolved against a path Python resolved, so this
silently broke all of them whenever the agent supplied a POSIX-style path — including the exact
documented bootstrap recovery command copied verbatim from a deny message.

Loads cx_check.py via importlib under a private module name (not the bare "cx_check" that
test_cx_check_admin_config.py uses for the sibling Claude plugin) so the two test files can never
collide in sys.modules regardless of run order.

Run from the repo root:  python -m unittest discover -s tests -v
"""

import importlib.util
import os
import sys
import unittest


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CX_CHECK_PATH = os.path.join(
    _REPO_ROOT, "plugins", "cx-devassist-cursor", "hooks", "cx_check.py"
)

_spec = importlib.util.spec_from_file_location("cx_check_cursor_pathnorm", _CX_CHECK_PATH)
cx_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cx_check)


def _to_gitbash_posix(windows_path):
    """`C:\\AST\\Repos\\x.sh` -> `/c/AST/Repos/x.sh`."""
    drive, rest = os.path.splitdrive(windows_path)
    return "/" + drive[0].lower() + rest.replace("\\", "/")


@unittest.skipUnless(os.name == "nt", "Git-Bash POSIX path aliasing is Windows-only")
class TestNormalizePathGitBashDriveAlias(unittest.TestCase):
    def test_posix_and_native_forms_normalize_equal(self):
        native = r"C:\AST\Repos\cx-agentic-ai\plugins\cx-devassist-cursor\scripts\cx-bootstrap.sh"
        posix = _to_gitbash_posix(native)
        self.assertEqual(cx_check._normalize_path(native), cx_check._normalize_path(posix))

    def test_bare_drive_root(self):
        self.assertEqual(cx_check._normalize_path("/c"), cx_check._normalize_path(r"C:\ "[:-1]))

    def test_msys_drive_colon_form_normalizes(self):
        native = r"C:\Cx-Flow\Test\.checkmarx\finding.json"
        posix_colon = "/c:/Cx-Flow/Test/.checkmarx/finding.json"
        self.assertEqual(cx_check._normalize_path(native), cx_check._normalize_path(posix_colon))

    def test_does_not_treat_a_multi_letter_first_segment_as_a_drive(self):
        # "/checkmarx/..." starts with a slash but its first segment is not a bare single drive
        # letter — must NOT be mistaken for a Git-Bash drive alias (only "/checkmarx" would match,
        # not "/c/...").
        self.assertIsNone(cx_check._GITBASH_DRIVE_RE.match("/checkmarx/bin/cx"))
        self.assertIsNotNone(cx_check._GITBASH_DRIVE_RE.match("/c/checkmarx/bin/cx"))


@unittest.skipUnless(os.name == "nt", "Git-Bash POSIX path aliasing is Windows-only")
class TestIsBootstrapCommandGitBashPath(unittest.TestCase):
    def test_posix_style_bootstrap_path_is_recognized(self):
        native_boot = cx_check._bootstrap_script_path()
        posix_boot = _to_gitbash_posix(native_boot)
        hook_input = {
            "tool_name": "Shell",
            "tool_input": {"command": 'bash "{0}" install'.format(posix_boot)},
        }
        self.assertTrue(cx_check._is_bootstrap_command(hook_input))


@unittest.skipUnless(os.name == "nt", "Git-Bash POSIX path aliasing is Windows-only")
class TestAuthRecoveryAndSetupDiagnosticGitBashPath(unittest.TestCase):
    def setUp(self):
        # Point the gate's resolved cx at a fixed, fake absolute Windows path (no real binary
        # needs to exist for these matcher-level tests — _cx_exe is monkeypatched directly, so
        # nothing actually spawns it).
        self._fake_cx = r"C:\Users\dev\.checkmarx\bin\cx.exe"
        self._orig_cx_exe = cx_check._cx_exe
        cx_check._cx_exe = lambda: self._fake_cx

    def tearDown(self):
        cx_check._cx_exe = self._orig_cx_exe

    def test_auth_recovery_recognizes_posix_style_cx_path(self):
        posix_cx = _to_gitbash_posix(self._fake_cx)
        hook_input = {
            "tool_name": "Shell",
            "tool_input": {"command": '"{0}" auth validate'.format(posix_cx)},
        }
        self.assertTrue(cx_check._is_auth_recovery_command(hook_input))

    def test_setup_diagnostic_recognizes_posix_style_cx_path(self):
        posix_cx = _to_gitbash_posix(self._fake_cx)
        hook_input = {"tool_name": "Shell", "tool_input": {"command": '"{0}" version'.format(posix_cx)}}
        self.assertTrue(cx_check._is_setup_diagnostic_command(hook_input, "Shell"))

    def test_unrelated_posix_path_is_not_mistaken_for_cx(self):
        hook_input = {
            "tool_name": "Shell",
            "tool_input": {"command": '"/c/Users/dev/some/other/tool.exe" auth validate'},
        }
        self.assertFalse(cx_check._is_auth_recovery_command(hook_input))

    def test_bash_c_wrapped_auth_login_is_auth_recovery(self):
        inner = (
            '"C:/Users/kedarb/AppData/Local/Checkmarx/cx/cx.exe" auth login '
            "--base-auth-uri https://eu.ast.checkmarx.net --tenant cx_seg 1>/dev/null"
        )
        command = "bash -c '{0}'".format(inner)
        unwrapped = cx_check._unwrap_shell_wrappers(command)
        self.assertIn("auth login", unwrapped)
        self.assertNotIn("bash -c", unwrapped)
        self.assertFalse(cx_check._has_unsafe_redirect(unwrapped))


@unittest.skipUnless(os.name == "nt", "Git-Bash POSIX path aliasing is Windows-only")
class TestAuthRecoveryBashCWrapper(unittest.TestCase):
    """Regression for the cx_run.sh-allows/cx_check.sh-denies deadlock: real Cursor
    beforeShellExecution events for a command needing shell interpretation (e.g. the
    oauth.md-mandated `1>/dev/null` redirect on `cx auth login`) arrive wrapped as
    `bash -c '<inner>'`, not bare — the auth-recovery carve-out must unwrap that before matching."""

    def setUp(self):
        self._fake_cx = r"C:\Users\dev\.checkmarx\bin\cx.exe"
        self._orig_cx_exe = cx_check._cx_exe
        cx_check._cx_exe = lambda: self._fake_cx

    def tearDown(self):
        cx_check._cx_exe = self._orig_cx_exe

    def test_bash_c_wrapped_auth_login_with_null_redirect_is_recognized(self):
        posix_cx = _to_gitbash_posix(self._fake_cx)
        wrapped = "bash -c '\"{0}\" auth login --base-auth-uri https://eu.ast.checkmarx.net " \
            "--tenant cx_seg 1>/dev/null'".format(posix_cx)
        hook_input = {"hook_event_name": "beforeShellExecution", "command": wrapped}
        self.assertTrue(cx_check._is_auth_recovery_command(hook_input))

    def test_bash_c_wrapped_command_with_injected_chaining_is_still_rejected(self):
        posix_cx = _to_gitbash_posix(self._fake_cx)
        wrapped = "bash -c '\"{0}\" auth login; rm -rf /'".format(posix_cx)
        hook_input = {"hook_event_name": "beforeShellExecution", "command": wrapped}
        self.assertFalse(cx_check._is_auth_recovery_command(hook_input))

    def test_bash_c_wrapped_untrusted_exe_is_still_rejected(self):
        hook_input = {
            "hook_event_name": "beforeShellExecution",
            "command": "bash -c '\"/c/evil/tool.exe\" auth login'",
        }
        self.assertFalse(cx_check._is_auth_recovery_command(hook_input))

    def test_tool_name_shell_with_native_event_uses_top_level_command(self):
        cx_path = r"C:\Users\dev\AppData\Local\Checkmarx\cx\cx.exe"
        hook_input = {
            "tool_name": "Shell",
            "hook_event_name": "beforeShellExecution",
            "command": '"{0}" auth login --tenant t'.format(cx_path.replace("\\", "/")),
        }
        self.assertEqual(
            cx_check._shell_command(hook_input, "cursor"),
            hook_input["command"],
        )
        self._orig_cx_exe = cx_check._cx_exe
        cx_check._cx_exe = lambda: cx_path
        try:
            self.assertTrue(cx_check._is_auth_recovery_command(hook_input))
        finally:
            cx_check._cx_exe = self._orig_cx_exe


@unittest.skipUnless(os.name == "nt", "Git-Bash POSIX path aliasing is Windows-only")
class TestAuthRecoveryPowerShellAndCmd(unittest.TestCase):
    """Regression for PowerShell-native auth-login shapes: Cursor's default shell on Windows is
    PowerShell, so a Shell-tool `cx auth login ... 1>$null` command can arrive as a raw
    (unwrapped) PowerShell line using PowerShell's own call operator (`& "<path>" ...`) or as a
    `cmd /c "..."` wrapper — neither of which the bash-oriented carve-out recognized before this
    fix, denying every one of these forms while a bare unquoted path happened to still work."""

    def setUp(self):
        self._fake_cx = r"C:\Users\dev\.checkmarx\bin\cx.exe"
        self._orig_cx_exe = cx_check._cx_exe
        cx_check._cx_exe = lambda: self._fake_cx

    def tearDown(self):
        cx_check._cx_exe = self._orig_cx_exe

    def test_call_operator_with_null_redirect_is_recognized(self):
        posix_cx = _to_gitbash_posix(self._fake_cx)
        command = '& "{0}" auth login --base-auth-uri https://eu.ast.checkmarx.net ' \
            '--tenant cx_seg 1>$null'.format(posix_cx)
        hook_input = {"hook_event_name": "beforeShellExecution", "command": command}
        self.assertTrue(cx_check._is_auth_recovery_command(hook_input))

    def test_call_operator_without_redirect_is_recognized(self):
        posix_cx = _to_gitbash_posix(self._fake_cx)
        command = '& "{0}" auth login --tenant cx_seg'.format(posix_cx)
        hook_input = {"hook_event_name": "beforeShellExecution", "command": command}
        self.assertTrue(cx_check._is_auth_recovery_command(hook_input))

    def test_cmd_c_wrapped_with_nul_redirect_is_recognized(self):
        command = 'cmd /c ""{0}" auth login --tenant cx_seg 1>NUL"'.format(self._fake_cx)
        hook_input = {"hook_event_name": "beforeShellExecution", "command": command}
        self.assertTrue(cx_check._is_auth_recovery_command(hook_input))

    def test_bare_unquoted_absolute_path_is_recognized(self):
        command = "{0} auth login --tenant cx_seg".format(self._fake_cx)
        hook_input = {"hook_event_name": "beforeShellExecution", "command": command}
        self.assertTrue(cx_check._is_auth_recovery_command(hook_input))

    def test_call_operator_with_injected_chaining_is_still_rejected(self):
        posix_cx = _to_gitbash_posix(self._fake_cx)
        command = '& "{0}" auth login; rm -rf /'.format(posix_cx)
        hook_input = {"hook_event_name": "beforeShellExecution", "command": command}
        self.assertFalse(cx_check._is_auth_recovery_command(hook_input))

    def test_cmd_c_wrapped_caret_hidden_ampersand_is_still_rejected(self):
        command = 'cmd /c ""{0}" auth login ^& evil"'.format(self._fake_cx)
        hook_input = {"hook_event_name": "beforeShellExecution", "command": command}
        self.assertFalse(cx_check._is_auth_recovery_command(hook_input))

    def test_path_prepend_then_semicolon_chained_bare_cx_is_still_rejected(self):
        # Deliberately NOT bypassed: bypassing chaining just because the tail looks like an auth
        # command would let an attacker hide anything before the `;`.
        command = '$env:Path = "C:\\fake;" + $env:Path; cx auth login --tenant cx_seg'
        hook_input = {"hook_event_name": "beforeShellExecution", "command": command}
        self.assertFalse(cx_check._is_auth_recovery_command(hook_input))


if __name__ == "__main__":
    unittest.main()
