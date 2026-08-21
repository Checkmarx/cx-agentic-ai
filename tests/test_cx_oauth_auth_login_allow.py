"""Regression: OAuth auth login must allow in cx_check and cx_run while cx is unauthenticated."""
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOOKS = os.path.join(_REPO, "plugins", "cursor-devassist", "hooks")
_CX_CHECK = os.path.join(_HOOKS, "cx_check.py")
_CX_CHECK_SH = os.path.join(_HOOKS, "cx_check.sh")
_CX_RUN = os.path.join(_HOOKS, "cx_run.sh")
_SH = shutil.which("sh") or shutil.which("bash")

_spec = importlib.util.spec_from_file_location("cx_check_oauth", _CX_CHECK)
cx_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cx_check)

OAUTH_PS = (
    '& "C:\\Users\\kedarb\\AppData\\Local\\Checkmarx\\cx\\cx.exe" auth login '
    "--base-auth-uri https://eu.ast.checkmarx.net --tenant cx_seg 1>$null"
)


def _hook(command):
    return {
        "hook_event_name": "beforeShellExecution",
        "command": command,
        "cwd": "",
        "sandbox": False,
    }


class TestOAuthAuthLoginAllow(unittest.TestCase):
    def test_powershell_oauth_command_is_auth_recovery(self):
        self.assertTrue(cx_check._is_auth_recovery_command(_hook(OAUTH_PS)))
        self.assertTrue(cx_check.is_trusted_setup_command(_hook(OAUTH_PS)))

    def test_foreign_cx_exe_path_is_trusted_when_file_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            foreign = os.path.join(tmp, "cx.exe")
            with open(foreign, "wb") as f:
                f.write(b"")
            cmd = '& "{0}" auth login --tenant t 1>$null'.format(foreign)
            self.assertTrue(cx_check._is_auth_recovery_command(_hook(cmd)))

    def test_pre_tool_use_shell_oauth_payload(self):
        hook = {
            "tool_name": "Shell",
            "tool_input": {
                "command": OAUTH_PS,
                "cwd": "",
                "timeout": 300000,
            },
            "hook_event_name": "preToolUse",
            "cwd": "",
        }
        self.assertTrue(cx_check._is_auth_recovery_command(hook))
        self.assertTrue(cx_check.is_trusted_setup_command(hook))

    @unittest.skipUnless(_SH, "sh required")
    def test_shell_dollar_null_not_expanded_by_cx_check_sh(self):
        """Regression: Git Bash expands `$null` inside `"$INPUT"` — OAuth `1>$null` must still allow."""
        hook = {
            "tool_name": "Shell",
            "tool_input": {"command": OAUTH_PS, "cwd": "", "timeout": 300000},
            "hook_event_name": "preToolUse",
            "cwd": "",
        }
        env = os.environ.copy()
        env.pop("CX_BINARY", None)
        proc = subprocess.run(
            [_SH, _CX_CHECK_SH],
            input=json.dumps(hook),
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    @unittest.skipUnless(_SH, "sh required")
    def test_cx_check_sh_and_cx_run_both_allow_oauth(self):
        hook = _hook(OAUTH_PS)
        env = os.environ.copy()
        env.pop("CX_BINARY", None)
        for script, args in ((_CX_CHECK_SH, []), (_CX_RUN, ["hooks", "cursor-before-shell"])):
            proc = subprocess.run(
                [_SH, script] + args,
                input=json.dumps(hook),
                capture_output=True,
                text=True,
                env=env,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            out = json.loads(proc.stdout.strip())
            self.assertEqual(out["permission"], "allow")


if __name__ == "__main__":
    unittest.main()
