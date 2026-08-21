"""Regression: bootstrap install must be allowed when command targets another install copy."""
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CX_CHECK = os.path.join(_REPO, "plugins", "cursor-devassist", "hooks", "cx_check.py")
_CX_CHECK_SH = os.path.join(_REPO, "plugins", "cursor-devassist", "hooks", "cx_check.sh")
_CX_RUN = os.path.join(_REPO, "plugins", "cursor-devassist", "hooks", "cx_run.sh")
_SH = shutil.which("sh") or shutil.which("bash")

_spec = importlib.util.spec_from_file_location("cx_check_foreign_boot", _CX_CHECK)
cx_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cx_check)


class TestForeignInstallBootstrapPath(unittest.TestCase):
    def test_existing_foreign_scripts_cx_bootstrap_is_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            scripts = os.path.join(tmp, "cursor-devassist", "scripts")
            os.makedirs(scripts)
            foreign_boot = os.path.join(scripts, "cx-bootstrap.sh")
            with open(foreign_boot, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\nexit 0\n")
            cmd = 'bash "{0}" install'.format(foreign_boot.replace("\\", "/"))
            hook = {
                "hook_event_name": "beforeShellExecution",
                "command": cmd,
                "cwd": "",
                "sandbox": False,
            }
            self.assertTrue(cx_check._is_bootstrap_command(hook))
            self.assertTrue(cx_check.is_trusted_setup_command(hook))

    @unittest.skipUnless(_SH, "sh required")
    def test_cx_check_sh_allows_foreign_bootstrap_before_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            scripts = os.path.join(tmp, "cursor-devassist", "scripts")
            os.makedirs(scripts)
            foreign_boot = os.path.join(scripts, "cx-bootstrap.sh")
            with open(foreign_boot, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\nexit 0\n")
            hook = {
                "hook_event_name": "beforeShellExecution",
                "command": 'bash "{0}" install'.format(foreign_boot.replace("\\", "/")),
                "cwd": "",
                "sandbox": False,
            }
            env = os.environ.copy()
            env.pop("CX_BINARY", None)
            empty_home = tempfile.mkdtemp()
            for var in ("HOME", "LOCALAPPDATA", "USERPROFILE"):
                env[var] = empty_home
            proc = subprocess.run(
                [_SH, _CX_CHECK_SH],
                input=json.dumps(hook),
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("allow", proc.stdout)

    @unittest.skipUnless(_SH, "sh required")
    def test_cx_run_allows_foreign_bootstrap_when_cx_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            scripts = os.path.join(tmp, "cursor-devassist", "scripts")
            os.makedirs(scripts)
            foreign_boot = os.path.join(scripts, "cx-bootstrap.sh")
            with open(foreign_boot, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\nexit 0\n")
            hook = {
                "hook_event_name": "beforeShellExecution",
                "command": 'bash "{0}" install'.format(foreign_boot.replace("\\", "/")),
                "cwd": "",
                "sandbox": False,
            }
            env = os.environ.copy()
            env.pop("CX_BINARY", None)
            empty_home = tempfile.mkdtemp()
            for var in ("HOME", "LOCALAPPDATA", "USERPROFILE"):
                env[var] = empty_home
            kept = [
                e for e in env.get("PATH", "").split(os.pathsep)
                if e and not any(os.path.isfile(os.path.join(e, n)) for n in ("cx", "cx.exe"))
            ]
            env["PATH"] = os.pathsep.join(kept)
            proc = subprocess.run(
                [_SH, _CX_RUN, "hooks", "cursor-before-shell"],
                input=json.dumps(hook),
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("allow", proc.stdout)


if __name__ == "__main__":
    unittest.main()
