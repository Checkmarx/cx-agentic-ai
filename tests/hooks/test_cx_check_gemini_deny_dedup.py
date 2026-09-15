"""Gemini CLI: gate deny systemMessage is shown once per session per reason_code."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_HOOKS_DIR = os.path.join(_REPO_ROOT, "hooks")
sys.path.insert(0, _HOOKS_DIR)
import cx_check  # noqa: E402


def _write(path="/proj/main.tf"):
    return {
        "sessionId": "sess-dedup-test",
        "tool_name": "write_file",
        "tool_input": {"file_path": path, "content": "x"},
    }


def _run_gemini_deny(hook_input, *, log_dir, repeat_env=None, authed=False,
                     scanner_state=None):
    if scanner_state is None:
        scanner_state = cx_check._SCANNER_SCAN
    orig = {
        "which": cx_check.shutil.which,
        "vstate": cx_check._version_state,
        "authed": cx_check._is_authenticated,
        "scanner": cx_check._scanner_state,
        "read": cx_check._read_hook_input,
        "environ": cx_check.os.environ,
        "argv": sys.argv,
        "cred_mtime": cx_check._credential_mtime,
    }
    cx_check.shutil.which = lambda name: "cx"
    cx_check._version_state = lambda identity=None: "ok"
    cx_check._is_authenticated = lambda identity=None: authed
    cx_check._scanner_state = lambda identity=None: scanner_state
    cx_check._read_hook_input = lambda: hook_input
    cx_check._credential_mtime = lambda: 1000.0
    env = {"CX_LOG_DIR": log_dir, "CX_LOG_DISABLE": "1"}
    if repeat_env is not None:
        env["CX_GATE_REPEAT_DENY_MESSAGES"] = repeat_env
    cx_check.os.environ = env
    sys.argv = ["cx_check.py", "--gemini-cli"]

    out = io.StringIO()
    code = 0
    try:
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            cx_check.cx_check()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    finally:
        cx_check.shutil.which = orig["which"]
        cx_check._version_state = orig["vstate"]
        cx_check._is_authenticated = orig["authed"]
        cx_check._scanner_state = orig["scanner"]
        cx_check._read_hook_input = orig["read"]
        cx_check.os.environ = orig["environ"]
        cx_check._credential_mtime = orig["cred_mtime"]
        sys.argv = orig["argv"]

    parsed = None
    text = out.getvalue().strip()
    if text:
        parsed = json.loads(text)
    return parsed, code


class TestGeminiDenyDedup(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._shown = os.path.join(self._tmpdir, "cx_gemini_deny_shown.json")
        self._orig_shown = cx_check._GEMINI_DENY_SHOWN_FILE
        cx_check._GEMINI_DENY_SHOWN_FILE = self._shown

    def tearDown(self):
        cx_check._GEMINI_DENY_SHOWN_FILE = self._orig_shown
        for name in ("cx_gemini_deny_shown.json",):
            path = os.path.join(self._tmpdir, name)
            if os.path.exists(path):
                os.unlink(path)
        os.rmdir(self._tmpdir)

    def test_first_deny_shows_system_message_second_suppresses(self):
        first, code1 = _run_gemini_deny(_write(), log_dir=self._tmpdir)
        second, code2 = _run_gemini_deny(_write("/proj/other.tf"), log_dir=self._tmpdir)

        self.assertEqual(0, code1)
        self.assertEqual(0, code2)
        self.assertEqual("deny", first.get("decision"))
        self.assertEqual("deny", second.get("decision"))
        self.assertIn("systemMessage", first)
        self.assertNotIn("systemMessage", second)
        self.assertIn("reason", second)

    def test_repeat_opt_in_shows_every_time(self):
        first, _ = _run_gemini_deny(_write(), log_dir=self._tmpdir, repeat_env="1")
        second, _ = _run_gemini_deny(_write("/proj/other.tf"), log_dir=self._tmpdir, repeat_env="1")

        self.assertIn("systemMessage", first)
        self.assertIn("systemMessage", second)

    def test_different_reason_codes_each_show_once(self):
        passthrough, _ = _run_gemini_deny(
            _write(), log_dir=self._tmpdir, authed=True,
            scanner_state=cx_check._SCANNER_PASSTHROUGH)
        unauth, _ = _run_gemini_deny(
            _write("/proj/other.tf"), log_dir=self._tmpdir, authed=False)

        self.assertIn("systemMessage", passthrough)
        self.assertIn("systemMessage", unauth)
        self.assertIn("pass-through", passthrough["systemMessage"])
        self.assertIn("could not authenticate", unauth["systemMessage"])


if __name__ == "__main__":
    unittest.main()
