"""Tests for "Checkmarx Self-Healing in VS Code" in the Copilot plugin (copilot-devassist).

GitHub Copilot in VS Code loads the same plugin as the terminal Copilot CLI and runs the same hooks.
Covered here: VS Code host detection (GITHUB_COPILOT_INTEGRATION_ID=vscode-chat, or VS Code-shaped
stdin), the IDE state file (~/.checkmarx/cx-onboarding-ide.properties) validity rules, Self-Healing
OFF -> allow before any readiness check, the terminal Copilot CLI staying unchanged, and the shell
stages (hooks/_cx_ide_host.sh, hooks/cx_run.sh, hooks/cx_check.sh).

Dependency-free (stdlib unittest). Run from the repo root:
    python -m unittest discover -s tests -t tests -p test_cx_check_vscode_self_healing.py -v

ONE PROCESS: imports copilot-devassist's cx_check, so run-tests.sh gives it its own interpreter.
"""

import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOOKS_DIR = os.path.join(_REPO_ROOT, "plugins", "copilot-devassist", "hooks")

# Unique module names (not a bare `import cx_check`): every plugin ships a same-named cx_check.py.
_log_spec = importlib.util.spec_from_file_location(
    "cx_log_copilot_vscode", os.path.join(_HOOKS_DIR, "cx_log.py"))
cx_log = importlib.util.module_from_spec(_log_spec)
_log_spec.loader.exec_module(cx_log)
_prev_cx_log = sys.modules.get("cx_log")
sys.modules["cx_log"] = cx_log
_spec = importlib.util.spec_from_file_location(
    "cx_check_copilot_vscode", os.path.join(_HOOKS_DIR, "cx_check.py"))
cx_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cx_check)
if _prev_cx_log is None:
    sys.modules.pop("cx_log", None)
else:
    sys.modules["cx_log"] = _prev_cx_log

# Forward slashes: cx_run.sh derives its own directory from $0 by splitting on "/".
CX_RUN_SH = os.path.join(_HOOKS_DIR, "cx_run.sh").replace("\\", "/")
CX_CHECK_SH = os.path.join(_HOOKS_DIR, "cx_check.sh").replace("\\", "/")
IDE_HOST_SH = os.path.join(_HOOKS_DIR, "_cx_ide_host.sh").replace("\\", "/")
_BASH = shutil.which("bash")
_SH = shutil.which("sh")

_IDE_ON = "cx_schema_version=1\ncx_self_healing_enabled=true\n"
_IDE_OFF = "cx_schema_version=1\ncx_self_healing_enabled=false\n"
_VSCODE_ENV = {"GITHUB_COPILOT_INTEGRATION_ID": "vscode-chat"}
# PLUGIN_ROOT values as the hosts set them (AST-186850 PoC; Windows paths, any user name).
_ROOT_VSCODE_FROM_CLI_INSTALL = (
    r"C:\Users\u\AppData\Roaming\Code\agentPlugins"
    r"\file-c-3A-Users-u-copilot-installed-plugins-cx-devassist-marketplace-cx-devassist\1a15407167c")
_ROOT_VSCODE_FROM_MARKETPLACE = (
    r"C:\Users\u\AppData\Roaming\Code\agentPlugins"
    r"\file-c-3A-Users-u-vscode-agent-plugins-marketplace-repositories-github-com-Checkmarx-cx-agentic-ai"
    r"\1a1542d091b")
_ROOT_CLI = r"C:\Users\u\.copilot\installed-plugins\cx-devassist-marketplace\cx-devassist"


def vscode(tool, tool_input):
    """VS Code's own agent PreToolUse stdin (snake_case keys, tool_input is an object)."""
    return {"tool_name": tool, "tool_input": tool_input, "tool_use_id": "t1",
            "hook_event_name": "PreToolUse", "session_id": "s1", "cwd": "/w",
            "timestamp": "2026-10-23T00:00:00Z"}


def cli(tool, args):
    """Copilot CLI preToolUse stdin (camelCase keys, toolArgs is a JSON STRING). Sent by the terminal
    AND by the Copilot CLI engine VS Code runs some models through — only the env tells them apart."""
    return {"toolName": tool, "toolArgs": json.dumps(args), "cwd": "/w",
            "timestamp": 1761177600000, "sessionId": "s1"}


class _IdeHome(unittest.TestCase):
    """Throwaway ~/.checkmarx; cx_check's user-config and IDE-config paths are pointed into it."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="cx-vscode-")
        self.addCleanup(shutil.rmtree, self.home, True)
        self.cfg_dir = os.path.join(self.home, ".checkmarx")
        os.makedirs(self.cfg_dir)
        self.ide = os.path.join(self.cfg_dir, "cx-onboarding-ide.properties")
        self.user_cfg = os.path.join(self.cfg_dir, "cx-onboarding.properties")
        orig = (cx_check._ide_config_path, cx_check._user_config_path, cx_check._COPILOT_CLI_MODE)
        cx_check._ide_config_path = lambda: self.ide
        cx_check._user_config_path = lambda: self.user_cfg

        def restore():
            cx_check._ide_config_path, cx_check._user_config_path, cx_check._COPILOT_CLI_MODE = orig
        self.addCleanup(restore)

    def write_ide(self, body, mode="w", encoding="utf-8", newline="\n"):
        if mode == "wb":
            with open(self.ide, "wb") as f:
                f.write(body)
        else:
            with open(self.ide, mode, encoding=encoding, newline=newline) as f:
                f.write(body)

    def gate(self, hook_input, *, which=None, copilot_cli=True, authed=True, log_dir=None, env=None):
        """Run cx_check() with cx stubbed. Returns (raw_stdout, parsed_or_None, exit_code)."""
        orig = (cx_check._read_hook_input, cx_check.shutil.which, cx_check._cx_exe_with_tier,
                cx_check._version_state, cx_check._is_authenticated, cx_check._scanner_state,
                cx_check.os.environ, sys.argv)
        cx_check._read_hook_input = lambda: hook_input
        cx_check.shutil.which = lambda name: which
        cx_check._cx_exe_with_tier = lambda: ("cx", "path")
        cx_check._version_state = lambda identity=None: "ok"
        cx_check._is_authenticated = lambda identity=None: authed
        cx_check._scanner_state = lambda identity=None: cx_check._SCANNER_SCAN
        environ = {"CX_LOG_DIR": log_dir} if log_dir else {"CX_LOG_DISABLE": "1"}
        environ.update(env or {})
        cx_check.os.environ = environ
        sys.argv = ["cx_check.py", "--copilot-cli"] if copilot_cli else ["cx_check.py"]
        buf = io.StringIO()
        code = 0
        try:
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                try:
                    cx_check.cx_check()
                except SystemExit as e:
                    code = e.code if isinstance(e.code, int) else 1
        finally:
            (cx_check._read_hook_input, cx_check.shutil.which, cx_check._cx_exe_with_tier,
             cx_check._version_state, cx_check._is_authenticated, cx_check._scanner_state,
             cx_check.os.environ, sys.argv) = orig
        raw = buf.getvalue().strip()
        return raw, (json.loads(raw) if raw else None), code


# --- host detection ------------------------------------------------------------------------------

class HostDetection(unittest.TestCase):
    def setUp(self):
        orig = cx_check.os.environ
        self.addCleanup(setattr, cx_check.os, "environ", orig)
        cx_check.os.environ = {}

    def test_plugin_root_vscode_copies(self):
        for root in (_ROOT_VSCODE_FROM_CLI_INSTALL, _ROOT_VSCODE_FROM_MARKETPLACE,
                     "/home/u/.config/Code/agentPlugins/x/1a",
                     "/Users/u/Library/Application Support/Code - Insiders/agentPlugins/x/1a"):
            cx_check.os.environ = {"PLUGIN_ROOT": root}
            self.assertTrue(cx_check._in_vscode(cli("create", {"path": "/a.py"})), root)

    def test_plugin_root_terminal_cli_wins_over_input_and_env(self):
        # The terminal's PascalCase Stop hook gets VS Code-shaped input: PLUGIN_ROOT still says CLI.
        cx_check.os.environ = dict(_VSCODE_ENV, PLUGIN_ROOT=_ROOT_CLI)
        self.assertFalse(cx_check._in_vscode({"hook_event_name": "Stop", "session_id": "s"}))
        cx_check.os.environ = {"PLUGIN_ROOT": "/home/u/.copilot/installed-plugins/m/cx-devassist"}
        self.assertFalse(cx_check._in_vscode(vscode("create_file", {"filePath": "/a.py"})))

    def test_vscode_fork_copies_are_not_vscode(self):
        for root in (r"C:\Users\u\AppData\Roaming\Windsurf\agentPlugins\x\1a",
                     "/Users/u/Library/Application Support/Cursor/agentPlugins/x/1a",
                     "/home/u/.config/Kiro/agentPlugins/x/1a"):
            # Not VS Code, and the fallbacks must not override that.
            cx_check.os.environ = dict(_VSCODE_ENV, PLUGIN_ROOT=root)
            self.assertFalse(cx_check._in_vscode(vscode("create_file", {"filePath": "/a.py"})), root)

    def test_terminal_path_containing_agentplugins_is_cli(self):
        for root in (r"C:\Users\agentPlugins\.copilot\installed-plugins\m\cx-devassist",
                     "/home/u/agentPlugins/.copilot/installed-plugins/m/cx-devassist"):
            cx_check.os.environ = {"PLUGIN_ROOT": root}
            self.assertFalse(cx_check._in_vscode(cli("create", {"path": "/a.py"})), root)

    def test_other_host_plugin_root_is_not_vscode(self):
        # JetBrains, Visual Studio, ... : their own PLUGIN_ROOT; neither env nor input shape may override it.
        cx_check.os.environ = {"PLUGIN_ROOT": r"D:\other\plugin"}
        self.assertFalse(cx_check._in_vscode(cli("create", {"path": "/a.py"})))
        cx_check.os.environ = dict(_VSCODE_ENV, PLUGIN_ROOT=r"D:\other\plugin")
        self.assertFalse(cx_check._in_vscode(vscode("create_file", {"filePath": "/a.py"})))

    def test_vscode_integration_id_env(self):
        # VS Code's Copilot CLI engine: CLI-shaped stdin, only the env says "VS Code".
        cx_check.os.environ = dict(_VSCODE_ENV)
        self.assertTrue(cx_check._in_vscode(cli("create", {"path": "/a.py"})))

    def test_other_integration_ids_are_not_vscode(self):
        for value in ("", "copilot-developer-cli", "VSCODE-CHAT", "vscode"):
            cx_check.os.environ = {"GITHUB_COPILOT_INTEGRATION_ID": value}
            self.assertFalse(cx_check._in_vscode(cli("create", {"path": "/a.py"})), value)

    def test_vscode_shaped_input(self):
        for key in ("tool_name", "tool_input", "hook_event_name", "session_id"):
            self.assertTrue(cx_check._in_vscode({key: "x"}), key)
        self.assertTrue(cx_check._in_vscode(vscode("create_file", {"filePath": "/a.py"})))

    def test_terminal_cli_is_not_vscode(self):
        self.assertFalse(cx_check._in_vscode(cli("create", {"path": "/a.py"})))
        self.assertFalse(cx_check._in_vscode(
            {"sessionId": "s", "cwd": "/w", "toolCalls": [{"name": "edit", "args": "{}"}]}))
        self.assertFalse(cx_check._in_vscode({}))

    def test_nested_key_inside_cli_tool_args_is_not_vscode(self):
        # toolArgs is a JSON string — a "tool_name" inside it is not a top-level key.
        self.assertFalse(cx_check._in_vscode(cli("create", {"tool_name": "x", "session_id": "y"})))

    def test_vscode_terminal_env_vars_are_ignored(self):
        # The integrated terminal inherits these; they must not make the terminal look like VS Code.
        cx_check.os.environ = {"TERM_PROGRAM": "vscode", "VSCODE_PID": "1", "VSCODE_IPC_HOOK": "x"}
        self.assertFalse(cx_check._in_vscode(cli("create", {"path": "/a.py"})))


# --- IDE state file ------------------------------------------------------------------------------

class IdeConfigValidity(_IdeHome):
    def test_missing_file_is_invalid_and_on(self):
        self.assertIsNone(cx_check._load_ide_config())
        self.assertFalse(cx_check._ide_self_healing_disabled())

    def test_off_values(self):
        for value in ("false", "FALSE", "0", "no", "Off", "disabled", "  false  "):
            self.write_ide("cx_self_healing_enabled=%s\n" % value)
            self.assertTrue(cx_check._ide_self_healing_disabled(), repr(value))

    def test_other_values_are_on(self):
        for value in ("true", "", "banana", "flase", "1", "yes"):
            self.write_ide("cx_self_healing_enabled=%s\n" % value)
            self.assertFalse(cx_check._ide_self_healing_disabled(), repr(value))

    def test_missing_key_is_on(self):
        self.write_ide("cx_schema_version=1\ncx_ide_extension=ast-results\n")
        self.assertFalse(cx_check._ide_self_healing_disabled())

    def test_schema_absent_or_1_is_valid(self):
        self.write_ide("cx_self_healing_enabled=false\n")
        self.assertIsNotNone(cx_check._load_ide_config())
        self.write_ide(_IDE_OFF)
        self.assertIsNotNone(cx_check._load_ide_config())

    def test_unknown_schema_is_invalid_and_on(self):
        for schema in ("2", "1.0", "x", ""):
            self.write_ide("cx_schema_version=%s\ncx_self_healing_enabled=false\n" % schema)
            self.assertIsNone(cx_check._load_ide_config(), schema)
            self.assertFalse(cx_check._ide_self_healing_disabled(), schema)

    def test_oversized_file_is_invalid(self):
        self.write_ide(_IDE_OFF + "#" * 8200 + "\n")
        self.assertIsNone(cx_check._load_ide_config())
        self.assertFalse(cx_check._ide_self_healing_disabled())

    def test_exactly_8kb_is_valid(self):
        body = _IDE_OFF
        self.write_ide(body + "#" * (8192 - len(body) - 1) + "\n")
        self.assertEqual(os.path.getsize(self.ide), 8192)
        self.assertTrue(cx_check._ide_self_healing_disabled())

    def test_undecodable_file_is_invalid(self):
        self.write_ide(b"cx_self_healing_enabled=false\n\xff\xfe\x00garbage\n", mode="wb")
        self.assertIsNone(cx_check._load_ide_config())

    def test_bom_crlf_comments_and_last_wins(self):
        self.write_ide("﻿cx_schema_version=1\r\n# cx_self_healing_enabled=true\r\n"
                       "cx_self_healing_enabled=true\r\ncx_self_healing_enabled=false\r\n")
        self.assertTrue(cx_check._ide_self_healing_disabled())
        self.write_ide("cx_self_healing_enabled=false\ncx_self_healing_enabled=true\n")
        self.assertFalse(cx_check._ide_self_healing_disabled())

    def test_default_path(self):
        cx_check._ide_config_path = type(self)._real_ide_config_path
        self.assertEqual(cx_check._ide_config_path(), os.path.join(
            os.path.expanduser("~"), ".checkmarx", "cx-onboarding-ide.properties"))


IdeConfigValidity._real_ide_config_path = staticmethod(cx_check._ide_config_path)


# --- Self-Healing OFF / ON through the gate -------------------------------------------------------

class SelfHealingOff(_IdeHome):
    _CLI_WRITE = staticmethod(lambda: cli("create", {"path": "/src/app.py", "file_text": "x=1"}))

    def test_off_allows_vscode_cli_engine_write_with_cx_absent(self):
        self.write_ide(_IDE_OFF)
        raw, _parsed, code = self.gate(self._CLI_WRITE(), which=None, env=_VSCODE_ENV)
        self.assertEqual((raw, code), ("", 0))

    def test_off_allows_vscode_by_plugin_root(self):
        self.write_ide(_IDE_OFF)
        raw, _parsed, code = self.gate(self._CLI_WRITE(), which=None,
                                       env={"PLUGIN_ROOT": _ROOT_VSCODE_FROM_MARKETPLACE})
        self.assertEqual((raw, code), ("", 0))

    def test_off_does_not_affect_terminal_by_plugin_root(self):
        self.write_ide(_IDE_OFF)
        _raw, parsed, _code = self.gate(self._CLI_WRITE(), which=None, env={"PLUGIN_ROOT": _ROOT_CLI})
        self.assertEqual(parsed.get("permissionDecision"), "deny")

    def test_off_allows_vscode_shaped_write(self):
        self.write_ide(_IDE_OFF)
        raw, _parsed, code = self.gate(vscode("create_file", {"filePath": "/src/app.py"}), which=None)
        self.assertEqual((raw, code), ("", 0))

    def test_off_skips_every_readiness_check(self):
        self.write_ide(_IDE_OFF)
        called = []
        orig = cx_check._is_bootstrap_command
        cx_check._is_bootstrap_command = lambda h: called.append("bootstrap") or False
        self.addCleanup(setattr, cx_check, "_is_bootstrap_command", orig)
        raw, _parsed, code = self.gate(self._CLI_WRITE(), which=None, authed=False, env=_VSCODE_ENV)
        self.assertEqual((raw, code, called), ("", 0, []))

    def test_off_logs_self_healing_disabled(self):
        self.write_ide(_IDE_OFF)
        log_dir = tempfile.mkdtemp(prefix="cx-vscode-log-")
        self.addCleanup(shutil.rmtree, log_dir, True)
        self.gate(self._CLI_WRITE(), which=None, log_dir=log_dir, env=_VSCODE_ENV)
        with open(os.path.join(log_dir, "cx-devassist.jsonl"), encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]
        gate = [r for r in records if r.get("event") == "gate_decision"]
        self.assertEqual(len(gate), 1, records)
        self.assertEqual(gate[0].get("decision"), "allow")
        self.assertEqual(gate[0].get("reason_code"), "self_healing_disabled")
        self.assertEqual(gate[0].get("tool_name"), "create")

    def test_off_does_not_affect_terminal_cli(self):
        self.write_ide(_IDE_OFF)
        _raw, parsed, code = self.gate(self._CLI_WRITE(), which=None)
        self.assertEqual(code, 0)
        self.assertEqual(parsed.get("permissionDecision"), "deny")
        self.assertNotIn("hookSpecificOutput", parsed)

    def test_off_needs_the_copilot_plugin_flag(self):
        # Without --copilot-cli this is not the Copilot plugin (Claude Code path): never skipped.
        self.write_ide(_IDE_OFF)
        raw, _parsed, _code = self.gate(vscode("Write", {"file_path": "/src/app.py"}), which=None,
                                        copilot_cli=False)
        self.assertNotEqual(raw, "")

    def test_on_missing_or_invalid_file_keeps_gating(self):
        for body in (None, _IDE_ON, "cx_schema_version=2\ncx_self_healing_enabled=false\n",
                     "cx_self_healing_enabled=nope\n"):
            if body is None:
                if os.path.exists(self.ide):
                    os.remove(self.ide)
            else:
                self.write_ide(body)
            _raw, parsed, code = self.gate(self._CLI_WRITE(), which=None, env=_VSCODE_ENV)
            self.assertEqual(code, 0, body)
            # Unchanged: the same flat Copilot CLI deny as the terminal gets.
            self.assertEqual(parsed.get("permissionDecision"), "deny", body)


# --- shell stages --------------------------------------------------------------------------------

def _shell_env(home, **extra):
    env = dict(os.environ)
    env.update({"HOME": home, "USERPROFILE": home, "LOCALAPPDATA": home, "CX_LOG_DISABLE": "1"})
    env.pop("CX_BINARY", None)
    env.pop("GITHUB_COPILOT_INTEGRATION_ID", None)
    env.pop("PLUGIN_ROOT", None)
    env.update(extra)
    return env


class _ShellHome(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="cx-vscode-sh-")
        self.addCleanup(shutil.rmtree, self.home, True)
        os.makedirs(os.path.join(self.home, ".checkmarx"))
        self.ide = os.path.join(self.home, ".checkmarx", "cx-onboarding-ide.properties")

    def write_ide(self, body):
        with open(self.ide, "w", encoding="utf-8", newline="") as f:
            f.write(body)


@unittest.skipUnless(_BASH, "bash not found on PATH")
class IdeHostHelper(_ShellHome):
    """hooks/_cx_ide_host.sh must agree with cx_check.py on host + validity rules."""

    def _call(self, fn, arg="", **env):
        # The argument travels in the environment: MSYS bash would brace-expand a bare `{a,b}` argv.
        proc = subprocess.run([_BASH, "-c", '. "$0"; %s "$CX_TEST_ARG"' % fn, IDE_HOST_SH],
                              env=_shell_env(self.home, CX_TEST_ARG=arg, **env), capture_output=True,
                              timeout=30)
        return proc.returncode == 0

    def test_in_vscode(self):
        cli_payload = json.dumps(cli("create", {"tool_name": "x"}))
        self.assertTrue(self._call("cx_in_vscode", cli_payload, **_VSCODE_ENV))
        self.assertTrue(self._call("cx_in_vscode", json.dumps(vscode("create_file", {}))))
        self.assertTrue(self._call("cx_in_vscode", '{"hook_event_name":"Stop","session_id":"s"}'))
        self.assertFalse(self._call("cx_in_vscode", cli_payload))
        self.assertFalse(self._call("cx_in_vscode", cli_payload, TERM_PROGRAM="vscode"))
        self.assertFalse(self._call("cx_in_vscode", '{"sessionId":"s","stopReason":"end_turn"}'))

    def test_in_vscode_plugin_root(self):
        cli_payload = json.dumps(cli("create", {"path": "/a.py"}))
        for root in (_ROOT_VSCODE_FROM_CLI_INSTALL, _ROOT_VSCODE_FROM_MARKETPLACE,
                     "/home/u/.config/Code/agentPlugins/x/1a"):
            self.assertTrue(self._call("cx_in_vscode", cli_payload, PLUGIN_ROOT=root), root)
        stop = '{"hook_event_name":"Stop","session_id":"s"}'
        self.assertFalse(self._call("cx_in_vscode", stop, PLUGIN_ROOT=_ROOT_CLI, **_VSCODE_ENV))
        self.assertFalse(self._call("cx_in_vscode", cli_payload, PLUGIN_ROOT=r"D:\other\plugin"))
        self.assertFalse(self._call("cx_in_vscode", cli_payload,
                                    PLUGIN_ROOT=r"C:\Users\agentPlugins\.copilot\installed-plugins\m\cx-devassist"))
        self.assertTrue(self._call("cx_in_vscode", cli_payload,
                                   PLUGIN_ROOT="/Users/u/Library/Application Support/Code - Insiders/agentPlugins/x/1a"))
        for fork in (r"C:\Users\u\AppData\Roaming\Windsurf\agentPlugins\x\1a", "/home/u/.config/Kiro/agentPlugins/x/1a"):
            self.assertFalse(self._call("cx_in_vscode", json.dumps(vscode("create_file", {})),
                                        PLUGIN_ROOT=fork, **_VSCODE_ENV), fork)

    def test_self_healing_matches_python(self):
        cases = [
            (None, False),
            (_IDE_ON, False),
            (_IDE_OFF, True),
            ("cx_self_healing_enabled= Disabled \n", True),
            ("﻿cx_schema_version=1\r\ncx_self_healing_enabled=OFF\r\n", True),
            ("cx_schema_version=2\ncx_self_healing_enabled=false\n", False),
            ("# cx_self_healing_enabled=false\n", False),
            ("cx_self_healing_enabled=false\ncx_self_healing_enabled=true\n", False),
            ("cx_self_healing_enabled=nope\n", False),
            (_IDE_OFF + "#" * 8200 + "\n", False),
        ]
        orig = cx_check._ide_config_path
        cx_check._ide_config_path = lambda: self.ide
        self.addCleanup(setattr, cx_check, "_ide_config_path", orig)
        for body, expected in cases:
            if body is None:
                if os.path.exists(self.ide):
                    os.remove(self.ide)
            else:
                self.write_ide(body)
            self.assertEqual(self._call("cx_ide_self_healing_off"), expected, repr(body))
            self.assertEqual(cx_check._ide_self_healing_disabled(), expected, repr(body))


@unittest.skipUnless(_BASH, "bash not found on PATH")
class CxRunSh(_ShellHome):
    """cx_run.sh: Self-Healing OFF short-circuit in VS Code; the terminal is untouched."""

    def setUp(self):
        super().setUp()
        self.mark = os.path.join(self.home, "called")
        self.stdin_copy = os.path.join(self.home, "stdin")
        self.stub = os.path.join(self.home, "cx-stub")
        with open(self.stub, "w", newline="\n") as f:
            f.write('#!/bin/sh\necho called >> "$STUB_MARK"\ncat > "$STUB_STDIN"\nexit 0\n')
        os.chmod(self.stub, os.stat(self.stub).st_mode | stat.S_IXUSR)

    def run_cx(self, sub, stdin, **extra):
        env = _shell_env(self.home, CX_BINARY=self.stub.replace("\\", "/"), STUB_MARK=self.mark,
                         STUB_STDIN=self.stdin_copy, **extra)
        proc = subprocess.run([_BASH, CX_RUN_SH, "hooks", sub], input=stdin.encode(), env=env,
                              capture_output=True, timeout=60)
        return proc.returncode, proc.stdout.decode("utf-8", "replace")

    def called(self):
        return os.path.exists(self.mark)

    def test_off_vscode_cli_engine_skips_cx(self):
        self.write_ide(_IDE_OFF)
        payload = json.dumps(cli("create", {"path": "/a.py"}))
        for sub in ("copilot-cli-pre-file-write", "copilot-cli-stop"):
            code, out = self.run_cx(sub, payload, **_VSCODE_ENV)
            self.assertEqual((code, out, self.called()), (0, "", False), sub)

    def test_off_vscode_by_plugin_root_skips_cx(self):
        self.write_ide(_IDE_OFF)
        code, out = self.run_cx("copilot-cli-pre-file-write", json.dumps(cli("create", {"path": "/a.py"})),
                                PLUGIN_ROOT=_ROOT_VSCODE_FROM_CLI_INSTALL)
        self.assertEqual((code, out, self.called()), (0, "", False))

    def test_off_terminal_pascal_case_stop_still_runs_cx(self):
        # The terminal Copilot CLI's PascalCase Stop gets VS Code-shaped stdin; PLUGIN_ROOT keeps it CLI.
        self.write_ide(_IDE_OFF)
        self.run_cx("copilot-cli-stop", '{"hook_event_name":"Stop","session_id":"s"}', PLUGIN_ROOT=_ROOT_CLI)
        self.assertTrue(self.called())

    def test_off_vscode_shaped_stop_skips_cx(self):
        self.write_ide(_IDE_OFF)
        code, out = self.run_cx("copilot-cli-stop", '{"hook_event_name":"Stop","session_id":"s"}')
        self.assertEqual((code, out, self.called()), (0, "", False))

    def test_off_terminal_still_runs_cx_with_stdin_replayed(self):
        self.write_ide(_IDE_OFF)
        payload = json.dumps(cli("create", {"path": "/a.py"}))
        for sub in ("copilot-cli-pre-file-write", "copilot-cli-stop"):
            if os.path.exists(self.mark):
                os.remove(self.mark)
            code, _out = self.run_cx(sub, payload)
            self.assertEqual(code, 0, sub)
            self.assertTrue(self.called(), sub)
            with open(self.stdin_copy, encoding="utf-8") as f:
                self.assertEqual(f.read(), payload, sub)

    def test_on_vscode_runs_cx(self):
        self.write_ide(_IDE_ON)
        self.run_cx("copilot-cli-pre-file-write", json.dumps(cli("create", {"path": "/a.py"})),
                    **_VSCODE_ENV)
        self.assertTrue(self.called())


@unittest.skipUnless(_SH and os.name != "nt", "needs POSIX sh + symlinks (Windows → manual)")
class CxCheckShNoPython(_ShellHome):
    """cx_check.sh's no-Python branch: allow in VS Code when Self-Healing is OFF, else unchanged."""

    def _run(self, stdin, **extra):
        bindir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, bindir, True)
        for tool in ("sh", "cat", "dirname", "tr", "uname", "wc", "awk", "printf"):
            src = shutil.which(tool)
            if src:
                os.symlink(src, os.path.join(bindir, tool))
        env = {"PATH": bindir, "HOME": self.home}
        env.update(extra)
        proc = subprocess.run([os.path.join(bindir, "sh"), CX_CHECK_SH, "--copilot-cli"],
                              input=stdin.encode(), capture_output=True, timeout=30, env=env)
        return proc.returncode, proc.stdout.decode("utf-8", "replace")

    def test_vscode_off_allows(self):
        self.write_ide(_IDE_OFF)
        code, out = self._run(json.dumps(cli("create", {"path": "/a.py"})), **_VSCODE_ENV)
        self.assertEqual((code, out), (0, ""))

    def test_vscode_on_flat_deny_unchanged(self):
        code, out = self._run(json.dumps(cli("create", {"path": "/a.py"})), **_VSCODE_ENV)
        self.assertEqual(code, 0)
        self.assertEqual(set(json.loads(out)), {"permissionDecision", "permissionDecisionReason"})

    def test_terminal_off_flat_deny_unchanged(self):
        self.write_ide(_IDE_OFF)
        code, out = self._run(json.dumps(cli("create", {"path": "/a.py"})))
        self.assertEqual(code, 0)
        self.assertEqual(set(json.loads(out)), {"permissionDecision", "permissionDecisionReason"})


if __name__ == "__main__":
    unittest.main()
