"""Tests for cursor-devassist gate deny/allow JSON on stdout."""

import json
import os
import subprocess
import sys
import unittest


PLUGIN_HOOKS = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "plugins", "cursor-devassist", "hooks")
)
CX_CHECK = os.path.join(PLUGIN_HOOKS, "cx_check.py")
DENY_PREFIX = "CHECKMARX_HOOK_DENY — MANDATORY agent_message"


class TestCxCheckCursorGateJson(unittest.TestCase):
    def _run_gate(self, hook_input):
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        proc = subprocess.run(
            [sys.executable, CX_CHECK],
            input=json.dumps(hook_input),
            text=True,
            capture_output=True,
            env=env,
            timeout=120,
        )
        return proc

    def test_readonly_shell_emits_allow_json(self):
        proc = self._run_gate({
            "tool_name": "Shell",
            "tool_input": {"command": "ls"},
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    def test_readonly_where_shell_emits_allow_json(self):
        # "where" is the Windows analog of "which" — used by cx-cli-setup Phase 0 to detect
        # whether cx is on PATH before cx is installed/authenticated.
        proc = self._run_gate({
            "tool_name": "Shell",
            "tool_input": {"command": "where cx"},
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    def test_cx_version_shell_emits_allow_json(self):
        # `cx version` is a read-only diagnostic with no side effects — cx-cli-setup Phase 1a uses
        # it to check whether the install landed, even before cx is authenticated/verified.
        proc = self._run_gate({
            "tool_name": "Shell",
            "tool_input": {"command": "cx version"},
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    def test_cx_utils_env_shell_emits_allow_json(self):
        proc = self._run_gate({
            "tool_name": "Shell",
            "tool_input": {"command": "cx utils env"},
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    def test_cx_version_diagnostic_carve_out_disabled_by_gate_all_commands(self):
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["CX_GATE_ALL_COMMANDS"] = "1"
        env["CX_BINARY"] = r"C:\nonexistent\cx.exe"
        proc = subprocess.run(
            [sys.executable, CX_CHECK],
            input=json.dumps({"tool_name": "Shell", "tool_input": {"command": "cx version"}}),
            text=True,
            capture_output=True,
            env=env,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout)

    def test_cx_scan_command_is_not_treated_as_setup_diagnostic(self):
        # A real scan/write-capable subcommand must NOT ride the diagnostic carve-out.
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["CX_BINARY"] = r"C:\nonexistent\cx.exe"
        proc = subprocess.run(
            [sys.executable, CX_CHECK],
            input=json.dumps({"tool_name": "Shell", "tool_input": {"command": "cx scan asca -s file.py"}}),
            text=True,
            capture_output=True,
            env=env,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout)

    def test_chained_which_or_where_probe_is_still_gated(self):
        # Shell chaining (`||`) disqualifies the bare-command carve-outs by design — the
        # cx-cli-setup skill must issue a single OS-appropriate probe, not an OR'd fallback.
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["CX_BINARY"] = r"C:\nonexistent\cx.exe"
        proc = subprocess.run(
            [sys.executable, CX_CHECK],
            input=json.dumps({
                "tool_name": "Shell",
                "tool_input": {"command": "which cx 2>/dev/null || where cx 2>nul"},
            }),
            text=True,
            capture_output=True,
            env=env,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout)

    def _to_gitbash_posix(self, windows_path):
        """`C:\\AST\\Repos\\x.sh` -> `/c/AST/Repos/x.sh` — the POSIX rendering Git-Bash's own `pwd`
        and path resolution produce, as opposed to Python's native backslash rendering."""
        drive, rest = os.path.splitdrive(windows_path)
        return "/" + drive[0].lower() + rest.replace("\\", "/")

    @unittest.skipUnless(sys.platform == "win32", "Git-Bash POSIX path aliasing is Windows-only")
    def test_bootstrap_command_allowed_with_gitbash_posix_path(self):
        # Regression: the agent's own bash/sh resolves the bootstrap script via `pwd`, which
        # yields a Git-Bash POSIX path (/c/...), not Python's native backslash rendering. Before
        # the _normalize_path fix, os.path.abspath("/c/...") on Windows treated "c" as a literal
        # subdirectory instead of drive C:, so this never matched the real bootstrap script and
        # the install command was denied as "not recognized".
        bootstrap = os.path.join(
            os.path.dirname(PLUGIN_HOOKS), "scripts", "cx-bootstrap.sh"
        )
        posix_path = self._to_gitbash_posix(os.path.abspath(bootstrap))
        proc = self._run_gate({
            "tool_name": "Shell",
            "tool_input": {"command": 'bash "{0}" install'.format(posix_path)},
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    def test_native_before_shell_bootstrap_allowed(self):
        # Cursor beforeShellExecution carries top-level "command" — not tool_input.command.
        bootstrap = os.path.join(
            os.path.dirname(PLUGIN_HOOKS), "scripts", "cx-bootstrap.sh"
        )
        proc = self._run_gate({
            "hook_event_name": "beforeShellExecution",
            "command": 'bash "{0}" install'.format(bootstrap.replace("\\", "/")),
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    @unittest.skipUnless(sys.platform == "win32", "Windows backslash bootstrap path")
    def test_native_before_shell_bootstrap_with_backslashes_allowed(self):
        bootstrap = os.path.abspath(
            os.path.join(os.path.dirname(PLUGIN_HOOKS), "scripts", "cx-bootstrap.sh")
        )
        proc = self._run_gate({
            "hook_event_name": "beforeShellExecution",
            "command": 'bash "{0}" install'.format(bootstrap),
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    def _canonical_cx_path(self):
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, "Checkmarx", "cx", "cx.exe")

    @unittest.skipUnless(sys.platform == "win32", "Windows canonical cx path")
    def test_auth_validate_allowed_with_forward_slash_canonical_cx(self):
        cx_path = self._canonical_cx_path()
        if not os.path.isfile(cx_path):
            self.skipTest("canonical cx not installed at {0}".format(cx_path))
        proc = self._run_gate({
            "hook_event_name": "beforeShellExecution",
            "command": '"{0}" auth validate'.format(cx_path.replace("\\", "/")),
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    @unittest.skipUnless(sys.platform == "win32", "Windows canonical cx path")
    def test_auth_login_allowed_with_forward_slash_canonical_cx(self):
        cx_path = self._canonical_cx_path()
        if not os.path.isfile(cx_path):
            self.skipTest("canonical cx not installed at {0}".format(cx_path))
        proc = self._run_gate({
            "hook_event_name": "beforeShellExecution",
            "command": (
                '"{0}" auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant cx_seg'
            ).format(cx_path.replace("\\", "/")),
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    @unittest.skipUnless(sys.platform == "win32", "Windows canonical cx path")
    def test_auth_login_bash_c_with_null_redirect_allowed(self):
        # Cursor wraps `1>/dev/null` auth commands as bash -c '…' — must unwrap before auth-recovery
        # matching (cx_run.sh allows via shell carve-out; cx_check.py must agree).
        cx_path = self._canonical_cx_path()
        if not os.path.isfile(cx_path):
            self.skipTest("canonical cx not installed at {0}".format(cx_path))
        inner = (
            '"{0}" auth login --base-auth-uri https://eu.ast.checkmarx.net '
            "--tenant cx_seg 1>/dev/null"
        ).format(cx_path.replace("\\", "/"))
        command = "bash -c '{0}'".format(inner)
        proc = self._run_gate({
            "hook_event_name": "beforeShellExecution",
            "command": command,
        })
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    @unittest.skipUnless(sys.platform == "win32", "Windows canonical cx path")
    def test_native_before_shell_auth_login_exact_user_payload(self):
        # Regression for cx_run-allows / cx_check-denies deadlock on real beforeShellExecution
        # payloads (top-level command, not tool_input.command).
        cx_path = self._canonical_cx_path()
        if not os.path.isfile(cx_path):
            self.skipTest("canonical cx not installed at {0}".format(cx_path))
        proc = self._run_gate({
            "conversation_id": "b0608750-a01d-4d31-b255-7b6f180ebf7f",
            "generation_id": "bf389c7c-a92a-4934-b7d7-5bc7021b83ae",
            "model": "composer-2.5",
            "command": (
                '"{0}" auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant cx_seg'
            ).format(cx_path.replace("\\", "/")),
            "cwd": "",
            "sandbox": False,
            "session_id": "b0608750-a01d-4d31-b255-7b6f180ebf7f",
            "hook_event_name": "beforeShellExecution",
            "cursor_version": "3.13.10",
            "workspace_roots": ["/c:/Cx-Flow/Test/JavaVulnerabilityLabE"],
            "user_email": "kedar.bhujade@checkmarx.com",
            "transcript_path": (
                "c:\\Users\\kedarb\\.cursor\\projects\\c-Cx-Flow-Test-JavaVulnerabilityLabE\\"
                "agent-transcripts\\b0608750-a01d-4d31-b255-7b6f180ebf7f\\"
                "b0608750-a01d-4d31-b255-7b6f180ebf7f.jsonl"
            ),
        })
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    @unittest.skipUnless(sys.platform == "win32", "Windows canonical cx path")
    def test_native_before_shell_auth_login_with_tool_name_shell_uses_top_level_command(self):
        # Some Cursor builds may include tool_name alongside hook_event_name; the gate must still
        # read the top-level command (beforeShellExecution shape), not an empty tool_input.command.
        cx_path = self._canonical_cx_path()
        if not os.path.isfile(cx_path):
            self.skipTest("canonical cx not installed at {0}".format(cx_path))
        proc = self._run_gate({
            "tool_name": "Shell",
            "hook_event_name": "beforeShellExecution",
            "command": '"{0}" auth login --tenant cx_seg'.format(cx_path.replace("\\", "/")),
        })
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    @unittest.skipUnless(sys.platform == "win32", "Git-Bash POSIX path aliasing is Windows-only")
    def test_setup_diagnostic_allowed_with_gitbash_posix_cx_binary_path(self):
        # Same POSIX-path regression, but for the CX_BINARY-resolved absolute-path form
        # (`"<resolved cx>" version`) that _matches_bare_or_resolved_cx_subcommand builds.
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["CX_BINARY"] = sys.executable  # any real, existing absolute-path file
        posix_path = self._to_gitbash_posix(sys.executable)
        proc = subprocess.run(
            [sys.executable, CX_CHECK],
            input=json.dumps({
                "tool_name": "Shell",
                "tool_input": {"command": '"{0}" version'.format(posix_path)},
            }),
            text=True,
            capture_output=True,
            env=env,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    def test_plugin_owned_script_is_allowed_with_any_args(self):
        # Any script physically inside the plugin's own directory tree is trusted first-party
        # content — not just the narrow cx-bootstrap.sh install/upgrade shape.
        script = os.path.join(
            os.path.dirname(PLUGIN_HOOKS), "scripts", "cx-asset-resolver.sh"
        )
        proc = self._run_gate({
            "tool_name": "Shell",
            "tool_input": {"command": 'bash "{0}" some arbitrary args'.format(script)},
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    def test_script_outside_plugin_is_not_treated_as_plugin_owned(self):
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["CX_BINARY"] = r"C:\nonexistent\cx.exe"
        outside = os.path.join(os.path.dirname(PLUGIN_HOOKS), "..", "..", "evil.sh")
        proc = subprocess.run(
            [sys.executable, CX_CHECK],
            input=json.dumps({
                "tool_name": "Shell",
                "tool_input": {"command": 'bash "{0}" install'.format(outside)},
            }),
            text=True,
            capture_output=True,
            env=env,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout)

    def test_deny_json_includes_agent_message_prefix(self):
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["CX_BINARY"] = r"C:\nonexistent\cx.exe"
        proc = subprocess.run(
            [sys.executable, CX_CHECK],
            input=json.dumps({"tool_name": "Write", "tool_input": {}}),
            text=True,
            capture_output=True,
            env=env,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "deny")
        self.assertIn(DENY_PREFIX, out["agent_message"])
        # additional_context must mirror agent_message verbatim — Cursor's preToolUse response
        # surfaces additional_context to the agent; agent_message alone was not reliably reaching
        # it, which is why the MANDATORY recovery instructions were silently dropped.
        self.assertEqual(out["additional_context"], out["agent_message"])


if __name__ == "__main__":
    unittest.main()
