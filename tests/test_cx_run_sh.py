"""Regression tests for hooks/cx_run.sh — the stage-2 shell wrapper that runs the native cx
scanner. This module is POSIX sh/bash, so it is not covered by any Python import test; these tests
shell out to `bash` directly. They exist because two real, undiscovered bugs shipped in this file:

1. A missing opening quote (`_CXRUN_BOOTSTRAP=$(...)/scripts/cx-bootstrap.sh"`, no leading `"`)
   left an UNTERMINATED string that swallowed the rest of the case-arm, producing a hard bash
   PARSE-TIME syntax error ("syntax error near unexpected token `('") for the ENTIRE script — not
   just this branch. Since `bash -n` fails on a parse error before any code runs, this broke
   *every* beforeShellExecution/beforeMCPExecution hook invocation, not only the cx-absent path.
2. The cx-absent deny JSON embeds a `cygpath -w`-resolved (backslash-form) Windows path, and a
   static "%LOCALAPPDATA%\\Checkmarx\\cx\\cx.exe" string, directly into an UNQUOTED heredoc
   (`<<JSON`, needed so `${_CXRUN_BOOTSTRAP}` expands). Unquoted heredocs collapse `\\` pairs the
   same way a double-quoted string does, so both backslash sources silently lost a backslash on
   their way to stdout, producing INVALID JSON that Cursor cannot parse.

Run from the repo root:  python -m unittest discover -s tests -v
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOOKS_DIR = os.path.join(_REPO_ROOT, "plugins", "cursor-devassist", "hooks")
CX_RUN = os.path.join(_HOOKS_DIR, "cx_run.sh")
CX_CHECK_SH = os.path.join(_HOOKS_DIR, "cx_check.sh")
BOOTSTRAP = os.path.join(_REPO_ROOT, "plugins", "cursor-devassist", "scripts", "cx-bootstrap.sh")

_BASH = shutil.which("bash")
_SH = shutil.which("sh") or _BASH


@unittest.skipUnless(_BASH, "bash not found on PATH")
class TestCxRunShSyntax(unittest.TestCase):
    def test_bash_parses_the_whole_script(self):
        """`bash -n` must succeed — a parse-time syntax error anywhere in this file breaks
        EVERY invocation of it, not just the branch containing the bug (AST cx_run.sh
        heredoc/quoting regression)."""
        proc = subprocess.run([_BASH, "-n", CX_RUN], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)


@unittest.skipUnless(_BASH, "bash not found on PATH")
class TestCxRunShCxAbsent(unittest.TestCase):
    """Exercises the "cx could not be resolved anywhere" branch (hooks/cx_run.sh, the
    *cursor-before-shell* case arm).

    cx_run.sh resolves cx from THREE places (CX_BINARY -> the canonical per-OS store -> PATH), so
    all three have to be neutralized or the branch is never reached and every assertion here
    silently tests the real scanner instead: CX_BINARY is cleared, HOME/LOCALAPPDATA/USERPROFILE are
    repointed at an empty temp dir so the canonical store is absent, and PATH entries that actually
    contain a cx binary are dropped (rather than emptying PATH, which would also remove the
    bash/cygpath/sed tools the script itself needs)."""

    def _env(self):
        env = os.environ.copy()
        env.pop("CX_BINARY", None)
        empty_home = tempfile.mkdtemp(prefix="cx-absent-home-")
        self.addCleanup(shutil.rmtree, empty_home, True)
        for var in ("HOME", "LOCALAPPDATA", "USERPROFILE"):
            env[var] = empty_home
        kept = [
            entry for entry in env.get("PATH", "").split(os.pathsep)
            if entry and not any(
                os.path.isfile(os.path.join(entry, name)) for name in ("cx", "cx.exe")
            )
        ]
        env["PATH"] = os.pathsep.join(kept)
        return env

    def _run(self, hook_input):
        proc = subprocess.run(
            [_BASH, CX_RUN, "hooks", "cursor-before-shell"],
            input=json.dumps(hook_input),
            capture_output=True,
            text=True,
            env=self._env(),
            timeout=30,
        )
        return proc

    def test_deny_emits_valid_json(self):
        proc = self._run({
            "tool_name": "Shell",
            "hook_event_name": "beforeShellExecution",
            "tool_input": {"command": "ls -la"},
        })
        self.assertEqual(proc.returncode, 2, proc.stderr)
        out = json.loads(proc.stdout.strip())  # raises if the JSON is malformed
        self.assertEqual(out["permission"], "deny")
        self.assertIn("CHECKMARX_HOOK_DENY", out["agent_message"])
        # The canonical-store hint must round-trip as a real single backslash per separator,
        # not the raw double-backslash source text or a collapsed-to-nothing empty string.
        self.assertIn(r"%LOCALAPPDATA%\Checkmarx\cx\cx.exe", out["agent_message"])
        # additional_context must mirror agent_message verbatim — Cursor's preToolUse response
        # surfaces additional_context to the agent, not agent_message alone.
        self.assertEqual(out["additional_context"], out["agent_message"])

    def test_bootstrap_command_is_allowed(self):
        command = 'bash "{0}" install'.format(BOOTSTRAP.replace("\\", "/"))
        proc = self._run({
            "tool_name": "Shell",
            "hook_event_name": "beforeShellExecution",
            "tool_input": {"command": command},
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    @unittest.skipUnless(sys.platform == "win32", "Windows backslash bootstrap path")
    def test_native_before_shell_bootstrap_with_backslashes_is_allowed(self):
        # Cursor's native beforeShellExecution shape carries top-level "command" (no tool_input).
        # Deny messages embed Windows backslash paths; the shell matcher must accept them.
        command = 'bash "{0}" install'.format(BOOTSTRAP)
        proc = self._run({
            "command": command,
            "hook_event_name": "beforeShellExecution",
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    def test_other_plugin_owned_script_with_arbitrary_args_is_allowed(self):
        # _cx_bootstrap_match.sh's broadened carve-out: ANY *.sh under the plugin's scripts/ or
        # hooks/ directory, not just cx-bootstrap.sh install/upgrade — this is what lets
        # references/manual-install.md's `bash "<plugin-root>/scripts/cx-asset-resolver.sh"` run.
        other_script = os.path.join(
            os.path.dirname(BOOTSTRAP), "cx-asset-resolver.sh"
        ).replace("\\", "/")
        proc = self._run({
            "tool_name": "Shell",
            "hook_event_name": "beforeShellExecution",
            "tool_input": {"command": 'bash "{0}" some arbitrary args'.format(other_script)},
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    def test_script_outside_plugin_is_still_denied(self):
        proc = self._run({
            "tool_name": "Shell",
            "hook_event_name": "beforeShellExecution",
            "tool_input": {"command": 'bash "/tmp/evil.sh" install'},
        })
        self.assertEqual(proc.returncode, 2, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "deny")


@unittest.skipUnless(_SH, "sh not found on PATH")
class TestCxCheckShBootstrapAllow(unittest.TestCase):
    """cx_check.sh must allow bootstrap BEFORE invoking Python — same as cx_run.sh."""

    def test_native_before_shell_bootstrap_with_backslashes_is_allowed(self):
        bootstrap = os.path.abspath(BOOTSTRAP)
        hook_input = {
            "command": 'bash "{0}" install'.format(bootstrap),
            "hook_event_name": "beforeShellExecution",
        }
        env = os.environ.copy()
        env.pop("CX_BINARY", None)
        proc = subprocess.run(
            [_SH, CX_CHECK_SH],
            input=json.dumps(hook_input),
            text=True,
            capture_output=True,
            env=env,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")


@unittest.skipUnless(_SH, "sh not found on PATH")
class TestCxCheckShAuthRecoveryAllow(unittest.TestCase):
    """cx_check.sh must allow cx auth recovery before invoking Python."""

    def _canonical_cx(self):
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, "Checkmarx", "cx", "cx.exe")

    @unittest.skipUnless(sys.platform == "win32", "Windows canonical cx path")
    def test_auth_validate_allowed_via_shell_carve_out(self):
        cx_path = self._canonical_cx()
        if not os.path.isfile(cx_path):
            self.skipTest("canonical cx not installed")
        hook_input = {
            "command": '"{0}" auth validate'.format(cx_path.replace("\\", "/")),
            "hook_event_name": "beforeShellExecution",
        }
        proc = subprocess.run(
            [_SH, CX_CHECK_SH],
            input=json.dumps(hook_input),
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")

    @unittest.skipUnless(sys.platform == "win32", "Windows canonical cx path")
    def test_auth_login_bash_c_allowed_via_shell_carve_out(self):
        cx_path = self._canonical_cx()
        if not os.path.isfile(cx_path):
            self.skipTest("canonical cx not installed")
        inner = (
            '"{0}" auth login --base-auth-uri https://eu.ast.checkmarx.net '
            "--tenant cx_seg 1>/dev/null"
        ).format(cx_path.replace("\\", "/"))
        command = "bash -c '{0}'".format(inner)
        proc = subprocess.run(
            [_SH, CX_CHECK_SH],
            input=json.dumps({
                "hook_event_name": "beforeShellExecution",
                "command": command,
            }),
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "allow")


@unittest.skipUnless(_SH, "sh not found on PATH")
class TestCxCheckShDenyAdditionalContext(unittest.TestCase):
    """cx_check.sh's hand-written no-Python deny (the only JSON it emits directly; the normal
    path just relays cx_check.py's own JSON) must also carry additional_context alongside
    agent_message — Cursor's preToolUse response surfaces additional_context to the agent, not
    agent_message alone, so every hand-written deny JSON in this plugin needs both."""

    def test_no_python_deny_has_matching_additional_context(self):
        env = os.environ.copy()
        env.pop("CX_BINARY", None)
        # Force the "no working Python 3" branch regardless of what's actually installed, by
        # putting a fake `python3`/`python`/`py` ahead on PATH that always fails the probe.
        fake_bin_dir = tempfile.mkdtemp(prefix="cx-no-python-")
        self.addCleanup(shutil.rmtree, fake_bin_dir, True)
        for name in ("python3", "python", "py"):
            path = os.path.join(fake_bin_dir, name)
            with open(path, "w", newline="\n") as f:
                f.write("#!/bin/sh\nexit 1\n")
            os.chmod(path, 0o755)
        env["PATH"] = fake_bin_dir + os.pathsep + env.get("PATH", "")
        proc = subprocess.run(
            [_SH, CX_CHECK_SH],
            input=json.dumps({"tool_name": "Shell", "tool_input": {"command": "ls"}}),
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 2, proc.stderr)
        out = json.loads(proc.stdout.strip())
        self.assertEqual(out["permission"], "deny")
        self.assertIn("additional_context", out)
        self.assertEqual(out["additional_context"], out["agent_message"])


if __name__ == "__main__":
    unittest.main()
