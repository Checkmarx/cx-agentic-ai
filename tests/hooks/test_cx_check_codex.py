"""Unit tests for the codex-devassist PreToolUse gate's Codex-specific behavior (cx_check.py).

This does NOT duplicate the full cx-devassist / copilot-devassist gate-logic suite
(tests/hooks/test_cx_check.py already covers that shared logic against the Claude copy) — it
covers only what differs in the codex-devassist copy: the --codex argv flag / _CODEX_MODE
detection, the $codex-cli-setup messaging via _setup_invocation(), the apply_patch matcher's
_bash_command/_tool_name handling, and that deny/allow output stays in the Claude-shaped nested
envelope (never the Copilot CLI flat shape) for a codex-mode invocation.

Run: python3 tests/hooks/test_cx_check_codex.py    (stdlib only — no pytest needed)
"""

import io
import json
import os
import shutil
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr

# Source under test lives in the plugin's hooks/ (tests live at the repo root, outside the plugin).
_HOOKS_DIR = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "plugins", "codex-devassist", "hooks"))
sys.path.insert(0, _HOOKS_DIR)
import cx_check  # noqa: E402

BOOTSTRAP = cx_check._bootstrap_script_path()

LAST_OUTPUT = None


def run(hook_input, *, which="cx", version_state="ok", authed=True,
        scanner_state=cx_check._SCANNER_SCAN, env=None, codex=True):
    """Invoke cx_check() with stubs. Returns (decision_or_None, exit_code).

    codex=True (default) simulates the --codex argv flag so _CODEX_MODE is set correctly,
    mirroring how hooks/hooks.json invokes `cx_check.sh --codex`."""
    orig = {
        "which": cx_check.shutil.which,
        "vstate": cx_check._version_state,
        "authed": cx_check._is_authenticated,
        "scanner": cx_check._scanner_state,
        "read": cx_check._read_hook_input,
        "environ": cx_check.os.environ,
        "copilot_cli_mode": cx_check._COPILOT_CLI_MODE,
        "codex_mode": cx_check._CODEX_MODE,
        "argv": sys.argv,
    }
    cx_check.shutil.which = lambda name: which
    cx_check._version_state = lambda identity=None: version_state
    cx_check._is_authenticated = lambda identity=None: authed
    cx_check._scanner_state = lambda identity=None: scanner_state
    cx_check._read_hook_input = lambda: hook_input
    sys.argv = ["cx_check.py", "--codex"] if codex else ["cx_check.py"]

    e = dict(env) if env is not None else {}
    if "CX_LOG_DIR" not in e:
        e.setdefault("CX_LOG_DISABLE", "1")
    cx_check.os.environ = e

    out = io.StringIO()
    code = 0
    try:
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            cx_check.cx_check()
    except SystemExit as ex:
        code = ex.code if isinstance(ex.code, int) else 1
    finally:
        cx_check.shutil.which = orig["which"]
        cx_check._version_state = orig["vstate"]
        cx_check._is_authenticated = orig["authed"]
        cx_check._scanner_state = orig["scanner"]
        cx_check._read_hook_input = orig["read"]
        cx_check.os.environ = orig["environ"]
        cx_check._COPILOT_CLI_MODE = orig["copilot_cli_mode"]
        cx_check._CODEX_MODE = orig["codex_mode"]
        sys.argv = orig["argv"]

    global LAST_OUTPUT
    LAST_OUTPUT = None
    decision = None
    text = out.getvalue().strip()
    if text:
        try:
            parsed = json.loads(text)
            if "hookSpecificOutput" in parsed:
                LAST_OUTPUT = parsed["hookSpecificOutput"]
                decision = LAST_OUTPUT["permissionDecision"]
            elif "permissionDecision" in parsed:
                LAST_OUTPUT = parsed
                decision = parsed["permissionDecision"]
            else:
                decision = "<unparseable:%s>" % text
        except (ValueError, KeyError):
            decision = "<unparseable:%s>" % text
    return decision, code


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def apply_patch(path="/x", content="x"):
    return {"tool_name": "apply_patch", "tool_input": {"file_path": path, "content": content}}


class TestCodexModeDetection(unittest.TestCase):
    def test_codex_flag_sets_codex_mode(self):
        # run() restores _CODEX_MODE in its own finally block, so assert on an observable
        # EFFECT of codex mode (the $-prefixed setup invocation in the deny message) rather
        # than the module flag after run() has already reset it.
        decision, _code = run(bash("npm test"), which=None, codex=True)
        self.assertEqual(decision, "deny")
        self.assertIn("$codex-cli-setup", LAST_OUTPUT["permissionDecisionReason"])

    def test_no_codex_flag_leaves_codex_mode_false(self):
        decision, _code = run(bash("npm test"), which=None, codex=False)
        self.assertEqual(decision, "deny")
        self.assertIn("/checkmarx-cli-setup", LAST_OUTPUT["permissionDecisionReason"])

    def test_setup_invocation_dollar_prefix_in_codex_mode(self):
        cx_check._CODEX_MODE = True
        try:
            self.assertEqual(cx_check._setup_invocation(), "$codex-cli-setup")
        finally:
            cx_check._CODEX_MODE = False

    def test_setup_invocation_slash_form_outside_codex_mode(self):
        cx_check._CODEX_MODE = False
        self.assertEqual(cx_check._setup_invocation(), "/checkmarx-cli-setup")


class TestCodexOutputEnvelope(unittest.TestCase):
    """Codex CLI's PreToolUse deny contract is confirmed identical to Claude Code's nested
    hookSpecificOutput shape — codex mode must NEVER take the Copilot CLI flat-JSON branch."""

    def test_cx_absent_denies_nested_shape_exit_2(self):
        decision, code = run(bash("npm test"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        self.assertIn("hookEventName", LAST_OUTPUT)
        self.assertEqual(LAST_OUTPUT["hookEventName"], "PreToolUse")

    def test_deny_reason_uses_dollar_invocation(self):
        decision, code = run(bash("npm test"), which=None)
        self.assertEqual(decision, "deny")
        self.assertIn("$codex-cli-setup", LAST_OUTPUT["permissionDecisionReason"])

    def test_below_min_version_denies_with_dollar_invocation(self):
        decision, code = run(bash("npm test"), version_state="below")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        self.assertIn("$codex-cli-setup", LAST_OUTPUT["additionalContext"])

    def test_unauthenticated_denies_with_dollar_invocation(self):
        decision, code = run(bash("npm test"), authed=False)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        self.assertIn("$codex-cli-setup", LAST_OUTPUT["additionalContext"])

    def test_allowed_when_ready(self):
        decision, code = run(bash("npm test"))
        self.assertIsNone(decision)
        self.assertEqual(code, 0)


class TestApplyPatchMatcher(unittest.TestCase):
    """Codex has a single file-mutation tool, apply_patch — unlike Claude's separate
    Write/Edit/MultiEdit/NotebookEdit tools. Confirm the gate recognizes it as a gated tool
    (not a Bash/shell tool, but still denies fail-closed when cx is absent)."""

    def test_apply_patch_tool_name_extracted(self):
        hook_input = apply_patch("/src/foo.py", "print('hi')")
        self.assertEqual(cx_check._tool_name(hook_input), "apply_patch")

    def test_apply_patch_is_not_a_shell_command(self):
        # _bash_command must return '' for apply_patch — it is not in _SHELL_TOOLS, so the
        # bootstrap/auth-recovery/read-only carve-outs (which only apply to shell commands)
        # never fire for a file-write tool call.
        hook_input = apply_patch("/src/foo.py", "print('hi')")
        self.assertEqual(cx_check._bash_command(hook_input), "")

    def test_apply_patch_denies_fail_closed_when_cx_absent(self):
        decision, code = run(apply_patch("/src/foo.py"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_apply_patch_allowed_when_ready(self):
        decision, code = run(apply_patch("/src/foo.py", "x = 1"))
        self.assertIsNone(decision)
        self.assertEqual(code, 0)


class TestBootstrapPlaceholder(unittest.TestCase):
    """Codex's plugin-root env var is PLUGIN_ROOT (not Claude's CLAUDE_PLUGIN_ROOT) —
    _is_bootstrap_command must recognize the ${PLUGIN_ROOT} placeholder form."""

    def test_plugin_root_placeholder_resolves_via_env(self):
        orig_environ = cx_check.os.environ
        cx_check.os.environ = {"PLUGIN_ROOT": os.path.dirname(_HOOKS_DIR)}
        try:
            hook_input = bash('bash "${PLUGIN_ROOT}/scripts/cx-bootstrap.sh" install')
            self.assertTrue(cx_check._is_bootstrap_command(hook_input))
        finally:
            cx_check.os.environ = orig_environ

    def test_plugin_root_placeholder_fails_closed_when_unset(self):
        orig_environ = cx_check.os.environ
        cx_check.os.environ = {}
        try:
            hook_input = bash('bash "${PLUGIN_ROOT}/scripts/cx-bootstrap.sh" install')
            self.assertFalse(cx_check._is_bootstrap_command(hook_input))
        finally:
            cx_check.os.environ = orig_environ

    def test_resolved_absolute_path_recognized(self):
        hook_input = bash('bash "%s" install' % BOOTSTRAP)
        self.assertTrue(cx_check._is_bootstrap_command(hook_input))


class TestCapabilityProbes(unittest.TestCase):
    def test_capability_probes_include_codex_subcommands(self):
        probes_flat = [" ".join(p) for p in cx_check._CAPABILITY_PROBES]
        self.assertTrue(
            any("codex-pre-tool-use" in p for p in probes_flat),
            "codex-pre-tool-use not in _CAPABILITY_PROBES: %r" % probes_flat)
        self.assertTrue(
            any("codex-pre-file-write" in p for p in probes_flat),
            "codex-pre-file-write not in _CAPABILITY_PROBES: %r" % probes_flat)
        self.assertTrue(
            any("codex-stop" in p for p in probes_flat),
            "codex-stop not in _CAPABILITY_PROBES: %r" % probes_flat)
        self.assertFalse(
            any("copilot-cli" in p for p in probes_flat),
            "codex-devassist's own probes should not reference copilot-cli subcommands: %r" % probes_flat)


if __name__ == "__main__":
    unittest.main(verbosity=2)
