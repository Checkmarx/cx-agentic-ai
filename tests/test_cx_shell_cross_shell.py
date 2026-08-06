"""Cross-shell tests for the cx-devassist-cursor plugin: hooks/cx_shell.py plus the carve-outs in
hooks/cx_check.py that depend on it.

Why this file exists. Cursor's default shell on Windows is PowerShell, and the plugin's own deny
messages tell the agent to run `cx auth login` / the bundled bootstrap. Before hooks/cx_shell.py, the
gate recognized only bash-shaped spellings of those commands, so the following legitimate forms were
all DENIED — including several the plugin's OWN skills instruct the agent to use:

  & 'C:\\…\\cx.exe' auth validate                      (PowerShell single-quoted path)
  & "$env:LOCALAPPDATA\\…\\cx.exe" auth validate       (PowerShell env reference)
  "%LOCALAPPDATA%\\…\\cx.exe" auth validate            (cmd env reference — `%` was banned outright)
  "$LOCALAPPDATA/Checkmarx/cx/cx.exe" auth validate    (Git-Bash env reference; SKILL.md's own form)
  powershell -c "…"                                    (`-c`, the short form of -Command)

Each of those is asserted below, alongside the security invariants that must NOT loosen: chaining,
command substitution, cmd's `^`-escaped `&`, a redirect to a real file, and an untrusted executable
path all still fail the carve-out.

Run from the repo root:  python -m unittest discover -s tests -v
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import unittest
import unittest.mock


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HOOKS_DIR = os.path.join(_REPO_ROOT, "plugins", "cx-devassist-cursor", "hooks")
_CX_CHECK_PATH = os.path.join(_HOOKS_DIR, "cx_check.py")
_CX_CHECK_SH = os.path.join(_HOOKS_DIR, "cx_check.sh")
_BOOTSTRAP = os.path.join(
    _REPO_ROOT, "plugins", "cx-devassist-cursor", "scripts", "cx-bootstrap.sh")

# Private module names so this file can never collide in sys.modules with the sibling test modules
# that load the same (or the Claude plugin's) cx_check.py.
_spec = importlib.util.spec_from_file_location("cx_check_cursor_crossshell", _CX_CHECK_PATH)
cx_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cx_check)
cx_shell = cx_check.cx_shell

_SH = shutil.which("sh") or shutil.which("bash")

# A cx path that does NOT exist on disk: the carve-out compares against the gate's RESOLVED cx (which
# these tests monkeypatch), and only the absolute_path_only variant requires the file to exist — so
# using a fake path keeps the tests independent of whether cx happens to be installed on the runner.
_FAKE_CX_WIN = r"C:\Users\dev\AppData\Local\Checkmarx\cx\cx.exe"
_FAKE_CX_UNIX = "/home/dev/.checkmarx/bin/cx"


def _hook_input(command):
    """A native Cursor beforeShellExecution payload (top-level "command", no tool_input wrapper)."""
    return {"hook_event_name": "beforeShellExecution", "command": command}


class TestUnwrapPowerShellValueTakingFlags(unittest.TestCase):
    """Regression: cx_shell.unwrap() must peel a PowerShell wrapper whose startup switches include
    ones that take a SEPARATE value token (`-ExecutionPolicy Bypass`, `-WindowStyle Hidden`,
    `-InputFormat Text`) — not just bare `-flag` tokens. `-NoProfile -NonInteractive -ExecutionPolicy
    Bypass -Command "…"` is a routine non-interactive PowerShell invocation; a pattern that only
    accepted a run of bare flags stopped matching at `Bypass` (it has no leading `-`), so the ENTIRE
    wrapper was left unrecognized. That silently denied `cx auth login` and the bundled bootstrap
    install in a real Cursor session on Windows, where PowerShell is the default shell."""

    def _wrapped(self, prefix_flags, inner):
        escaped = inner.replace('"', '\\"')
        return '{0} -Command "{1}"'.format(prefix_flags, escaped)

    def test_execution_policy_bypass_is_unwrapped(self):
        inner = 'bash "C:/plugin/scripts/cx-bootstrap.sh" install'
        wrapped = self._wrapped(
            "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass", inner)
        unwrapped, shell = cx_shell.unwrap(wrapped)
        self.assertEqual(unwrapped, inner)
        self.assertEqual(shell, cx_shell.POWERSHELL)

    def test_window_style_hidden_is_unwrapped(self):
        inner = 'cx auth validate'
        wrapped = self._wrapped("powershell -WindowStyle Hidden", inner)
        unwrapped, shell = cx_shell.unwrap(wrapped)
        self.assertEqual(unwrapped, inner)
        self.assertEqual(shell, cx_shell.POWERSHELL)

    def test_multiple_value_taking_flags_combined(self):
        inner = 'cx auth validate'
        wrapped = self._wrapped(
            "pwsh -NoLogo -InputFormat Text -ExecutionPolicy Bypass -WindowStyle Hidden", inner)
        unwrapped, shell = cx_shell.unwrap(wrapped)
        self.assertEqual(unwrapped, inner)
        self.assertEqual(shell, cx_shell.POWERSHELL)

    def test_short_c_flag_with_value_taking_prefix_flags(self):
        inner = 'cx auth validate'
        wrapped = '{0} -c "{1}"'.format(
            "powershell -ExecutionPolicy Bypass -NoProfile", inner.replace('"', '\\"'))
        unwrapped, shell = cx_shell.unwrap(wrapped)
        self.assertEqual(unwrapped, inner)
        self.assertEqual(shell, cx_shell.POWERSHELL)

    def test_bash_c_double_quoted_wrapper_is_unwrapped(self):
        inner = '& "C:/Users/dev/AppData/Local/Checkmarx/cx/cx.exe" auth validate'
        wrapped = 'bash -c "{0}"'.format(inner.replace('"', '\\"'))
        unwrapped, shell = cx_shell.unwrap(wrapped)
        self.assertEqual(unwrapped, inner)
        self.assertEqual(shell, cx_shell.BASH)


class TestShellRendering(unittest.TestCase):
    """cx_shell.render_invocation must emit syntax that is VALID AS WRITTEN in each shell."""

    def test_powershell_absolute_path_gets_the_call_operator(self):
        # Without `&`, PowerShell evaluates a quoted path as a string EXPRESSION and prints it
        # instead of running anything — the command silently does nothing.
        rendered = cx_shell.render_invocation(cx_shell.POWERSHELL, _FAKE_CX_WIN, "auth validate")
        self.assertTrue(rendered.startswith('& "'), rendered)
        self.assertIn("auth validate", rendered)

    def test_posix_absolute_path_has_no_call_operator(self):
        # A leading `&` is a syntax error in bash, so the POSIX form must never carry it.
        rendered = cx_shell.render_invocation(cx_shell.BASH, _FAKE_CX_WIN, "auth validate")
        self.assertFalse(rendered.startswith("&"), rendered)
        self.assertTrue(rendered.startswith('"'), rendered)

    def test_cmd_absolute_path_has_no_call_operator(self):
        rendered = cx_shell.render_invocation(cx_shell.CMD, _FAKE_CX_WIN, "auth validate")
        self.assertFalse(rendered.startswith("&"), rendered)

    def test_bare_name_is_identical_in_every_shell(self):
        rendered = {cx_shell.render_invocation(s, "cx", "auth validate")
                    for s in cx_shell.SUPPORTED_SHELLS}
        self.assertEqual(rendered, {"cx auth validate"})

    @unittest.skipUnless(os.name == "nt", "separator flip is Windows-only")
    def test_separators_match_the_shell(self):
        self.assertIn("/", cx_shell.render_invocation(cx_shell.BASH, _FAKE_CX_WIN, "version"))
        self.assertNotIn("\\", cx_shell.render_invocation(cx_shell.BASH, _FAKE_CX_WIN, "version"))
        self.assertIn("\\", cx_shell.render_invocation(cx_shell.CMD, _FAKE_CX_WIN, "version"))

    def test_null_device_is_per_shell(self):
        self.assertEqual(cx_shell.null_redirect(cx_shell.POWERSHELL), "1>$null")
        self.assertEqual(cx_shell.null_redirect(cx_shell.CMD), "1>NUL")
        self.assertEqual(cx_shell.null_redirect(cx_shell.BASH), "1>/dev/null")
        self.assertEqual(cx_shell.null_redirect(cx_shell.SH), "1>/dev/null")

    def test_login_rendering_always_suppresses_stdout(self):
        # `cx auth login` prints a LIVE refresh token on stdout; every rendered form must discard it
        # using that shell's own null device.
        for shell, expected in (
            (cx_shell.POWERSHELL, "1>$null"),
            (cx_shell.CMD, "1>NUL"),
            (cx_shell.BASH, "1>/dev/null"),
        ):
            rendered = cx_shell.render_invocation(
                shell, _FAKE_CX_WIN, "auth login --tenant acme", suppress_stdout=True)
            self.assertTrue(rendered.endswith(expected), (shell, rendered))

    def test_json_argument_quoting_per_shell(self):
        payload = '{"packageName":"lodash"}'
        # cmd.exe has no literal-quote form, so inner double quotes must be backslash-escaped.
        self.assertEqual(cx_shell.quote_arg(cx_shell.CMD, payload),
                         '"{\\"packageName\\":\\"lodash\\"}"')
        # PowerShell and POSIX both take single quotes, leaving the JSON untouched.
        self.assertEqual(cx_shell.quote_arg(cx_shell.POWERSHELL, payload), "'%s'" % payload)
        self.assertEqual(cx_shell.quote_arg(cx_shell.BASH, payload), "'%s'" % payload)

    def test_render_with_json_data_per_shell(self):
        payload = '{"packageName":"lodash"}'
        args = "ignore-vulnerability --scan-type sca"
        ps = cx_shell.render_with_json_data(cx_shell.POWERSHELL, _FAKE_CX_WIN, args, payload)
        self.assertIn("ignore-vulnerability", ps)
        self.assertIn('"{""packageName"":""lodash""}"', ps)
        self.assertTrue(ps.startswith("& "), ps)
        cmd = cx_shell.render_with_json_data(cx_shell.CMD, _FAKE_CX_WIN, args, payload)
        self.assertIn('"{""packageName"":""lodash""}"', cmd)
        bash = cx_shell.render_with_json_data(cx_shell.BASH, _FAKE_CX_WIN, args, payload)
        self.assertIn('"{\\"packageName\\":\\"lodash\\"}"', bash)

    def test_path_with_spaces_stays_one_argument(self):
        spaced = os.path.join("C:" + os.sep, "Program Files", "Checkmarx", "cx.exe")
        for shell in cx_shell.SUPPORTED_SHELLS:
            rendered = cx_shell.render_invocation(shell, spaced, "version")
            self.assertIn('"', rendered, (shell, rendered))
            self.assertIn("Program Files", rendered)


class TestVariantsBlock(unittest.TestCase):
    def setUp(self):
        self._orig = os.environ.get(cx_shell.SHELL_OVERRIDE_ENV)

    def tearDown(self):
        if self._orig is None:
            os.environ.pop(cx_shell.SHELL_OVERRIDE_ENV, None)
        else:
            os.environ[cx_shell.SHELL_OVERRIDE_ENV] = self._orig

    def test_bare_cx_collapses_to_a_single_line(self):
        block = cx_shell.variants_block("cx", "auth validate")
        self.assertEqual(block.strip(), "cx auth validate")
        self.assertNotIn("PowerShell", block)

    @unittest.skipUnless(os.name == "nt", "the multi-shell block is emitted on Windows")
    def test_detected_shell_is_listed_first(self):
        os.environ[cx_shell.SHELL_OVERRIDE_ENV] = "cmd"
        block = cx_shell.variants_block(_FAKE_CX_WIN, "auth validate")
        lines = [ln for ln in block.splitlines() if ln.startswith("    ")]
        self.assertTrue(lines[0].strip().startswith("cmd.exe:"), block)
        # …and every shell is still offered, so a mis-detection is recoverable by the agent.
        self.assertIn("PowerShell:", block)
        self.assertIn("bash / sh:", block)


@unittest.skipUnless(os.name == "nt", "Windows canonical-store path shapes")
class TestAuthCarveOutAcrossShells(unittest.TestCase):
    """Every shell's spelling of the SAME `cx auth …` command must reach the auth-recovery allow."""

    def setUp(self):
        self._orig_cx_exe = cx_check._cx_exe
        cx_check._cx_exe = lambda: _FAKE_CX_WIN

    def tearDown(self):
        cx_check._cx_exe = self._orig_cx_exe

    def _assert_allowed(self, command):
        self.assertTrue(
            cx_check._is_auth_recovery_command(_hook_input(command)),
            "should be recognized as auth recovery: " + command,
        )

    def _assert_rejected(self, command):
        self.assertFalse(
            cx_check._is_auth_recovery_command(_hook_input(command)),
            "must NOT be recognized as auth recovery: " + command,
        )

    def test_powershell_single_quoted_path(self):
        self._assert_allowed("& '{0}' auth validate".format(_FAKE_CX_WIN))

    def test_powershell_double_quoted_path(self):
        self._assert_allowed('& "{0}" auth validate'.format(_FAKE_CX_WIN))

    def test_powershell_env_reference(self):
        # LOCALAPPDATA is what _FAKE_CX_WIN is built from only on a matching machine, so pin the
        # variable for the duration of the assertion instead of depending on the runner's value.
        os.environ["CX_TEST_STORE"] = os.path.dirname(_FAKE_CX_WIN)
        self.addCleanup(os.environ.pop, "CX_TEST_STORE", None)
        self._assert_allowed('& "$env:CX_TEST_STORE\\cx.exe" auth validate')

    def test_cmd_percent_env_reference(self):
        os.environ["CX_TEST_STORE"] = os.path.dirname(_FAKE_CX_WIN)
        self.addCleanup(os.environ.pop, "CX_TEST_STORE", None)
        self._assert_allowed('"%CX_TEST_STORE%\\cx.exe" auth validate 1>NUL')

    def test_gitbash_env_reference(self):
        # The exact form skills/cx-devassist-{asca,sca}/SKILL.md tell the agent to use.
        os.environ["CX_TEST_STORE"] = os.path.dirname(_FAKE_CX_WIN).replace("\\", "/")
        self.addCleanup(os.environ.pop, "CX_TEST_STORE", None)
        self._assert_allowed('"$CX_TEST_STORE/cx.exe" auth validate 1>/dev/null')

    def test_powershell_wrapper_short_c_flag(self):
        inner = '& \\"{0}\\" auth validate'.format(_FAKE_CX_WIN)
        self._assert_allowed('powershell -NoProfile -c "{0}"'.format(inner))

    def test_bash_c_double_quoted_wrapper(self):
        self._assert_allowed('bash -c "& \\"{0}\\" auth validate"'.format(_FAKE_CX_WIN))

    def test_powershell_wrapper_long_command_flag(self):
        inner = '& \\"{0}\\" auth validate'.format(_FAKE_CX_WIN)
        self._assert_allowed('powershell -NoProfile -Command "{0}"'.format(inner))

    def test_powershell_wrapper_with_value_taking_flags(self):
        # Same regression as TestBootstrapCarveOutAcrossShells: `-ExecutionPolicy Bypass` is a
        # value-taking switch (no leading `-` on the value), and it broke the auth-recovery carve-out
        # the same way it broke the bootstrap one — one shared unwrapper, one shared bug, one fix.
        inner = '& \\"{0}\\" auth validate'.format(_FAKE_CX_WIN)
        self._assert_allowed(
            'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "{0}"'
            .format(inner))

    def test_cmd_c_wrapper_with_extra_flags(self):
        self._assert_allowed('cmd.exe /d /s /c ""{0}" auth login --tenant acme 1>NUL"'.format(
            _FAKE_CX_WIN))

    def test_hooks_check_auth_is_session_validation(self):
        # Session/licence validation is part of the trusted setup surface: it must not be blocked by
        # the very auth state it exists to report.
        self._assert_allowed("cx hooks check-auth")
        self._assert_allowed('& "{0}" hooks check-auth'.format(_FAKE_CX_WIN))

    # --- invariants that must NOT loosen ---------------------------------------------------------

    def test_chaining_is_still_rejected(self):
        self._assert_rejected("& '{0}' auth login; rm -rf /".format(_FAKE_CX_WIN))

    def test_caret_escaped_ampersand_is_still_rejected(self):
        self._assert_rejected('cmd /c ""{0}" auth login ^& evil"'.format(_FAKE_CX_WIN))

    def test_command_substitution_is_still_rejected(self):
        self._assert_rejected('"{0}" auth login --tenant $(whoami)'.format(_FAKE_CX_WIN))

    def test_redirect_to_a_real_file_is_still_rejected(self):
        # `cx auth login` prints a live token on stdout — capturing it to a file must never pass.
        self._assert_rejected('& "{0}" auth login 1>C:/tmp/token.txt'.format(_FAKE_CX_WIN))

    def test_untrusted_executable_is_still_rejected(self):
        self._assert_rejected("& 'C:\\evil\\cx.exe' auth login")

    def test_variable_expanding_to_an_untrusted_path_is_rejected(self):
        # Expansion must not become a way to launder an arbitrary path into the carve-out: the
        # EXPANDED value still has to equal the gate's resolved cx.
        os.environ["CX_TEST_STORE"] = "C:\\evil"
        self.addCleanup(os.environ.pop, "CX_TEST_STORE", None)
        self._assert_rejected('& "$env:CX_TEST_STORE\\cx.exe" auth validate')

    def test_variable_expanding_to_a_chained_value_is_rejected(self):
        # A value carrying a metacharacter is caught because the chaining scan runs AFTER expansion.
        os.environ["CX_TEST_STORE"] = "C:\\a;C:\\b"
        self.addCleanup(os.environ.pop, "CX_TEST_STORE", None)
        self._assert_rejected('& "$env:CX_TEST_STORE\\cx.exe" auth validate')

    def test_unknown_variable_stays_literal_and_is_rejected(self):
        os.environ.pop("CX_TEST_ABSENT", None)
        self._assert_rejected('"%CX_TEST_ABSENT%\\cx.exe" auth validate')


class TestBootstrapCarveOutAcrossShells(unittest.TestCase):
    """`bash "<bootstrap>" install` is spelled identically in every shell, but the QUOTING style and
    the wrapper Cursor adds are not — all of them must still resolve to the bundled bootstrap."""

    def _assert_allowed(self, command):
        self.assertTrue(cx_check._is_bootstrap_command(_hook_input(command))
                        or cx_check._is_plugin_script_command(_hook_input(command)),
                        "should be a trusted plugin script: " + command)

    def test_double_quoted_path(self):
        self._assert_allowed('bash "{0}" install'.format(_BOOTSTRAP.replace("\\", "/")))

    def test_single_quoted_path(self):
        self._assert_allowed("bash '{0}' install".format(_BOOTSTRAP.replace("\\", "/")))

    def test_unquoted_path(self):
        self._assert_allowed("bash {0} install".format(_BOOTSTRAP.replace("\\", "/")))

    def test_powershell_wrapped(self):
        inner = 'bash \\"{0}\\" install'.format(_BOOTSTRAP.replace("\\", "/"))
        self._assert_allowed('powershell -NoProfile -Command "{0}"'.format(inner))

    def test_powershell_wrapped_with_value_taking_flags(self):
        # Regression: PowerShell startup switches are not all bare `-flag` tokens — several take a
        # SEPARATE value with no leading `-` of its own (-ExecutionPolicy Bypass, -WindowStyle
        # Hidden). `-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "…"` is an entirely
        # ordinary non-interactive PowerShell invocation, and it is exactly the shape that denied the
        # bootstrap install in a real Cursor session (the bare-`-flag`-only unwrap pattern stopped at
        # `Bypass`, since it isn't itself a `-flag`, so the whole wrapper was left unrecognized and
        # every carve-out — bootstrap, auth, setup diagnostics — silently denied).
        inner = 'bash \\"{0}\\" install'.format(_BOOTSTRAP.replace("\\", "/"))
        self._assert_allowed(
            'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "{0}"'
            .format(inner))

    def test_powershell_wrapped_with_window_style_flag(self):
        inner = 'bash \\"{0}\\" install'.format(_BOOTSTRAP.replace("\\", "/"))
        self._assert_allowed('powershell -WindowStyle Hidden -Command "{0}"'.format(inner))

    def test_script_outside_the_plugin_is_still_rejected(self):
        for command in ("bash '/tmp/evil.sh' install", "bash /tmp/evil.sh install"):
            self.assertFalse(cx_check._is_bootstrap_command(_hook_input(command)), command)
            self.assertFalse(cx_check._is_plugin_script_command(_hook_input(command)), command)


class TestReadOnlyCarveOutAcrossShells(unittest.TestCase):
    """The same "is cx present?" probe is `which`/`where`/`Get-Command` depending on the shell."""

    def _allowed(self, command):
        return cx_check._is_readonly_command(_hook_input(command), "Shell")

    def test_probe_forms(self):
        for command in ("which cx", "where cx", "Get-Command cx", "get-command cx", "dir", "ver"):
            self.assertTrue(self._allowed(command), command)

    def test_write_capable_commands_are_still_gated(self):
        for command in ("Set-Content x", "Out-File x", "tee x", "New-Item x", "Invoke-Expression x"):
            self.assertFalse(self._allowed(command), command)

    def test_chained_probe_is_still_gated(self):
        self.assertFalse(self._allowed("where cx || which cx"))


class TestMatchTrustedSetupCli(unittest.TestCase):
    """The `--match-trusted-setup` CLI is the SINGLE matcher the sh stages delegate to, so its exit
    codes are load-bearing: 0 = trusted (allow), 1 = not trusted (fall through to the gate),
    anything else = undecided (the sh caller uses its own fallback rather than denying recovery)."""

    def _run(self, hook_input):
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        return subprocess.run(
            [sys.executable, _CX_CHECK_PATH, "--match-trusted-setup"],
            input=json.dumps(hook_input), text=True, capture_output=True, env=env, timeout=60,
        )

    def test_bootstrap_exits_zero(self):
        proc = self._run(_hook_input('bash "{0}" install'.format(_BOOTSTRAP.replace("\\", "/"))))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "", "the match CLI must print nothing")

    def test_bare_auth_exits_zero(self):
        self.assertEqual(self._run(_hook_input("cx auth validate")).returncode, 0)

    def test_setup_diagnostic_exits_zero(self):
        self.assertEqual(self._run(_hook_input("cx version")).returncode, 0)

    def test_setup_diagnostic_bash_c_double_quote_exits_zero(self):
        self.assertEqual(
            self._run(_hook_input('bash -c "cx version"')).returncode, 0)

    def test_unrelated_command_exits_one(self):
        self.assertEqual(self._run(_hook_input("rm -rf /tmp/x")).returncode, 1)

    def test_chained_auth_exits_one(self):
        self.assertEqual(self._run(_hook_input("cx auth validate; rm -rf /")).returncode, 1)

    def test_empty_stdin_exits_one(self):
        proc = subprocess.run(
            [sys.executable, _CX_CHECK_PATH, "--match-trusted-setup"],
            input="", text=True, capture_output=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)


class TestSetupStepsAllPlatforms(unittest.TestCase):
    """Steps 1–4 (bootstrap install/upgrade, auth, validate, version) must be allowed on every OS."""

    def setUp(self):
        self._orig_cx_exe = cx_check._cx_exe
        self._orig_recovery = cx_check._cx_recovery_exe
        if os.name == "nt":
            cx_check._cx_exe = lambda: _FAKE_CX_WIN
            cx_check._cx_recovery_exe = lambda: _FAKE_CX_WIN
            self._cx = _FAKE_CX_WIN
        else:
            cx_check._cx_exe = lambda: _FAKE_CX_UNIX
            cx_check._cx_recovery_exe = lambda: _FAKE_CX_UNIX
            self._cx = _FAKE_CX_UNIX

    def tearDown(self):
        cx_check._cx_exe = self._orig_cx_exe
        cx_check._cx_recovery_exe = self._orig_recovery

    def _assert_auth_allowed(self, command):
        self.assertTrue(
            cx_check._is_auth_recovery_command(_hook_input(command)),
            "step 2/3 auth must be allowed: " + command,
        )

    def test_step1_bootstrap_install(self):
        boot = _BOOTSTRAP.replace("\\", "/")
        for command in (
            'bash "{0}" install'.format(boot),
            "sh '{0}' install".format(boot),
            'bash "{0}" upgrade'.format(boot),
        ):
            self.assertTrue(
                cx_check._is_bootstrap_command(_hook_input(command))
                or cx_check._is_plugin_script_command(_hook_input(command)),
                command,
            )

    def test_step2_auth_login_bare_cx(self):
        self._assert_auth_allowed("cx auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant t")

    def test_step3_auth_validate_bare_cx(self):
        self._assert_auth_allowed("cx auth validate")

    def test_step3_auth_validate_absolute_path(self):
        if os.name == "nt":
            self._assert_auth_allowed('& "{0}" auth validate'.format(self._cx))
            self._assert_auth_allowed('"{0}" auth validate'.format(self._cx.replace("\\", "/")))
        else:
            self._assert_auth_allowed('"{0}" auth validate'.format(self._cx))
            os.environ["CX_TEST_HOME"] = os.path.dirname(self._cx)
            self.addCleanup(os.environ.pop, "CX_TEST_HOME", None)
            self._assert_auth_allowed('"$CX_TEST_HOME/cx" auth validate')

    def test_step3_hooks_check_auth(self):
        self._assert_auth_allowed("cx hooks check-auth")
        self._assert_auth_allowed('"{0}" hooks check-auth'.format(self._cx))

    def test_step4_version_and_utils_env(self):
        for command in ("cx version", '"{0}" version'.format(self._cx), "cx utils env"):
            self.assertTrue(
                cx_check._is_setup_diagnostic_command(_hook_input(command), "Shell"),
                command,
            )

    def test_recovery_block_uses_canonical_path_when_cx_not_resolved(self):
        cx_check._cx_exe = lambda: "cx"
        cx_check._cx_recovery_exe = self._orig_recovery
        block = cx_check._cx_recovery_command_block("auth validate")
        canon = cx_check._canonical_cx_path().replace("\\", "/")
        self.assertIn(canon, block.replace("\\", "/"))


@unittest.skipUnless(_SH, "sh not found on PATH")
@unittest.skipUnless(os.name == "nt", "Windows canonical-store path shapes")
class TestCxCheckShDelegatesAcrossShells(unittest.TestCase):
    """End-to-end through the sh launcher: hooks/cx_check.sh must allow the PowerShell and cmd
    spellings BEFORE the Python gate runs, because it reaches the same matcher via
    _cx_bootstrap_match.sh -> cx_check.py --match-trusted-setup. Stage 1 and stage 2 disagreeing on
    one command blocks the tool call, so this is the property that has to hold end to end."""

    def _canonical_cx(self):
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, "Checkmarx", "cx", "cx.exe")

    def _run(self, command):
        proc = subprocess.run(
            [_SH, _CX_CHECK_SH], input=json.dumps(_hook_input(command)),
            text=True, capture_output=True, env=os.environ.copy(), timeout=60,
        )
        return proc

    def test_powershell_and_cmd_auth_forms_are_allowed(self):
        cx_path = self._canonical_cx()
        if not os.path.isfile(cx_path):
            self.skipTest("canonical cx not installed")
        for command in (
            "& '{0}' auth validate".format(cx_path),
            '& "{0}" auth validate'.format(cx_path),
            '& "$env:LOCALAPPDATA\\Checkmarx\\cx\\cx.exe" auth validate',
            '"%LOCALAPPDATA%\\Checkmarx\\cx\\cx.exe" auth validate 1>NUL',
            'cmd /c ""{0}" auth validate"'.format(cx_path),
            "cx hooks check-auth",
        ):
            proc = self._run(command)
            self.assertEqual(proc.returncode, 0, (command, proc.stdout, proc.stderr))
            self.assertEqual(json.loads(proc.stdout.strip())["permission"], "allow", command)


class TestNormalizeCxFilesystemPath(unittest.TestCase):
    def test_msys_drive_colon_form(self):
        self.assertEqual(
            cx_shell.normalize_cx_filesystem_path("/c:/Cx-Flow/Test/.checkmarx/finding.json"),
            "C:/Cx-Flow/Test/.checkmarx/finding.json",
        )

    def test_msys_atfile(self):
        self.assertEqual(
            cx_shell.normalize_cx_filesystem_path("@/c:/project/.checkmarx/f.json"),
            "@C:/project/.checkmarx/f.json",
        )


class TestCheckmarxIgnorePrepCarveOut(unittest.TestCase):
    def test_new_item_out_null_allowed(self):
        cmd = (
            'New-Item -ItemType Directory -Force -Path '
            '"c:\\Cx-Flow\\Test\\JavaVulnerabilityLabE\\.checkmarx" | Out-Null'
        )
        self.assertTrue(cx_check._is_checkmarx_ignore_prep_command(_hook_input(cmd)))

    def test_set_content_allowed(self):
        cmd = (
            'Set-Content -Path "c:\\project\\.checkmarx\\finding.json" '
            '-Value \'{"FileName":"Demo.java"}\' -NoNewline'
        )
        self.assertTrue(cx_check._is_checkmarx_ignore_prep_command(_hook_input(cmd)))

    def test_unrelated_new_item_rejected(self):
        cmd = 'New-Item -ItemType Directory -Force -Path "c:\\temp" | Out-Null'
        self.assertFalse(cx_check._is_checkmarx_ignore_prep_command(_hook_input(cmd)))


class TestIgnoreVulnerabilityAtFile(unittest.TestCase):
    def test_atfile_data_allowed(self):
        cx_path = _FAKE_CX_WIN
        cmd = (
            '& "{0}" ignore-vulnerability --scan-type asca '
            '--data "@c:/project/.checkmarx/finding.json" '
            '--ignored-file-path "c:/project/.checkmarx/checkmarxIgnoredTempList.json"'
        ).format(cx_path)
        with unittest.mock.patch.object(cx_check, "_is_trusted_cx_exe_path", return_value=True):
            self.assertTrue(cx_check._is_ignore_vulnerability_command(_hook_input(cmd)))


@unittest.skipUnless(_SH, "sh not found on PATH")
class TestCxCheckShIgnorePrepFastPath(unittest.TestCase):
    def test_checkmarx_prep_allowed_before_full_gate(self):
        hook_input = {
            "command": (
                'New-Item -ItemType Directory -Force -Path '
                '"c:\\project\\.checkmarx" | Out-Null'
            ),
            "hook_event_name": "beforeShellExecution",
        }
        proc = subprocess.run(
            [_SH, _CX_CHECK_SH], input=json.dumps(hook_input),
            text=True, capture_output=True, env=os.environ.copy(), timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout.strip())["permission"], "allow")


if __name__ == "__main__":
    unittest.main()
