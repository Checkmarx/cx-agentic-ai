"""Tests for the two behaviour changes on this branch:

  1. The readiness gate blocks only writes to files a Checkmarx engine can actually scan
     (ASCA / KICS / SCA). Everything else — other file types, and all shell commands — proceeds.
  2. The `run_shell_command` matcher carries ONLY the login-history observer, which must never block.

Covers, in order:
  - _load_scannable_files   — parsing and its fail-CLOSED failure modes
  - _is_scannable_file      — the gate's decision, incl. every union entry and the fail-closed paths
  - cx_record_login         — the observer records real logins, ignores everything else
  - record-login exit codes — end-to-end proof it exits 0 and emits no decision on EVERY path
  - drift guards            — the file-type lists still match ast-vscode-extension's engine filters

Dependency-free (stdlib only), like the sibling suites.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from _gemini_gatelib import (_HOOKS_DIR, _HistoryFileMixin, _bash, _pwsh, _run_shell,
                             _write_file, cx_check)


def _write(path):
    return {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}}


def _edit(path):
    return {"tool_name": "Edit", "tool_input": {"file_path": path, "old_string": "a",
                                                "new_string": "b"}}


def _notebook(path):
    return {"tool_name": "NotebookEdit", "tool_input": {"notebook_path": path,
                                                        "new_source": "x"}}


# Files every engine block must gate. Kept as a flat list because it doubles as the parity fixture
# for the shell matcher — both implementations must agree on every entry.
_SCANNABLE = [
    # ASCA (constants.ascaSupportedExtensions)
    "app.py", "Main.java", "a.js", "b.jsx", "Program.cs", "main.go",
    # KICS / IaC (constants.iacSupportedExtensions + iacSupportedPatterns)
    "main.tf", "k8s.yaml", "ci.yml", "tsconfig.json", "api.proto", "build.dockerfile",
    "vars.auto.tfvars", "vars.terraform.tfvars", "Dockerfile",
    # SCA (constants.supportedManifestFilePatterns)
    "App.csproj", "build.sbt", "pom.xml", "package.json",
    "Directory.Packages.props", "packages.config", "go.mod", "build.gradle", "settings.gradle",
    "build.gradle.kts", "app.gradle.kts", "libs.versions.toml", "setup.cfg", "setup.py",
    "pyproject.toml", "requirements.txt", "requirements-dev.txt", "constraints.txt",
    "constraints-prod.txt",
    # SCA — CocoaPods / Carthage / Swift PM / Ruby, added via ast-jetbrains-plugin PR #452
    "MyPod.podspec", "Podfile", "Cartfile", "Cartfile.private", "Package.swift", "Gemfile",
    # SCA — Bower / PHP Composer / Dart Pub / JSON-podspec, also from PR #452
    "bower.json", "composer.json", "pubspec.yaml", "MyPod.podspec.json",
    # case-insensitivity
    "App.JAVA", "DOCKERFILE", "Pom.XML", "MAIN.TF",
]

# Files no engine can scan — these must stop being gated.
_NOT_SCANNABLE = [
    "README.md", "notes.txt", "index.html", "style.css", "query.sql", "deploy.sh", "app.rb",
    "index.php", "main.c", "main.cpp", "lib.rs", "App.kt", "notebook.ipynb",
    "LICENSE", "Makefile", "data.csv", "logo.png",
    # ASCA in the VS Code extension does not scan TypeScript / .mjs / .cjs / .pyw
    "index.ts", "app.tsx", "mod.mjs", "mod.cjs", "script.pyw",
    # SCA does not scan these lockfiles / manifests
    "yarn.lock", "packages.txt",
    # Package@swift-*.swift (a versioned Swift PM manifest, PR #452) has no exact representation
    # in this file's vocabulary; plain .swift source is deliberately NOT gated as a side effect.
    "App.swift", "Package@swift-5.9.swift",
    # plain .tfvars is deliberately NOT gated: KICS lists only the compound .auto.tfvars /
    # .terraform.tfvars suffixes, so it would not be scanned.
    "vars.tfvars",
    # a .txt whose basename matches no SCA manifest prefix
    "changelog.txt", "todo.txt",
]


def _gemini_write(path):
    return _write_file(path)


class LoadScannableFiles(unittest.TestCase):
    def test_bundled_file_parses(self):
        table = cx_check._load_scannable_files()
        self.assertIsNotNone(table, "the shipped config/cx-scannable-files must parse")
        for kind in cx_check._SCANNABLE_KINDS:
            self.assertIn(kind, table)
        self.assertTrue(table["ext"] and table["suffix"] and table["base"] and table["txtprefix"])

    def test_values_are_lowercased(self):
        table = cx_check._load_scannable_files()
        for kind, values in table.items():
            for value in values:
                self.assertEqual(value, value.lower(), "%s:%s not lowercased" % (kind, value))

    def _tmp(self, text):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_comments_and_blanks_ignored(self):
        table = cx_check._load_scannable_files(
            self._tmp("# a comment\n\n   \next:.py\n# ext:.NOPE\n"))
        self.assertEqual(table["ext"], frozenset({".py"}))

    def test_unknown_kinds_dropped(self):
        table = cx_check._load_scannable_files(self._tmp("bogus:.py\next:.go\n"))
        self.assertEqual(table["ext"], frozenset({".go"}))

    def test_bom_tolerated(self):
        path = self._tmp("")
        with open(path, "w", encoding="utf-8-sig") as f:
            f.write("ext:.py\n")
        self.assertEqual(cx_check._load_scannable_files(path)["ext"], frozenset({".py"}))

    # --- fail-CLOSED failure modes: every one must yield None so callers gate everything ---

    def test_missing_file_is_none(self):
        self.assertIsNone(cx_check._load_scannable_files(
            os.path.join(tempfile.gettempdir(), "cx-no-such-file-12345")))

    def test_empty_file_is_none(self):
        self.assertIsNone(cx_check._load_scannable_files(self._tmp("")))

    def test_comments_only_is_none(self):
        """A file that parses to nothing must read as 'unreadable', not 'nothing is scannable' —
        the latter would silently disable the gate for every file."""
        self.assertIsNone(cx_check._load_scannable_files(self._tmp("# only comments\n\n")))

    def test_oversized_file_is_none(self):
        big = "ext:.py\n" + ("# padding\n" * cx_check._SCANNABLE_FILES_MAX_BYTES)
        self.assertIsNone(cx_check._load_scannable_files(self._tmp(big)))

    def test_never_raises_on_directory(self):
        self.assertIsNone(cx_check._load_scannable_files(tempfile.gettempdir()))


class IsScannableFile(unittest.TestCase):
    def test_scannable_are_gated(self):
        for name in _SCANNABLE:
            for payload in (_write("/proj/" + name), _edit("/proj/src/" + name)):
                self.assertTrue(cx_check._is_scannable_file(payload),
                                "%s must stay gated" % name)

    def test_unscannable_are_skipped(self):
        for name in _NOT_SCANNABLE:
            for payload in (_write("/proj/" + name), _edit("/proj/docs/" + name)):
                self.assertFalse(cx_check._is_scannable_file(payload),
                                 "%s must no longer be gated" % name)

    def test_windows_path_separators(self):
        self.assertTrue(cx_check._is_scannable_file(_write(r"C:\Users\a\proj\app.py")))
        self.assertFalse(cx_check._is_scannable_file(_write(r"C:\Users\a\proj\README.md")))

    def test_notebook_path_key(self):
        """NotebookEdit carries notebook_path, not file_path — both keys must be consulted."""
        self.assertTrue(cx_check._is_scannable_file(_notebook("/proj/app.py")))
        self.assertFalse(cx_check._is_scannable_file(_notebook("/proj/nb.ipynb")))

    # --- fail-CLOSED: anything undeterminable stays gated exactly as before ---

    def test_missing_path_is_gated(self):
        self.assertTrue(cx_check._is_scannable_file({"tool_name": "Write", "tool_input": {}}))

    def test_empty_and_blank_path_is_gated(self):
        for bad in ("", "   "):
            self.assertTrue(cx_check._is_scannable_file(_write(bad)))

    def test_non_string_path_is_gated(self):
        for bad in (None, 123, ["a"], {"a": 1}):
            self.assertTrue(cx_check._is_scannable_file(
                {"tool_name": "Write", "tool_input": {"file_path": bad}}))

    def test_non_dict_tool_input_is_gated(self):
        self.assertTrue(cx_check._is_scannable_file({"tool_name": "Write", "tool_input": "x"}))

    def test_mcp_call_is_gated(self):
        """MCP tool calls must remain gated — cx is required for the MCP to work at all."""
        self.assertTrue(cx_check._is_scannable_file(
            {"tool_name": "mcp__Checkmarx__codeRemediation", "tool_input": {"q": 1}}))

    def test_mcp_call_carrying_a_file_path_is_still_gated(self):
        """Regression: keying only off the PRESENCE of `file_path` let an MCP remediation call — which
        legitimately carries one, e.g. asked to patch README.md — skip the ENTIRE readiness chain. The
        tool name is what decides whether the file-type rule may apply at all."""
        for path in ("/proj/README.md", "/proj/notes.txt", "/proj/app.py"):
            self.assertTrue(cx_check._is_scannable_file(
                {"tool_name": "mcp__Checkmarx__codeRemediation",
                 "tool_input": {"file_path": path}}),
                "MCP call bypassed the gate via file_path=%s" % path)

    def test_shell_payload_carrying_a_file_path_is_still_gated(self):
        """Same hole from the other direction: a Bash payload with both `command` and a `file_path`
        key must not be narrowed by the file-type rule. Shell no longer reaches cx_check.py at all,
        but this keeps the predicate safe if the gate is ever re-wired onto shell."""
        self.assertTrue(cx_check._is_scannable_file(
            {"tool_name": "Bash",
             "tool_input": {"command": "echo hi", "file_path": "/proj/README.md"}}))

    def test_unknown_file_tool_is_gated(self):
        """Only the tools in _FILE_WRITE_TOOLS may be narrowed. A future file tool added to
        hooks.json but not here is gated — the safe direction."""
        self.assertTrue(cx_check._is_scannable_file(
            {"tool_name": "WriteFileV2", "tool_input": {"file_path": "/proj/README.md"}}))

    def test_leading_dot_basenames(self):
        """os.path.splitext gives NO extension for `.py`, but DOES for `.foo.py`. A shell
        reimplementation of this rule collapsed both to "no extension", so `.foo.py` — a real Python
        file — was classified unscannable and written unscanned. Python is now the only
        implementation; these pin the boundary so it cannot drift back."""
        for name in (".foo.py", ".hidden.java", ".a.tf", ".config.json"):
            self.assertTrue(cx_check._is_scannable_file(_write("/proj/" + name)), name)
        for name in (".py", ".go", ".java", ".gitignore", ".env"):
            self.assertFalse(cx_check._is_scannable_file(_write("/proj/" + name)), name)

    def test_quotes_in_paths_are_classified_normally(self):
        """A `"` in a path needed no special handling once the shell matcher was deleted — Python's
        basename handles it. The earlier payload-wide bail-out that existed for shell parity had
        blocked any file whose CONTENT contained a quote."""
        self.assertTrue(cx_check._is_scannable_file(_write('/proj/sub"dir/app.py')))
        self.assertFalse(cx_check._is_scannable_file(_write('/proj/q"uote.md')))
        self.assertFalse(cx_check._is_scannable_file(
            {"tool_name": "Write",
             "tool_input": {"file_path": "/proj/README.md", "content": 'he said "hi"'}}))

    def test_unknown_tool_is_gated(self):
        """An assistant this gate does not know (e.g. the out-of-repo Cursor integration, which
        sends beforeShellExecution / preToolUse) must keep its current behaviour."""
        for tool in ("beforeShellExecution", "preToolUse", "SomethingNew"):
            self.assertTrue(cx_check._is_scannable_file({"tool_name": tool, "tool_input": {}}))

    def test_unloadable_config_gates_everything(self):
        orig = cx_check._load_scannable_files
        cx_check._load_scannable_files = lambda path=None: None
        try:
            self.assertTrue(cx_check._is_scannable_file(_write("/proj/README.md")))
        finally:
            cx_check._load_scannable_files = orig

    def test_gate_all_files_env_forces_gating(self):
        os.environ["CX_GATE_ALL_FILES"] = "1"
        try:
            self.assertTrue(cx_check._is_scannable_file(_write("/proj/README.md")))
        finally:
            del os.environ["CX_GATE_ALL_FILES"]

    def test_gemini_write_file_tool_is_scannable(self):
        for name in ("app.py", "package.json", "main.tf"):
            self.assertTrue(cx_check._is_scannable_file(_gemini_write("/proj/" + name)),
                            name)

    def test_gemini_write_file_tool_skips_unscannable(self):
        for name in ("README.md", "notes.txt", "deploy.sh"):
            self.assertFalse(cx_check._is_scannable_file(_gemini_write("/proj/" + name)),
                             name)

    def test_shell_tools_have_no_path_so_are_gated(self):
        """Shell tools no longer reach cx_check.py at all (hooks.json gives the
        run_shell_command matcher only the observer). But this predicate must still fail CLOSED for them, so that
        re-wiring the gate onto shell in future can never silently open it."""
        self.assertTrue(cx_check._is_scannable_file(_bash("npm test")))
        self.assertTrue(cx_check._is_scannable_file(_pwsh("Get-ChildItem")))
        self.assertTrue(cx_check._is_scannable_file(_run_shell("npm test")))


class RecordLoginObserver(_HistoryFileMixin):
    """`cx_check.py record-login` — the ONLY thing the plugin runs on run_shell_command now.

    Its defining property is that it OBSERVES and never blocks: the shell matcher no longer carries
    the readiness gate, so this must not be able to reintroduce "every command is blocked". It exists
    because ast-cli's `cx auth login` skips its prompt when connection flags are supplied and then
    persists only the refresh token (auth_login.go:102) — and the flag form is the only one an agent
    can issue, so --base-auth-uri / --tenant are visible only as the command goes past.
    """

    def setUp(self):
        super().setUp()
        cx_check._LOGIN_HISTORY_FILE = self.path   # redirect history writes to the temp file

    def tearDown(self):
        cx_check._LOGIN_HISTORY_FILE = self._orig_history
        super().tearDown()

    _orig_history = cx_check._LOGIN_HISTORY_FILE

    def _observe(self, payload):
        """Drive cx_record_login() over a payload by faking stdin, the way the hook does."""
        orig = cx_check._read_hook_input
        cx_check._read_hook_input = lambda: payload
        try:
            cx_check.cx_record_login()
        finally:
            cx_check._read_hook_input = orig
        return cx_check._load_login_history(self.path)

    def test_records_gemini_run_shell_command(self):
        entries = self._observe(_run_shell(
            "cx auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant acme"))
        self.assertEqual(1, len(entries))
        self.assertEqual("acme", entries[0]["tenant"])

    def test_records_a_clean_login(self):
        entries = self._observe(_bash(
            "cx auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant acme"))
        self.assertEqual(1, len(entries))
        self.assertEqual("acme", entries[0]["tenant"])
        self.assertEqual("https://eu.ast.checkmarx.net", entries[0]["base_auth_uri"])
        self.assertEqual("pending", entries[0]["status"])

    def test_snapshots_credential_mtime_before_the_login(self):
        """cred_before is what _promote_pending_login later requires to have CHANGED. A PostToolUse
        hook could not do this — it would record the POST-login mtime, the comparison would always be
        equal, and nothing would ever be promoted. This asserts the pre-login snapshot survives."""
        self._set_cred_mtime(4242.0)
        entries = self._observe(_bash(
            "cx auth login --base-auth-uri https://us.ast.checkmarx.net --tenant t1"))
        self.assertEqual(4242.0, entries[0]["cred_before"])

    def test_records_the_documented_absolute_path_forms(self):
        """references/oauth.md hands the agent `"$HOME/.checkmarx/bin/cx" auth login …` inside a code
        fence. The gate's _is_auth_recovery_command rejects that (it pins the absolute form to the
        gate's OWN resolved cx, correctly, because it is a PERMISSION guard) — but reusing it as the
        observation filter turned every rejected shape into SILENT data loss now that Bash is ungated:
        the login succeeds and nothing is remembered. The observer uses a looser matcher instead."""
        for cmd in (
            'cx auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant acme',
            'cx.exe auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant acme',
            '"$HOME/.checkmarx/bin/cx" auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant acme',
            '"$LOCALAPPDATA/Checkmarx/cx/cx.exe" auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant acme',
            '"$HOME/.checkmarx/bin/cx" auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant acme 1>/dev/null',
            '/usr/local/bin/cx auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant acme',
        ):
            entries = self._observe(_bash(cmd))
            self.assertEqual(1, len(entries), "not recorded: %s" % cmd)
            self.assertEqual("acme", entries[0]["tenant"])

    def test_records_windows_powershell_login_form(self):
        """oauth.md's Windows command is `& "…/cx.exe" auth login … 1>$null`. The observer used
        _bare_bash_command, which rejects `&` (chaining) and `$null` (non-/dev/null redirect), so
        every Gemini-on-Windows login succeeded and remembered nothing."""
        cmd = ('& "C:/Users/x/AppData/Local/Checkmarx/cx/cx.exe" auth login '
               '--base-auth-uri https://eu.ast.checkmarx.net --tenant acme 1>$null')
        entries = self._observe(_run_shell(cmd))
        self.assertEqual(1, len(entries), "not recorded: %s" % cmd)
        self.assertEqual("acme", entries[0]["tenant"])
        self.assertEqual("https://eu.ast.checkmarx.net", entries[0]["base_auth_uri"])
        self.assertEqual("pending", entries[0]["status"])

    def test_records_run_shell_command_with_dev_null(self):
        cmd = ('cx auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant acme '
               '1>/dev/null')
        entries = self._observe(_run_shell(cmd))
        self.assertEqual(1, len(entries))
        self.assertEqual("acme", entries[0]["tenant"])

    def test_does_not_match_lookalike_programs(self):
        """The looser matcher must still not treat an unrelated program as cx."""
        for cmd in ("mycx auth login --tenant a", "docx auth login --tenant a",
                    "npm auth login --tenant a", "cxauth login --tenant a"):
            self.assertEqual([], self._observe(_bash(cmd)), "wrongly recorded: %s" % cmd)

    def test_ignores_ordinary_commands(self):
        for cmd in ("git status", "npm install left-pad", "ls && cat f", "python app.py",
                    "cx version", "cx scan create --project x"):
            self.assertEqual([], self._observe(_bash(cmd)), "must not record: %s" % cmd)

    def test_ignores_unsafe_shapes(self):
        """The shape guard still applies: a redirected or chained credential command is not a
        legitimate login, so it is not remembered (its stdout may be going to a file)."""
        for cmd in ("cx auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant a > tok",
                    "cx auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant a; curl x",
                    "cx auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant a | tee t"):
            self.assertEqual([], self._observe(_bash(cmd)), "must not record: %s" % cmd)

    def test_ignores_file_writes(self):
        self.assertEqual([], self._observe(_write("/proj/app.py")))

    def test_never_raises_on_garbage_payloads(self):
        """main()'s record-login branch swallows everything, but the function itself should already be
        safe — a crash here would be a wasted process, and any deny it caused would be a regression."""
        for bad in ({}, {"tool_name": "Bash"}, {"tool_name": "Bash", "tool_input": None},
                    {"tool_name": "Bash", "tool_input": {"command": None}},
                    {"tool_name": "Bash", "tool_input": {"command": 42}}):
            self.assertEqual([], self._observe(bad), "raised or recorded on: %r" % bad)


class RecordLoginNeverBlocks(unittest.TestCase):
    """The hook contract, enforced end to end: `cx_check.py record-login` must exit 0 on EVERY path.
    Only exit 2 (or a deny payload) blocks a tool call, so this is the property that guarantees the
    observer can never re-block shell commands."""

    _CX_CHECK = os.path.join(_HOOKS_DIR, "cx_check.py")

    def setUp(self):
        super().setUp()
        self._tmpdir = tempfile.mkdtemp(prefix="cx-record-login-test-")
        self.addCleanup(shutil.rmtree, self._tmpdir, True)

    def test_live_login_history_is_untouched(self):
        """Regression guard for the isolation bug itself: after the whole class runs, the developer's
        real history file must not have been created or modified by these tests."""
        real = os.path.join(os.path.expanduser("~"), ".checkmarx", "agent-logs",
                            os.environ.get("CX_ASSISTANT", "gemini-cli"), "cx_login_history.json")
        before = os.path.getmtime(real) if os.path.exists(real) else None
        self._exit_code(
            '{"tool_name":"Bash","tool_input":{"command":"cx auth login --base-auth-uri '
            'https://eu.ast.checkmarx.net --tenant isolation-probe"}}')
        after = os.path.getmtime(real) if os.path.exists(real) else None
        self.assertEqual(before, after, "the test suite wrote to the developer's real %s" % real)
        # And the pair really did land in the redirected dir, proving the probe was not a no-op.
        self.assertTrue(os.path.exists(os.path.join(self._tmpdir, "cx_login_history.json")),
                        "recording did not happen at all — this test would pass vacuously")

    def _exit_code(self, payload, env=None):
        e = dict(os.environ)
        e["CX_LOG_DISABLE"] = "1"
        # CX_LOG_DIR is MANDATORY here, not optional tidiness: CX_LOG_DISABLE gates cx_log only, so
        # without it _record_login_attempt writes a fabricated pair into the developer's REAL
        # ~/.checkmarx/agent-logs/<assistant>/cx_login_history.json. That pair then gets promoted to
        # "confirmed" on their next real authentication and offered back to them as an environment
        # they had used. A unit test must never touch live state.
        e["CX_LOG_DIR"] = self._tmpdir
        if env:
            e.update(env)
        proc = subprocess.run(
            [sys.executable, self._CX_CHECK, "record-login"],
            input=payload.encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e, timeout=120,
        )
        return proc.returncode, proc.stdout

    def test_exit_zero_and_no_output_for_every_payload(self):
        for payload in (
            '{"tool_name":"Bash","tool_input":{"command":"git status"}}',
            '{"tool_name":"Bash","tool_input":{"command":"cx auth login --base-auth-uri '
            'https://eu.ast.checkmarx.net --tenant acme"}}',
            '{"tool_name":"Write","tool_input":{"file_path":"/p/app.py"}}',
            '{"tool_name":"Bash"}',
            '{}',
            'not json at all',
            '',
        ):
            code, out = self._exit_code(payload)
            self.assertEqual(0, code, "must exit 0 for: %s" % payload[:60])
            # A deny payload on stdout would block even with exit 0.
            self.assertNotIn(b"permissionDecision", out,
                             "must never emit a permission decision: %s" % payload[:60])

    def test_exit_zero_when_state_dir_is_unusable(self):
        """An unwritable log/state dir must cost a remembered environment, never the command."""
        code, out = self._exit_code(
            '{"tool_name":"Bash","tool_input":{"command":"cx auth login --base-auth-uri '
            'https://eu.ast.checkmarx.net --tenant acme"}}',
            env={"CX_LOG_DIR": os.path.join(_HOOKS_DIR, "cx_check.py")},  # a FILE, not a dir
        )
        self.assertEqual(0, code)
        self.assertNotIn(b"permissionDecision", out)


class EngineDriftGuards(unittest.TestCase):
    """If Checkmarx adds a language to an engine, ast-vscode-extension changes but this plugin's
    list does not — and the gate silently stops covering those writes. These guards turn that into
    a failing test. Update BOTH config/cx-scannable-files and the expectation here, together."""

    def test_asca_extensions(self):
        """Mirrors ascaSupportedExtensions — constants.ts (Java, C#, Go, Python, JS/JSX)."""
        expected = frozenset({".java", ".cs", ".go", ".py", ".js", ".jsx"})
        self.assertTrue(expected <= cx_check._load_scannable_files()["ext"])
        # TypeScript / ESM / .pyw are not in ascaSupportedExtensions
        for extra in (".ts", ".tsx", ".mjs", ".cjs", ".pyw"):
            self.assertNotIn(extra, cx_check._load_scannable_files()["ext"], extra)

    def test_kics_suffixes(self):
        """Mirrors iacSupportedExtensions + iacSupportedPatterns — constants.ts.
        Dockerfile is a basename (**/Dockerfile), not an extension."""
        expected = frozenset({".tf", ".yaml", ".yml", ".json", ".proto", ".dockerfile",
                              ".auto.tfvars", ".terraform.tfvars"})
        table = cx_check._load_scannable_files()
        self.assertTrue(expected <= table["suffix"])
        self.assertIn("dockerfile", table["base"])

    def test_sca_manifests(self):
        """Mirrors supportedManifestFilePatterns — constants.ts."""
        table = cx_check._load_scannable_files()
        self.assertTrue(frozenset({".csproj", ".sbt", ".gradle"}) <= table["ext"])
        self.assertIn(".gradle.kts", table["suffix"])
        expected_bases = frozenset({
            "pom.xml", "package.json", "directory.packages.props",
            "packages.config", "go.mod", "libs.versions.toml",
            "setup.cfg", "setup.py", "pyproject.toml",
        })
        self.assertTrue(expected_bases <= table["base"])
        self.assertEqual(frozenset({"requirement", "constraint"}), table["txtprefix"])
        for dropped in ("yarn.lock", "build.gradle", "build.gradle.kts"):
            self.assertNotIn(dropped, table["base"], dropped)

    def test_sca_manifests_jetbrains_package_managers(self):
        """Mirrors DevAssistConstants.MANIFEST_FILE_PATTERNS —
        ast-jetbrains-plugin PR #452 ("Enhance Package Manager Support"), which covers more
        package managers here than ast-vscode-extension currently does: CocoaPods, Carthage,
        Swift Package Manager, Ruby Bundler, Bower, PHP Composer, Dart/Flutter Pub."""
        table = cx_check._load_scannable_files()
        self.assertIn(".podspec", table["ext"])
        self.assertIn(".podspec.json", table["suffix"])
        expected_bases = frozenset({
            "podfile", "cartfile", "cartfile.private", "package.swift", "gemfile",
            "bower.json", "composer.json", "pubspec.yaml",
        })
        self.assertTrue(expected_bases <= table["base"])


class CxAbsentStageTwo(unittest.TestCase):
    """cx_run.sh's cx-UNRESOLVABLE branch: a file write must DEFER to stage 1, an MCP call must DENY.

    Regression test for a bug the Python-only tests could not see. _is_scannable_file was correct and
    logged `allow / unscannable_file`, but stage 2 denied the same call unconditionally — so on a
    cx-less machine a one-line `list_files.sh` was still BLOCKED. Verdicts merge most-restrictive-wins
    across the matcher, so stage 1 being right is not enough: BOTH stages must agree. Found only by
    running the real plugin on a VM with no cx.

    Nothing here re-implements the file-type rule; the assertion is that stage 2 stays silent for
    file writes and lets stage 1's decision stand.
    """

    @classmethod
    def setUpClass(cls):
        cls.sh = shutil.which("sh")
        if not cls.sh:
            raise unittest.SkipTest("POSIX sh unavailable")
        cls.run_sh = os.path.join(_HOOKS_DIR, "cx_run.sh")
        cls.check_sh = os.path.join(_HOOKS_DIR, "cx_check.sh")

    def _env_without_cx(self):
        """Defeat all three resolution tiers (CX_BINARY -> canonical store -> PATH) so cx is genuinely
        unresolvable, mirroring a machine where it was never installed."""
        env = dict(os.environ, CX_LOG_DISABLE="1")
        env.pop("CX_BINARY", None)
        self._store = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._store, True)
        env["LOCALAPPDATA"] = self._store          # Windows canonical store
        env["HOME"] = self._store                  # Unix canonical store (~/.checkmarx/bin/cx)
        env["USERPROFILE"] = self._store
        keep = []
        for d in env.get("PATH", "").split(os.pathsep):
            if not d:
                continue
            if any(os.path.exists(os.path.join(d, n)) for n in ("cx", "cx.exe")):
                continue                           # drop any dir that supplies cx
            keep.append(d)
        env["PATH"] = os.pathsep.join(keep)
        return env

    def _stage(self, script, args, payload):
        p = subprocess.run([self.sh, script] + args, input=json.dumps(payload).encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=self._env_without_cx(), timeout=60)
        return p.returncode, p.stdout.decode("utf-8", "replace")

    def _stage2_write(self, path):
        return self._stage(self.run_sh, ["hooks", "gemini-before-file-tool"], _write(path))

    def test_stage2_defers_on_unscannable_write(self):
        for path in ("/kode/list_files.sh", "/kode/README.md", "/kode/notes.css"):
            with self.subTest(path=path):
                code, out = self._stage2_write(path)
                self.assertEqual(0, code, "stage 2 must not deny a file write when cx is absent")
                self.assertNotIn("deny", out)

    def test_stage2_also_defers_on_scannable_write(self):
        """Stage 2 defers for EVERY file type — stage 1 is what denies a scannable one."""
        code, out = self._stage2_write("/kode/app.py")
        self.assertEqual(0, code)
        self.assertNotIn("deny", out)

    def _stage1_write(self, path):
        return self._stage(self.check_sh, ["--gemini-cli"], _write(path))

    def test_stage1_still_denies_scannable_write_when_cx_absent(self):
        """The other half of the contract: deferring is only safe because stage 1 holds the line."""
        for path, expect_deny in (("/kode/app.py", True), ("/kode/main.tf", True),
                                  ("/kode/list_files.sh", False), ("/kode/README.md", False)):
            with self.subTest(path=path):
                code, out = self._stage1_write(path)
                if expect_deny:
                    self.assertEqual(0, code, "Gemini deny must exit 0")
                    self.assertIn("deny", out)
                else:
                    self.assertEqual(0, code)
                    self.assertNotIn("deny", out)

    def test_stage2_still_denies_mcp_when_cx_absent(self):
        """Only the file-write case defers; a Checkmarx MCP call has no stage-1-equivalent fallback
        behaviour worth relaxing and stays fail-closed here."""
        payload = {"tool_name": "mcp__Checkmarx__codeRemediation", "tool_input": {}}
        code, out = self._stage(self.run_sh, ["hooks", "gemini-before-tool"], payload)
        self.assertEqual(0, code, "Gemini deny must exit 0")
        self.assertIn("deny", out)


if __name__ == "__main__":
    unittest.main()
