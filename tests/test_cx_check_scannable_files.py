"""Tests for the two behaviour changes on this branch:

  1. The readiness gate blocks only writes to files a Checkmarx engine can actually scan
     (ASCA / KICS / SCA). Everything else — other file types, and all shell commands — proceeds.
  2. The `Bash|PowerShell` matcher carries ONLY the login-history observer, which must never block.

Covers, in order:
  - _load_scannable_files   — parsing and its fail-CLOSED failure modes
  - _is_scannable_file      — the gate's decision, incl. every union entry and the fail-closed paths
  - cx_record_login         — the observer records real logins, ignores everything else
  - record-login exit codes — end-to-end proof it exits 0 and emits no decision on EVERY path
  - drift guards            — the file-type lists still match ast-cli's own engine filters

Dependency-free (stdlib only), like the sibling suites.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from _gatelib import _HOOKS_DIR, _HistoryFileMixin, _bash, _pwsh, cx_check


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
    # ASCA (asca.go:19-22)
    "app.py", "script.pyw", "Main.java", "a.js", "b.jsx", "c.ts", "d.tsx", "e.mjs", "f.cjs",
    "Program.cs", "main.go",
    # KICS (params/filters.go:197-207)
    "main.tf", "k8s.yaml", "ci.yml", "tsconfig.json", "api.proto", "build.dockerfile",
    "vars.auto.tfvars", "vars.terraform.tfvars", "Dockerfile",
    # SCA (oss-realtime.go:200-238)
    "App.csproj", "build.sbt", "pom.xml", "package.json", "bower.json", "yarn.lock",
    "Directory.Packages.props", "packages.config", "go.mod", "build.gradle", "build.gradle.kts",
    "libs.versions.toml", "setup.cfg", "setup.py", "pyproject.toml",
    "requirements.txt", "requirements-dev.txt", "packages.txt", "constraints.txt",
    # case-insensitivity
    "App.JAVA", "DOCKERFILE", "Pom.XML", "MAIN.TF",
]

# Files no engine can scan — these must stop being gated.
_NOT_SCANNABLE = [
    "README.md", "notes.txt", "index.html", "style.css", "query.sql", "deploy.sh", "app.rb",
    "index.php", "main.c", "main.cpp", "lib.rs", "App.kt", "App.swift", "notebook.ipynb",
    "LICENSE", "Makefile", "data.csv", "logo.png",
    # plain .tfvars is deliberately NOT gated: KICS lists only the compound .auto.tfvars /
    # .terraform.tfvars suffixes (kics.go:33 uses HasSuffix), so it would not be scanned.
    "vars.tfvars",
    # a .txt whose basename matches no SCA manifest prefix
    "changelog.txt", "todo.txt",
]


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

    def test_shell_tools_have_no_path_so_are_gated(self):
        """Shell tools no longer reach cx_check.py at all (hooks.json gives the Bash|PowerShell
        matcher only the observer). But this predicate must still fail CLOSED for them, so that
        re-wiring the gate onto shell in future can never silently open it."""
        self.assertTrue(cx_check._is_scannable_file(_bash("npm test")))
        self.assertTrue(cx_check._is_scannable_file(_pwsh("Get-ChildItem")))


class RecordLoginObserver(_HistoryFileMixin):
    """`cx_check.py record-login` — the ONLY thing the plugin runs on Bash/PowerShell now.

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
                            os.environ.get("CX_ASSISTANT", "claude"), "cx_login_history.json")
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
    """If Checkmarx adds a language to an engine, ast-cli changes but this plugin's list does not —
    and the gate silently stops covering those writes. These guards turn that into a failing test.
    Update BOTH config/cx-scannable-files and the expectation here, together."""

    def test_asca_extensions(self):
        """Mirrors ascaSupportedExtensions — asca.go:19-22 (Java, JS/TS, C#, Go, Python)."""
        expected = frozenset({".java", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
                              ".cs", ".go", ".py", ".pyw"})
        self.assertTrue(expected <= cx_check._load_scannable_files()["ext"])

    def test_kics_suffixes(self):
        """Mirrors params.KicsBaseFilters — filters.go:197-207. Dockerfile is a basename there."""
        expected = frozenset({".tf", ".yaml", ".yml", ".json", ".proto", ".dockerfile",
                              ".auto.tfvars", ".terraform.tfvars"})
        table = cx_check._load_scannable_files()
        self.assertTrue(expected <= table["suffix"])
        self.assertIn("dockerfile", table["base"])

    def test_sca_manifests(self):
        """Mirrors validateSupportedManifestFile — oss-realtime.go:200-238."""
        table = cx_check._load_scannable_files()
        self.assertTrue(frozenset({".csproj", ".sbt"}) <= table["ext"])
        expected_bases = frozenset({
            "pom.xml", "package.json", "bower.json", "yarn.lock", "directory.packages.props",
            "packages.config", "go.mod", "build.gradle", "build.gradle.kts",
            "libs.versions.toml", "setup.cfg", "setup.py", "pyproject.toml",
        })
        self.assertTrue(expected_bases <= table["base"])
        self.assertEqual(frozenset({"requirement", "packages", "constraint"}),
                         table["txtprefix"])


class SessionStartAnnouncer(unittest.TestCase):
    """`cx_session_start.sh` / `cx_check.py session-start` — announces posture, never blocks.

    Two properties. Stdout must be a clean JSON object, because Claude Code reads it AS the
    announcement, and any stray interpreter output (sitecustomize, PYTHONSTARTUP, a conda banner, a
    corporate wrapper) would become the banner. And the posture must never claim more than the gate
    delivers: an inactive scanner has to read as inactive, and the wording must stay scoped.

    One subprocess is shared by the read-only assertions — they inspect a single announcement rather
    than supplying independent stimuli, and a cold run pays the real auth + scanner probes.
    """

    @classmethod
    def setUpClass(cls):
        cls.sh = shutil.which("sh")
        if not cls.sh:
            raise unittest.SkipTest("POSIX sh unavailable")
        # Forward slashes, matching how hooks.json invokes it ("${CLAUDE_PLUGIN_ROOT}/hooks/...").
        # A bare os.path.join would hand sh a pure-backslash path that no real caller produces.
        cls.launcher = os.path.join(_HOOKS_DIR, "cx_session_start.sh").replace(os.sep, "/")
        cls.default = cls._invoke(cls)

    def _invoke(self, extra_env=None):
        env = dict(os.environ, CX_LOG_DISABLE="1")
        env.pop("CX_BINARY", None)
        env.pop("CX_ALLOW_UNLICENSED", None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [self.sh, self.launcher],
            input=b'{"hook_event_name":"SessionStart","source":"startup"}',
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=120)

    def _json(self, proc):
        return json.loads(proc.stdout.decode("utf-8", "replace"))

    def test_exits_zero_and_emits_only_a_json_object(self):
        """The regression guard: exit 0, and stdout is pure JSON with no interpreter chatter ahead of
        it. A non-zero exit would render a hook-error notice on every single session start."""
        self.assertEqual(0, self.default.returncode)
        out = self.default.stdout.decode("utf-8", "replace").strip()
        self.assertTrue(out.startswith("{"), "stdout must be pure JSON, got: %r" % out[:200])
        json.loads(out)

    def test_declares_session_start_and_both_channels(self):
        d = self._json(self.default)
        self.assertEqual("SessionStart", d["hookSpecificOutput"]["hookEventName"])
        self.assertIn("systemMessage", d)
        self.assertIn("additionalContext", d["hookSpecificOutput"])

    def test_never_emits_a_permission_decision(self):
        """SessionStart has no permission decision; emitting one would be meaningless at best."""
        self.assertNotIn("permissionDecision", self.default.stdout.decode("utf-8", "replace"))

    def test_wording_stays_scoped_and_promises_no_blanket_protection(self):
        """The gate does not see shell-written files and does not scan unscannable types, so the
        announcement must not assert session-wide protection."""
        ctx = self._json(self.default)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("powered by Checkmarx One", ctx)
        for overclaim in ("guarded by", "protected by", "fully secure", "all files are scanned"):
            self.assertNotIn(overclaim, ctx.lower())

    def test_tells_the_agent_not_to_bypass_via_shell(self):
        """The one behavioural line. Guidance, not a control — but it must be present, because the
        observed default was to silently rebuild a blocked file with a shell redirect."""
        ctx = self._json(self.default)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("shell", ctx.lower())
        self.assertIn("BLOCKED", ctx)

    def test_invalid_cx_binary_is_reported_without_blaming_setup(self):
        """The remedy must be per-reason. `/cx-cli-setup` cannot fix a dead CX_BINARY pin — the
        bootstrap only writes the canonical store, which the pin shadows."""
        d = self._json(self._invoke(
            {"CX_BINARY": os.path.join(tempfile.gettempdir(), "no-such-cx.exe")}))
        msg = d["systemMessage"]
        self.assertIn("NOT active", msg)
        self.assertIn("CX_BINARY", msg)
        self.assertNotIn("/cx-cli-setup", msg)

    def test_missing_cx_check_py_is_diagnosed_on_stderr_not_stdout(self):
        """Every dir-resolution failure must be visible AND must not corrupt stdout, which is the
        announcement channel. Simulated with a copy of the launcher that has no sibling cx_check.py."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        lone = os.path.join(tmp, "cx_session_start.sh").replace(os.sep, "/")
        shutil.copyfile(self.launcher, lone)
        p = subprocess.run([self.sh, lone], input=b"{}", stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           env=dict(os.environ, CX_LOG_DISABLE="1"), timeout=60)
        self.assertEqual(0, p.returncode)
        self.assertEqual(b"", p.stdout.strip())
        self.assertIn(b"cx_check.py not found", p.stderr)


class SessionPostureAgreesWithGate(unittest.TestCase):
    """_session_posture() must never describe a state the gate would handle differently.

    Both walk the same chain over the same probes, so the seam is testable by stubbing them. This is
    the contract test for a deliberate second implementation — the same approach
    tests/scripts/test_cx_resolution_contract.sh takes for the cx-resolution seam. Two divergences
    shipped before it existed: CX_ALLOW_UNLICENSED (the gate allows, the banner said writes were
    blocked) and the fresh-credential window (the gate says do NOT re-login, the banner said run setup).
    """

    def setUp(self):
        self._saved = {name: getattr(cx_check, name) for name in
                       ("_is_authenticated", "_scanner_state", "_version_state",
                        "_credential_is_fresh")}
        os.environ.pop("CX_ALLOW_UNLICENSED", None)

    def tearDown(self):
        for name, fn in self._saved.items():
            setattr(cx_check, name, fn)
        os.environ.pop("CX_ALLOW_UNLICENSED", None)

    def _stub(self, version="ok", authed=True, scanner=None, fresh=False):
        cx_check._version_state = lambda identity=None: version
        cx_check._is_authenticated = lambda identity=None: authed
        cx_check._scanner_state = lambda identity=None: (
            scanner if scanner is not None else cx_check._SCANNER_SCAN)
        cx_check._credential_is_fresh = lambda within_seconds=180: fresh

    def test_unlicensed_override_is_active_and_never_claims_writes_are_blocked(self):
        """The gate calls _allow_with_warning here, so writes DO proceed — unscanned."""
        self._stub(scanner=cx_check._SCANNER_UNLICENSED)
        os.environ["CX_ALLOW_UNLICENSED"] = "1"
        active, code, msg, ctx = cx_check._session_posture()
        self.assertTrue(active, "the gate allows with CX_ALLOW_UNLICENSED=1")
        self.assertNotIn("BLOCKED until", ctx)
        self.assertIn("UNSCANNED", ctx + msg)

    def test_unlicensed_without_override_uses_the_gates_reason_code(self):
        """A session_start/gate_decision join on reason_code must not break."""
        self._stub(scanner=cx_check._SCANNER_UNLICENSED)
        active, code, _, _ = cx_check._session_posture()
        self.assertFalse(active)
        self.assertEqual("scanner_unlicensed", code)

    def test_fresh_credential_window_warns_against_relogin(self):
        """The gate's auth_pending_fresh_login branch exists because re-running `cx auth login`
        revokes the token and restarts the wait. The banner must not prescribe that loop."""
        self._stub(authed=False, fresh=True)
        active, code, msg, ctx = cx_check._session_posture()
        self.assertFalse(active)
        self.assertEqual("auth_pending_fresh_login", code)
        self.assertNotIn("/cx-cli-setup", msg)
        self.assertIn("REVOKES", ctx)

    def test_plain_unauthenticated_still_points_at_setup(self):
        self._stub(authed=False, fresh=False)
        active, code, msg, _ = cx_check._session_posture()
        self.assertFalse(active)
        self.assertEqual("unauthenticated", code)
        self.assertIn("/cx-cli-setup", msg)

    def test_every_branch_returns_four_strings_and_a_bool(self):
        """Drives the branches rather than sampling whichever one this host happens to be in."""
        cases = (
            dict(version="below"), dict(version="incapable"), dict(version="unrunnable"),
            dict(authed=False), dict(authed=False, fresh=True),
            dict(scanner=cx_check._SCANNER_UNLICENSED),
            dict(scanner=cx_check._SCANNER_PASSTHROUGH),
            dict(scanner=cx_check._SCANNER_UNKNOWN), dict(),
        )
        for kwargs in cases:
            with self.subTest(**kwargs):
                self._stub(**kwargs)
                active, code, msg, ctx = cx_check._session_posture()
                self.assertIsInstance(active, bool)
                for field in (code, msg, ctx):
                    self.assertIsInstance(field, str)
                    self.assertTrue(field)
                self.assertTrue(msg.startswith(("Checkmarx One |", "Powered by Checkmarx One |")))
                self.assertIn("powered by Checkmarx One", ctx)
                # "Powered by" is reserved for the branch where scanning really runs — anything else
                # would announce protection the gate is not providing.
                if msg.startswith("Powered by"):
                    self.assertTrue(active)
                    self.assertIn("scanning active", msg)


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
        return self._stage(self.run_sh, ["hooks", "claude-pre-file-write"], _write(path))

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

    def test_stage1_still_denies_scannable_write_when_cx_absent(self):
        """The other half of the contract: deferring is only safe because stage 1 holds the line."""
        for path, expect_deny in (("/kode/app.py", True), ("/kode/main.tf", True),
                                  ("/kode/list_files.sh", False), ("/kode/README.md", False)):
            with self.subTest(path=path):
                code, _ = self._stage(self.check_sh, [], _write(path))
                self.assertEqual(2 if expect_deny else 0, code)

    def test_stage2_still_denies_mcp_when_cx_absent(self):
        """Only the file-write case defers; a Checkmarx MCP call has no stage-1-equivalent fallback
        behaviour worth relaxing and stays fail-closed here."""
        payload = {"tool_name": "mcp__Checkmarx__codeRemediation", "tool_input": {}}
        code, out = self._stage(self.run_sh, ["hooks", "claude-pre-tool-use"], payload)
        self.assertEqual(2, code)
        self.assertIn("deny", out)


if __name__ == "__main__":
    unittest.main()
