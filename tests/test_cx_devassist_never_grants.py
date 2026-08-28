"""The cx-devassist plugin must never GRANT a permission — only deny, or stay out of the way.

Background. A Claude Code PreToolUse hook returning permissionDecision:"allow" does not mean "this
hook has no objection". The host treats it as "bypass the permission check entirely": it short-
circuits the evaluator where permission mode, the settings allow/deny rules and the developer's
approval prompt all live. The plugin emitted exactly that on a clean result, so merely installing it
removed the file-write prompt for every Write/Edit/MultiEdit/NotebookEdit and Checkmarx MCP call the
scanner did not flag. The gate stopped gating writes and started answering consent on the
developer's behalf — and a clean scan is not consent, because the scanner cannot know the file was
unwanted in the first place.

The rule that came out of it: a security gate only ever narrows the host's consent model. Denying is
ours to do; approving is the developer's.

THE RULE IS A DENYLIST OF ONE VERDICT, NOT AN ALLOWLIST OF ONE VERDICT. The first attempt at this
fix relayed the scanner's stdout only when it matched a whitespace-exact `"permissionDecision":
"deny"` glob. That is a different rule, and it silently dropped four things that must reach the
host, while still leaking the grant whenever cx exited non-zero. Each of those shapes is pinned by
a named test below, because the suite as first written was green against every one of them.

Layers, because the original bug was not where anyone was looking:
  - TestCxRunShNeverGrants      — stage 2, the shell wrapper + cx_relay.py filter. This is where the
                                  grant comes from; cx still emits it and the filter removes it.
  - TestDeferWithWarning        — stage 1, the one Python path that used to grant.
  - TestNoGrantEmittersInPlugin — a source scan. Note its limit, stated in the class docstring: it
                                  could NOT have caught the original bug.

Dependency-free (stdlib only), like the sibling gate suites.
"""

import io
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout

from _gatelib import _HOOKS_DIR, cx_check

_PLUGIN_ROOT = os.path.dirname(_HOOKS_DIR)
CX_RUN = os.path.join(_HOOKS_DIR, "cx_run.sh")

# NOT skipUnless. run-tests.sh is itself `#!/usr/bin/env bash`, so if the suite is running at all,
# bash exists — a skip here could only ever hide the one layer that actually exercises the fix,
# while the runner still reported success. An absent bash is a broken harness, not a valid config.
_BASH = shutil.which("bash")

# The emission shape: a quoted JSON key with an "allow" value. Deliberately matches the payload and
# not prose, so the comments explaining this rule do not trip their own guard.
_GRANT = re.compile(r'"permissionDecision"\s*:\s*"allow"')

_SCANNED_SUFFIXES = (".py", ".sh", ".json", ".md")


class TestCxRunShNeverGrants(unittest.TestCase):
    """hooks/cx_run.sh relays the native scanner's stdout through cx_relay.py, which removes a
    grant and forwards everything else untouched.

    Driven by pinning CX_BINARY at a fake `cx` with a scripted stdout and exit code — the only way
    to exercise the relay without a licensed, authenticated real scanner."""

    _ALLOW = ('{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
              '"permissionDecision":"allow"}}')
    _DENY = ('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",'
             '"permissionDecisionReason":"SQL injection at app.py:12"}}')
    # Same verdict, one space after each colon. A shell substring matcher cannot see this as a
    # deny; a JSON parser cannot see it as anything else.
    _DENY_SPACED = ('{"hookSpecificOutput": {"hookEventName": "PreToolUse", '
                    '"permissionDecision": "deny", "permissionDecisionReason": "SQLi"}}')

    @classmethod
    def setUpClass(cls):
        if not _BASH:
            raise AssertionError(
                "bash not found on PATH. This class is the only layer that exercises the relay "
                "fix; skipping it would let the suite report OK without testing the fix at all.")

    def _fake_cx(self, stdout, exit_code):
        """An executable stand-in for the native cx binary.

        It drains stdin: cx_run.sh pipes the hook payload in, and a fake that exited without
        reading would hand the wrapper an EPIPE instead of the exit code under test."""
        directory = tempfile.mkdtemp(prefix="cx-fake-bin-")
        self.addCleanup(shutil.rmtree, directory, True)
        path = os.path.join(directory, "cx")
        body = ["#!/usr/bin/env bash", "cat >/dev/null"]
        if stdout:
            body.append("printf '%s\\n' " + shlex.quote(stdout))
        body.append("exit {0}".format(exit_code))
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(body) + "\n")
        os.chmod(path, 0o755)
        # Forward slashes: cx_binary_valid accepts a Windows drive path, but the backslash form is
        # unreliable as argv[0] under MSYS bash.
        return path.replace("\\", "/")

    def _run(self, stdout, exit_code, tool_name="Write", file_path="app.py",
             subcommand="claude-pre-file-write"):
        env = os.environ.copy()
        env["CX_BINARY"] = self._fake_cx(stdout, exit_code)
        log_dir = tempfile.mkdtemp(prefix="cx-fake-log-")
        self.addCleanup(shutil.rmtree, log_dir, True)
        env["CX_LOG_DIR"] = log_dir
        env.pop("CX_LOG_DISABLE", None)
        payload = {
            "tool_name": tool_name,
            "hook_event_name": "PreToolUse",
            "tool_input": {"file_path": file_path, "content": "print('hi')\n"},
        }
        proc = subprocess.run(
            # Forward slashes, exactly as Claude Code invokes it. cx_run.sh derives its own
            # directory by stripping at the last '/' of argv[0], which cannot split a backslash
            # path and would silently fall back to "." — losing cx_relay.py and cx_log.py with it.
            #
            # _BASH, not the string "bash": on Windows a bare "bash" resolves to the WSL launcher,
            # which cannot see a C:/ path, so CX_BINARY is rejected, the REAL cx runs instead of
            # the fake, and every assertion below silently tests the wrong binary.
            [_BASH, CX_RUN.replace("\\", "/"), "hooks", subcommand],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        self._log_dir = log_dir
        return proc

    # --- the grant is dropped ---------------------------------------------------------------

    def test_clean_scan_emits_nothing(self):
        """exit 0 with no finding: stdout MUST be empty so the host's own permission flow decides."""
        proc = self._run(self._ALLOW, 0)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "", "clean scan must not emit a permission decision")

    def test_grant_is_suppressed_on_nonzero_exit_too(self):
        """A grant is a grant whatever the exit code.

        Claude Code parses hook stdout and honours the decision regardless of exit status, so
        gating the filter on 'did cx fail' leaks the grant on any cx path that marshals a verdict
        and then dies in telemetry or cleanup. The first version of this fix had exactly that
        hole."""
        for code in (1, 3, 127):
            with self.subTest(exit_code=code):
                proc = self._run(self._ALLOW, code)
                self.assertNotIn("allow", proc.stdout)
                self.assertEqual(proc.returncode, code, proc.stderr)

    def test_unscannable_file_never_grants(self):
        """Pins the reported repro's exact shape, not a distinct branch: cx_run.sh never reads
        file_path, so this is the clean-scan path with a different payload. It earns its place
        because stage 1 stays silent for a .sh, and when verdicts merge (deny > ask > allow >
        silence) silence loses to allow — so a grant here is what actually deleted the prompt."""
        proc = self._run(self._ALLOW, 0, file_path="hello1.sh")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "")

    def test_mcp_call_never_grants(self):
        """The mcp__Checkmarx__.* matcher shares this branch and must not be auto-approved either."""
        proc = self._run(self._ALLOW, 0, tool_name="mcp__Checkmarx__scan",
                            subcommand="claude-pre-tool-use")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "")

    def test_legacy_approve_is_suppressed(self):
        """The deprecated top-level form still maps to permissionBehavior "allow" in the host."""
        proc = self._run('{"decision":"approve","reason":"clean"}', 0)
        self.assertEqual(proc.stdout.strip(), "")

    # --- everything that is NOT a grant survives ---------------------------------------------

    def test_deny_is_relayed_verbatim(self):
        """A real finding must reach Claude Code byte-for-byte, reason text intact, exit 2."""
        proc = self._run(self._DENY, 2)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout.strip(), self._DENY)

    def test_deny_with_exit_zero_is_still_relayed(self):
        """The shape the REAL cx binary produces: a deny payload on stdout with exit 0. Claude Code
        honours the JSON decision regardless of exit code, so the filter must never key off it."""
        proc = self._run(self._DENY, 0)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), self._DENY)

    def test_spaced_deny_is_relayed(self):
        """Whitespace must not decide whether a security block reaches the host.

        The first version of this fix keyed off a substring glob with no spaces in it, so this
        exact payload was silently dropped and the vulnerable write landed — while the audit log
        recorded decision=allow / no_issues_found."""
        proc = self._run(self._DENY_SPACED, 0)
        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"],
                         "deny")

    def test_deny_whose_reason_mentions_allow_is_relayed(self):
        """A finding whose prose contains the word 'allow' is still a finding. Rules out the naive
        inverse fix — 'suppress anything containing allow' — which would drop this block."""
        payload = ('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":'
                   '"deny","permissionDecisionReason":"do not allow unsanitized input"}}')
        proc = self._run(payload, 0)
        self.assertEqual(proc.stdout.strip(), payload)

    def test_ask_is_relayed(self):
        """`ask` is the one verdict that explicitly wants a human in the loop. Suppressing it under
        acceptEdits/bypassPermissions auto-accepts the very edit the scanner wanted confirmed."""
        payload = ('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":'
                   '"ask","permissionDecisionReason":"medium-severity finding, confirm"}}')
        proc = self._run(payload, 0)
        self.assertEqual(proc.stdout.strip(), payload)

    def test_continue_false_is_relayed(self):
        """continue:false halts the agent turn outright — strictly MORE blocking than a deny."""
        payload = '{"continue":false,"stopReason":"policy halt"}'
        proc = self._run(payload, 0)
        self.assertEqual(proc.stdout.strip(), payload)

    def test_advisory_context_without_a_decision_is_relayed(self):
        """cx's response type marks permissionDecision omitempty — it is designed to carry context
        with no decision. This stage is the only channel for it; the plugin ships no PostToolUse
        hook."""
        payload = ('{"hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":'
                   '"3 low-severity findings, not blocking"}}')
        proc = self._run(payload, 0)
        self.assertEqual(proc.stdout.strip(), payload)

    def test_grant_is_stripped_but_its_payload_survives(self):
        """Only the decision key is removed. Everything else cx attached — findings context, an
        inline fix in updatedInput — still reaches the model. Mirrors stage 1's
        _defer_with_warning, which also strips the decision and keeps additionalContext."""
        payload = ('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":'
                   '"allow","permissionDecisionReason":"clean","additionalContext":"3 low findings"'
                   ',"updatedInput":{"content":"fixed"}}}')
        proc = self._run(payload, 0)
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        self.assertNotIn("permissionDecision", out)
        self.assertNotIn("permissionDecisionReason", out)
        self.assertEqual(out["additionalContext"], "3 low findings")
        self.assertEqual(out["updatedInput"], {"content": "fixed"})

    def test_unparseable_output_is_relayed(self):
        """Non-JSON stdout (a cobra help dump from an unrecognised subcommand, a crash trace) is
        forwarded, not swallowed. A visible hook error beats a silently unscanned write."""
        proc = self._run('Error: unknown command "claude-pre-file-write"', 0)
        self.assertIn("unknown command", proc.stdout)

    def test_bare_exit_2_still_blocks(self):
        """cx exiting 2 with NO JSON is the fail-closed error path; exit 2 must survive. Exit-code
        passthrough is pinned elsewhere — what only this case can pin is that empty scanner output
        relays as empty, rather than the filter inventing a payload."""
        proc = self._run("", 2)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "")

    # --- the audit trail keeps what stdout no longer carries --------------------------------

    def test_clean_scan_is_still_audited(self):
        """Suppressing stdout must not blind the log: cx-devassist.jsonl is now the only record
        that a clean scan happened at all."""
        proc = self._run(self._ALLOW, 0)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        log = os.path.join(self._log_dir, "cx-devassist.jsonl")
        self.assertTrue(os.path.exists(log), "no audit log written for a clean scan")
        with open(log, encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle if line.strip()]
        scans = [r for r in records if r.get("event") == "scan_decision"]
        self.assertTrue(scans, "clean scan produced no audit record: {0}".format(records))
        self.assertEqual(scans[-1].get("decision"), "allow")
        self.assertEqual(scans[-1].get("reason_code"), "no_issues_found")


class TestDeferWithWarning(unittest.TestCase):
    """_defer_with_warning is the CX_ALLOW_UNLICENSED=1 escape hatch: cx is authenticated but has
    no AI-scanning license, so the write goes out UNSCANNED and the developer is warned. It used to
    emit "allow" — granting permission on the strength of a scan that never happened."""

    def setUp(self):
        """Hermetic logging. _defer_with_warning calls _log in-process, and _gatelib's
        os.environ.setdefault("CX_LOG_DISABLE", "1") is a no-op when the developer already exports
        that variable with any other value — cx_log.py only treats the literal "1" as off. Without
        this, the suite forges `decision=allow reason_code=unlicensed_override` records into the
        real ~/.checkmarx audit trail: fabricated approvals of unscanned writes, at 0600,
        indistinguishable from genuine ones. Note HOME is no defence on Windows, where
        expanduser("~") resolves from USERPROFILE and ignores it."""
        self._saved = {k: os.environ.get(k) for k in ("CX_LOG_DISABLE", "CX_LOG_DIR")}
        log_dir = tempfile.mkdtemp(prefix="cx-defer-log-")
        self.addCleanup(shutil.rmtree, log_dir, True)
        os.environ["CX_LOG_DISABLE"] = "1"
        os.environ["CX_LOG_DIR"] = log_dir
        self._log_dir = log_dir

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _emit(self):
        out = io.StringIO()
        code = None
        with redirect_stdout(out):
            try:
                cx_check._defer_with_warning("WARNING: ran UNSCANNED",
                                             reason_code="unlicensed_override", tool_name="Write")
            except SystemExit as exc:
                code = exc.code
        return json.loads(out.getvalue().strip()), code

    def test_exits_zero_without_blocking(self):
        _, code = self._emit()
        self.assertEqual(code, 0)

    def test_emits_no_permission_decision(self):
        payload, _ = self._emit()
        self.assertNotIn("permissionDecision", payload["hookSpecificOutput"])
        self.assertNotIn("permissionDecisionReason", payload["hookSpecificOutput"])

    def test_still_warns_the_model(self):
        """Dropping the decision must not drop the warning — an unscanned write is the one case
        where the model most needs to be told."""
        payload, _ = self._emit()
        hso = payload["hookSpecificOutput"]
        self.assertEqual(hso["hookEventName"], "PreToolUse")
        self.assertIn("UNSCANNED", hso["additionalContext"])

    def test_writes_nothing_to_the_real_audit_log(self):
        """Guards the isolation above, not the product: a test that fabricates approvals into the
        developer's security audit trail is worse than no test."""
        self._emit()
        self.assertEqual(os.listdir(self._log_dir), [],
                         "logging was not actually disabled during this test")

    def test_old_granting_helper_is_gone(self):
        """The rename is part of the fix: a helper named _allow_* that no longer allows would
        invite the next author to "restore" the decision."""
        self.assertFalse(hasattr(cx_check, "_allow_with_warning"))


class TestNoGrantEmittersInPlugin(unittest.TestCase):
    """Source-level scan of the shipped plugin, for grants written as literal text.

    KNOWN LIMIT, stated so nobody mistakes a green run for proof: this layer could NOT have caught
    the original bug. That grant was never literal text in this repo — it came from
    `printf '%s' "$_CXRUN_OUTPUT"` relaying a third-party binary's stdout, and no text scan can see
    a relay-class defect. TestCxRunShNeverGrants is the layer that actually covers the fix; this
    one only stops someone hard-coding a grant back in.

    Scope is cx-devassist only. The sibling copilot- and cursor-devassist trees are NOT covered
    here and do contain live grants — deliberately out of scope for this change, not clean."""

    def _sources(self):
        for root, _, files in os.walk(_PLUGIN_ROOT):
            for name in files:
                if name.endswith(_SCANNED_SUFFIXES):
                    yield os.path.join(root, name)

    def test_no_file_emits_an_allow_decision(self):
        offenders = []
        for path in self._sources():
            with open(path, encoding="utf-8", errors="replace") as handle:
                for lineno, line in enumerate(handle, start=1):
                    if _GRANT.search(line):
                        offenders.append("{0}:{1}: {2}".format(
                            os.path.relpath(path, _PLUGIN_ROOT), lineno, line.strip()))
        self.assertEqual(offenders, [], "\n".join(
            ["the gate must never emit an allow permissionDecision — Claude Code treats it as "
             "'bypass the permission check entirely', deleting the developer's approval prompt:"]
            + offenders))

    def test_the_guard_itself_works(self):
        """A guard that cannot fail is not a guard."""
        self.assertTrue(_GRANT.search('{"permissionDecision": "allow"}'))
        self.assertTrue(_GRANT.search('{"permissionDecision":"allow"}'))
        self.assertFalse(_GRANT.search("# explains why an allow decision is forbidden"))


if __name__ == "__main__":
    unittest.main()
