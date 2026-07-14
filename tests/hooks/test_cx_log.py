"""Unit tests for cx_log.py — redaction is the priority property.

Run: python3 hooks/test_cx_log.py   (stdlib only)
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

# Source under test lives in the plugin's hooks/ (tests live at the repo root, outside the plugin).
_HOOKS_DIR = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "plugins", "cx-devassist", "hooks"))
sys.path.insert(0, _HOOKS_DIR)
import cx_log  # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ("CX_LOG_DIR", "CX_LOG_DISABLE", "CX_ASSISTANT")}
        self.dir = tempfile.mkdtemp()
        os.environ["CX_LOG_DIR"] = self.dir
        os.environ.pop("CX_LOG_DISABLE", None)
        os.environ.pop("CX_ASSISTANT", None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    @property
    def logfile(self):
        return os.path.join(self.dir, "cx-devassist.jsonl")

    def raw(self):
        with open(self.logfile, encoding="utf-8") as f:
            return f.read()

    def records(self):
        return [json.loads(line) for line in self.raw().splitlines() if line.strip()]


class TestRedaction(_Base):
    def test_non_allowlisted_field_is_dropped(self):
        cx_log.log_event("gate_decision", reason_code="ok", secret="TOKEN_ABC_123", apikey="zzz")
        raw = self.raw()
        self.assertNotIn("TOKEN_ABC_123", raw)
        self.assertNotIn("secret", raw)
        self.assertNotIn("apikey", raw)
        rec = self.records()[0]
        self.assertNotIn("secret", rec)
        self.assertEqual(rec["reason_code"], "ok")

    def test_dirty_value_in_allowlisted_field_is_omitted(self):
        # A free string with secrets/punctuation must NOT pass the _token gate.
        cx_log.log_event("gate_decision", reason_code="ok; cat ~/.checkmarx SECRET=hunter2",
                         tool_name="Bash")
        raw = self.raw()
        self.assertNotIn("hunter2", raw)
        self.assertNotIn("SECRET", raw)
        self.assertNotIn("cat", raw)
        rec = self.records()[0]
        self.assertNotIn("reason_code", rec)   # dirty → omitted
        self.assertEqual(rec["tool_name"], "Bash")

    def test_enum_coerces_unknown_to_other(self):
        cx_log.log_event("gate_decision", decision="deny\ninjected: secret", version_state="ok")
        raw = self.raw()
        self.assertNotIn("injected", raw)
        self.assertNotIn("secret", raw)
        rec = self.records()[0]
        self.assertEqual(rec["decision"], "other")
        self.assertEqual(rec["version_state"], "ok")

    def test_unknown_event_writes_nothing(self):
        cx_log.log_event("exfiltrate", token="SECRET_TOKEN")
        self.assertFalse(os.path.exists(self.logfile))

    def test_only_envelope_and_allowlisted_keys_present(self):
        cx_log.log_event("gate_decision", decision="deny", reason_code="cx_absent",
                         tool_name="Write", version_state="unrunnable", exit_code=2)
        rec = self.records()[0]
        allowed = {"ts", "assistant", "plugin_version", "os", "event",
                   "decision", "reason_code", "tool_name", "version_state", "exit_code"}
        self.assertTrue(set(rec).issubset(allowed), "unexpected keys: %s" % (set(rec) - allowed))
        self.assertEqual(rec["event"], "gate_decision")
        self.assertEqual(rec["exit_code"], 2)
        self.assertIsInstance(rec["ts"], str)
        self.assertRegex(rec["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_assistant_env_is_sanitized(self):
        os.environ["CX_ASSISTANT"] = "evil/../; rm"
        cx_log.log_event("gate_decision", reason_code="ok")
        # dirty CX_ASSISTANT fails the token gate → falls back to "claude"
        self.assertEqual(self.records()[0]["assistant"], "claude")

    def test_bad_int_exit_code_omitted(self):
        cx_log.log_event("gate_decision", reason_code="ok", exit_code="2; rm -rf /")
        rec = self.records()[0]
        self.assertNotIn("exit_code", rec)
        self.assertNotIn("rm -rf", self.raw())

    def test_scan_decision_allowlist(self):
        # scan_decision is the stage-2 native-scanner event (AST-162014); it must carry only the
        # outcome, never a free-form finding/reason. `reason_code` says WHY (a genuine finding vs
        # an error-driven fail-closed block), never the finding text itself.
        cx_log.log_event("scan_decision", decision="deny", tool_name="Bash",
                          reason_code="vulnerability_detected", reason="SQL injection in foo.py")
        rec = self.records()[0]
        self.assertEqual(rec["event"], "scan_decision")
        self.assertEqual(rec["decision"], "deny")
        self.assertEqual(rec["tool_name"], "Bash")
        self.assertEqual(rec["reason_code"], "vulnerability_detected")
        self.assertNotIn("reason", rec)
        self.assertNotIn("SQL injection", self.raw())

    def test_scan_decision_error_during_block(self):
        # A deny that fell back to the raw exit-2 path without a structured JSON deny (an
        # unexpected/error condition) is distinguished from a genuine finding.
        cx_log.log_event("scan_decision", decision="deny", tool_name="Write",
                          reason_code="error_during_block")
        rec = self.records()[0]
        self.assertEqual(rec["reason_code"], "error_during_block")

    def test_scan_decision_no_exit_code_field(self):
        # exit_code was replaced by reason_code for this event — a caller-passed exit_code must be
        # dropped, not silently accepted.
        cx_log.log_event("scan_decision", decision="allow", tool_name="Bash", exit_code=0)
        rec = self.records()[0]
        self.assertNotIn("exit_code", rec)

    def test_scan_decision_unknown_value_coerces_to_other(self):
        cx_log.log_event("scan_decision", decision="maybe", tool_name="Write")
        rec = self.records()[0]
        self.assertEqual(rec["decision"], "other")

    def test_mcp_connect_allowlist_and_message_synthesis(self):
        # mcp_connect's `message` is NEVER caller-supplied — it's synthesized server-side from the
        # allowlisted reason_code + already-token-validated version fields (hooks/cx_run.sh's mcp
        # bridge spawn guard, added for the "-32000 failed to reconnect" reliability fix).
        cx_log.log_event("mcp_connect", result="denied", reason_code="below",
                          version_have="2.1.0", version_min="2.3.54")
        rec = self.records()[0]
        self.assertEqual(rec["event"], "mcp_connect")
        self.assertEqual(rec["result"], "denied")
        self.assertEqual(rec["reason_code"], "below")
        self.assertEqual(rec["version_have"], "2.1.0")
        self.assertEqual(rec["version_min"], "2.3.54")
        self.assertEqual(
            rec["message"],
            "cx v2.1.0 is below the required v2.3.54 — mcp bridge blocked; run /cx-cli-setup to upgrade.")

    def test_mcp_connect_ignores_caller_supplied_message(self):
        # `message` is not in the mcp_connect schema at all — a caller passing one (accidentally or
        # otherwise) must never see it echoed back; only the fixed, first-party template is used.
        cx_log.log_event("mcp_connect", result="ok", reason_code="ok",
                          version_have="2.9.0", version_min="2.3.54",
                          message="INJECTED os.system('rm -rf /')")
        raw = self.raw()
        self.assertNotIn("INJECTED", raw)
        self.assertNotIn("rm -rf", raw)
        rec = self.records()[0]
        self.assertTrue(rec["message"].startswith("cx v2.9.0 is capable and current"))

    def test_mcp_connect_unknown_reason_code_has_no_message(self):
        # An unrecognized reason_code coerces to the enum's "other" sentinel (never leaks the raw
        # value), and "other" has no template — so no message is synthesized rather than a wrong one.
        cx_log.log_event("mcp_connect", result="denied", reason_code="something_new_and_unmapped")
        rec = self.records()[0]
        self.assertEqual(rec["reason_code"], "other")
        self.assertNotIn("message", rec)
        self.assertNotIn("something_new_and_unmapped", self.raw())

    def test_mcp_connect_dirty_version_is_omitted_not_injected(self):
        # A dirty version string (whitespace/punctuation) fails the _token gate and is dropped; the
        # message template then falls back to the safe "?" placeholder instead of embedding it raw.
        cx_log.log_event("mcp_connect", result="denied", reason_code="below",
                          version_have="2.1.0; rm -rf /", version_min="2.3.54")
        raw = self.raw()
        self.assertNotIn("rm -rf", raw)
        rec = self.records()[0]
        self.assertNotIn("version_have", rec)
        self.assertIn("cx v?", rec["message"])

    def test_mcp_connect_allowlist_is_closed(self):
        cx_log.log_event("mcp_connect", result="ok", reason_code="ok", version_have="2.9.0",
                          version_min="2.3.54", secret="test-fixture-not-a-real-secret")
        rec = self.records()[0]
        allowed = {"ts", "assistant", "plugin_version", "os", "event",
                   "result", "reason_code", "version_have", "version_min", "message", "tier"}
        self.assertTrue(set(rec).issubset(allowed), "unexpected keys: %s" % (set(rec) - allowed))
        self.assertNotIn("test-fixture-not-a-real-secret", self.raw())

    def test_mcp_connect_binary_tier_denied_gets_pin_note(self):
        # A denial resolved via a CX_BINARY pin (tier="binary") won't self-heal from a bootstrap
        # upgrade — the bootstrap only ever writes the canonical store, which CX_BINARY continues
        # to shadow — so the message must say so explicitly.
        cx_log.log_event("mcp_connect", result="denied", reason_code="below",
                          version_have="2.0.0", version_min="2.3.55", tier="binary")
        rec = self.records()[0]
        self.assertEqual(rec["tier"], "binary")
        self.assertIn("CX_BINARY is pinned to this exact binary", rec["message"])
        self.assertIn("will NOT fix this", rec["message"])

    def test_mcp_connect_canonical_tier_denied_omits_pin_note(self):
        cx_log.log_event("mcp_connect", result="denied", reason_code="below",
                          version_have="2.0.0", version_min="2.3.55", tier="canonical")
        rec = self.records()[0]
        self.assertNotIn("CX_BINARY", rec["message"])

    def test_mcp_connect_binary_tier_ok_omits_pin_note(self):
        # The note is only relevant to a DENIAL — a capable binary resolved via CX_BINARY is fine
        # and must not carry a spurious "won't fix this" note.
        cx_log.log_event("mcp_connect", result="ok", reason_code="ok",
                          version_have="2.9.0", version_min="2.3.55", tier="binary")
        rec = self.records()[0]
        self.assertNotIn("CX_BINARY", rec["message"])

    def test_mcp_connect_unknown_tier_coerces_to_other(self):
        cx_log.log_event("mcp_connect", result="denied", reason_code="below",
                          version_have="2.0.0", version_min="2.3.55", tier="bogus")
        rec = self.records()[0]
        self.assertEqual(rec["tier"], "other")
        self.assertNotIn("CX_BINARY", rec["message"])

    def test_as_int_accepts_posix_range_only(self):
        # PR#15 #5: exit_code must be a POSIX code 0..255; the non-POSIX -1 sentinel is dropped.
        self.assertIsNone(cx_log._as_int(-1))
        self.assertIsNone(cx_log._as_int(-2))
        self.assertIsNone(cx_log._as_int(256))
        self.assertIsNone(cx_log._as_int(True))  # bool is not a valid exit code
        for ok in (0, 2, 255):
            self.assertEqual(cx_log._as_int(ok), ok)


class TestBehavior(_Base):
    def test_disabled_writes_nothing(self):
        os.environ["CX_LOG_DISABLE"] = "1"
        cx_log.log_event("gate_decision", reason_code="ok")
        self.assertFalse(os.path.exists(self.logfile))

    def test_disable_only_for_documented_value(self):
        # CX_LOG_DISABLE=0 / =false must NOT disable logging — only the documented "1" does.
        for val in ("0", "false", "no"):
            os.environ["CX_LOG_DISABLE"] = val
            cx_log.log_event("gate_decision", reason_code="ok")
            self.assertTrue(os.path.exists(self.logfile),
                            "CX_LOG_DISABLE=%r must NOT disable logging" % val)
            os.remove(self.logfile)

    def test_appends_one_line_per_event(self):
        cx_log.log_event("gate_decision", reason_code="ok")
        cx_log.log_event("capability_probe", result=True, version_state="dev")
        self.assertEqual(len(self.records()), 2)

    def test_rotation(self):
        saved = cx_log._MAX_BYTES
        cx_log._MAX_BYTES = 200
        try:
            for _ in range(50):
                cx_log.log_event("gate_decision", reason_code="ok", tool_name="Bash")
            self.assertTrue(os.path.exists(self.logfile + ".1"), "expected a rotated .1 file")
        finally:
            cx_log._MAX_BYTES = saved

    def test_never_raises_on_internal_failure(self):
        saved = cx_log._log_dir
        cx_log._log_dir = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            cx_log.log_event("gate_decision", reason_code="ok")  # must not raise
        finally:
            cx_log._log_dir = saved

    def test_cli_entry_point_logs_scan_decision(self):
        # cx_run.sh invokes cx_log.py as a subprocess (never a shell-interpolated -c string) to
        # record the stage-2 scanner's decision. Values arrive as argv, not env, so run it directly.
        env = dict(os.environ)
        env["CX_LOG_DIR"] = self.dir
        module_path = os.path.join(_HOOKS_DIR, "cx_log.py")
        subprocess.run(
            [sys.executable, module_path, "scan_decision",
             "decision=deny", "tool_name=Write", "reason_code=vulnerability_detected"],
            env=env, check=True, capture_output=True, text=True,
        )
        rec = self.records()[0]
        self.assertEqual(rec["event"], "scan_decision")
        self.assertEqual(rec["decision"], "deny")
        self.assertEqual(rec["tool_name"], "Write")
        self.assertEqual(rec["reason_code"], "vulnerability_detected")

    def test_cli_entry_point_logs_mcp_connect(self):
        # hooks/cx_run.sh invokes cx_log.py this same way before/instead of exec'ing `cx mcp bridge`.
        env = dict(os.environ)
        env["CX_LOG_DIR"] = self.dir
        module_path = os.path.join(_HOOKS_DIR, "cx_log.py")
        subprocess.run(
            [sys.executable, module_path, "mcp_connect",
             "result=denied", "reason_code=incapable", "version_have=2.9.0", "version_min=2.3.54"],
            env=env, check=True, capture_output=True, text=True,
        )
        rec = self.records()[0]
        self.assertEqual(rec["event"], "mcp_connect")
        self.assertEqual(rec["result"], "denied")
        self.assertEqual(rec["reason_code"], "incapable")
        self.assertIn("mcp bridge", rec["message"])

    def test_cli_entry_point_never_raises_on_bad_args(self):
        env = dict(os.environ)
        env["CX_LOG_DIR"] = self.dir
        module_path = os.path.join(_HOOKS_DIR, "cx_log.py")
        result = subprocess.run(
            [sys.executable, module_path],  # no event name at all
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
