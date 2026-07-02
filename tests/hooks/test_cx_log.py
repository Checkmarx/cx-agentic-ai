"""Unit tests for cx_log.py — redaction is the priority property.

Run: python3 hooks/test_cx_log.py   (stdlib only)
"""

import json
import os
import sys
import tempfile
import unittest

# Source under test lives in the plugin's hooks/ (tests live at the repo root, outside the plugin).
_HOOKS_DIR = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "plugins", "cx-security", "hooks"))
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
        return os.path.join(self.dir, "cx-security.jsonl")

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
        self.assertIsInstance(rec["ts"], int)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
