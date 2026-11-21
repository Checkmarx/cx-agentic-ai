"""Tests for the user-editable onboarding config (~/.checkmarx/cx-onboarding.properties) in the Claude
Code plugin (cx-devassist): first-run seeding, append-only merge on update, URL/tenant precedence, the
ASCA/SCA/KICS/secrets switch reader, and that only the secrets switch changes a gate decision (and
only by narrowing it).

Dependency-free (stdlib unittest) so it runs on every OS. Run from the repo root:
    python -m unittest discover -s tests -p test_cx_check_scanner_switches_claude.py -v

ONE PROCESS: this imports cx-devassist's cx_check (via _gatelib), so run-tests.sh gives it its own
interpreter (one process can only hold one module named `cx_check`).
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
from contextlib import redirect_stdout

from _gatelib import cx_check

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PLUGIN = os.path.join(_REPO_ROOT, "plugins", "cx-devassist")
_HOOKS_DIR = os.path.join(_PLUGIN, "hooks")
CX_CHECK_PY = os.path.join(_HOOKS_DIR, "cx_check.py")
# Forward slashes: cx_run.sh derives its own directory from $0 by splitting on "/".
CX_RUN_SH = os.path.join(_HOOKS_DIR, "cx_run.sh").replace("\\", "/")
BUNDLED = os.path.join(_PLUGIN, "config", "cx-onboarding.properties")
_BASH = shutil.which("bash")

_KEYS = ("cx_asca_scanner_enabled", "cx_sca_scanner_enabled", "cx_kics_scanner_enabled",
         "cx_secret_scanner_enabled")
_SECRET_SWITCH = _KEYS[3]
_OTHER_SWITCHES = _KEYS[:3]


def _props(**values):
    """A properties body; every scanner key defaults to 'true' unless overridden."""
    merged = {k: "true" for k in _KEYS}
    merged.update(values)
    return "".join("{0}={1}\n".format(k, v) for k, v in merged.items())


class _TempHome(unittest.TestCase):
    """A throwaway HOME with a ~/.checkmarx dir; cx_check._user_config_path is pointed at it."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="cx-claude-switches-")
        self.cfg_dir = os.path.join(self.home, ".checkmarx")
        os.makedirs(self.cfg_dir)
        self.cfg = os.path.join(self.cfg_dir, "cx-onboarding.properties")
        self._orig = cx_check._user_config_path
        cx_check._user_config_path = lambda: self.cfg

    def tearDown(self):
        cx_check._user_config_path = self._orig
        shutil.rmtree(self.home, ignore_errors=True)

    def write(self, body, newline="\n", encoding="utf-8"):
        with open(self.cfg, "w", encoding=encoding, newline=newline) as f:
            f.write(body)


class BundledFile(unittest.TestCase):
    def test_ships_switches_on_threshold_low(self):
        with open(BUNDLED, "r", encoding="utf-8") as f:
            active = [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]
        self.assertEqual(active, ["cx_asca_scanner_enabled=true", "cx_sca_scanner_enabled=true",
                                  "cx_kics_scanner_enabled=true", "cx_secret_scanner_enabled=true",
                                  "cx_severity_threshold=low"])

    def test_bundle_has_no_url_or_tenant(self):
        # The shipped defaults must not pre-fill anyone's environment.
        self.assertEqual(cx_check._parse_admin_file(BUNDLED), {})


class LoadScannerSwitches(_TempHome):
    def test_bundled_defaults_all_on(self):
        self.assertEqual(cx_check._load_scanner_switches(BUNDLED), {k: True for k in _KEYS})

    def test_missing_file_all_enabled(self):
        self.assertEqual(cx_check._load_scanner_switches(), {k: True for k in _KEYS})

    def test_explicit_false_values(self):
        for value in ("false", "FALSE", "False", "0", "no", "off", "Disabled", "  false  "):
            self.write(_props(cx_asca_scanner_enabled=value))
            got = cx_check._load_scanner_switches()
            self.assertFalse(got["cx_asca_scanner_enabled"], value)
            self.assertTrue(got["cx_sca_scanner_enabled"], value)

    def test_typo_or_garbage_stays_enabled(self):
        for value in ("flase", "", "banana", "2", "disable"):
            self.write(_props(cx_kics_scanner_enabled=value))
            self.assertTrue(cx_check._load_scanner_switches()["cx_kics_scanner_enabled"], repr(value))

    def test_each_key_is_independent(self):
        for key in _KEYS:
            self.write(_props(**{key: "false"}))
            got = cx_check._load_scanner_switches()
            self.assertEqual([k for k, v in got.items() if not v], [key])

    def test_secret_key_is_read(self):
        # The same key the Copilot plugin writes; a shared copy switches secrets off for both.
        self.write(_props(**{_SECRET_SWITCH: "false"}))
        got = cx_check._load_scanner_switches()
        self.assertFalse(got[_SECRET_SWITCH])
        self.assertTrue(all(got[k] for k in _OTHER_SWITCHES))

    def test_comments_unknown_ignored(self):
        self.write("# cx_asca_scanner_enabled=false\nsome_other=false\n")
        self.assertEqual(cx_check._load_scanner_switches(), {k: True for k in _KEYS})

    def test_windows_notepad_bom_and_crlf(self):
        self.write("﻿" + _props(cx_sca_scanner_enabled="false"), newline="\r\n")
        self.assertFalse(cx_check._load_scanner_switches()["cx_sca_scanner_enabled"])

    def test_oversized_file_fails_soft(self):
        self.write("# pad\n" * 5000 + _props(**{k: "false" for k in _KEYS}))
        self.assertEqual(cx_check._load_scanner_switches(), {k: True for k in _KEYS})

    def test_undecodable_file_fails_soft(self):
        with open(self.cfg, "wb") as f:
            f.write(b"\xff\xfe\x00\xd8garbage")
        self.assertEqual(cx_check._load_scanner_switches(), {k: True for k in _KEYS})


class SeedUserConfig(_TempHome):
    def test_copies_bundle_when_absent(self):
        self.assertTrue(cx_check._seed_user_config(src=BUNDLED, dest=self.cfg))
        with open(BUNDLED, "rb") as a, open(self.cfg, "rb") as b:
            self.assertEqual(a.read(), b.read())

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_copy_is_owner_only(self):
        cx_check._seed_user_config(src=BUNDLED, dest=self.cfg)
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg).st_mode), 0o600)

    def test_creates_missing_directory(self):
        dest = os.path.join(self.home, "fresh", ".checkmarx", "cx-onboarding.properties")
        self.assertTrue(cx_check._seed_user_config(src=BUNDLED, dest=dest))
        self.assertTrue(os.path.isfile(dest))

    def test_never_overwrites_user_edits(self):
        self.write(_props(cx_sca_scanner_enabled="false"))
        self.assertFalse(cx_check._seed_user_config(src=BUNDLED, dest=self.cfg))
        self.assertFalse(cx_check._load_scanner_switches()["cx_sca_scanner_enabled"])

    def test_missing_source_is_a_noop(self):
        self.assertFalse(cx_check._seed_user_config(
            src=os.path.join(self.home, "nope"), dest=self.cfg))
        self.assertFalse(os.path.exists(self.cfg))

    def test_unwritable_dest_never_raises(self):
        blocker = os.path.join(self.home, "blocker")
        open(blocker, "w").close()                       # a FILE where a directory is needed
        self.assertFalse(cx_check._seed_user_config(
            src=BUNDLED, dest=os.path.join(blocker, "x", "cx-onboarding.properties")))

    def test_default_path_in_checkmarx_dir(self):
        cx_check._user_config_path = self._orig
        path = cx_check._user_config_path()
        if path.endswith("cx-no-such-user-config.properties"):   # _gatelib's hermetic stand-in
            path = os.path.join(os.path.expanduser("~"), ".checkmarx", cx_check._USER_CONFIG_NAME)
        self.assertEqual(os.path.basename(path), "cx-onboarding.properties")
        self.assertEqual(os.path.basename(os.path.dirname(path)), ".checkmarx")


class MergeNewProperties(_TempHome):
    """A plugin update adds new settings to the user's copy without touching what they chose."""

    def _bundle(self, body):
        path = os.path.join(self.home, "bundle.properties")
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(body)
        return path

    def test_adds_only_missing_keys(self):
        self.write("cx_asca_scanner_enabled=false\n")
        bundle = self._bundle("# ASCA\ncx_asca_scanner_enabled=true\n# New engine\n# second line\n"
                              "cx_new_scanner_enabled=true\n")
        cx_check._seed_user_config(src=bundle, dest=self.cfg)
        with open(self.cfg, "r", encoding="utf-8") as f:
            text = f.read()
        self.assertIn("cx_asca_scanner_enabled=false", text)          # user's value kept
        self.assertEqual(text.count("cx_asca_scanner_enabled"), 1)    # not duplicated
        self.assertIn("# --- added by a plugin update ---", text)
        self.assertIn("# New engine\n# second line\ncx_new_scanner_enabled=true", text)

    def test_copilot_seeded_copy_gets_nothing_new(self):
        # Copilot's bundle carries the same keys as ours (incl. secrets), so a copy it seeded is complete.
        copilot = os.path.join(_REPO_ROOT, "plugins", "copilot-devassist", "config",
                               "cx-onboarding.properties")
        shutil.copyfile(copilot, self.cfg)
        self.assertFalse(cx_check._merge_new_properties(BUNDLED, self.cfg))

    def test_existing_lines_kept_in_order(self):
        original = "# my notes\ncx_sca_scanner_enabled=off\n\n# keep\ncx_tenant=acme\n"
        self.write(original)
        cx_check._seed_user_config(src=BUNDLED, dest=self.cfg)
        with open(self.cfg, "r", encoding="utf-8") as f:
            self.assertTrue(f.read().startswith(original))

    def test_second_run_is_a_noop(self):
        self.write("")
        cx_check._seed_user_config(src=BUNDLED, dest=self.cfg)
        with open(self.cfg, "rb") as f:
            first = f.read()
        self.assertFalse(cx_check._merge_new_properties(BUNDLED, self.cfg))
        with open(self.cfg, "rb") as f:
            self.assertEqual(f.read(), first)

    def test_commented_key_not_readded(self):
        self.write("#cx_kics_scanner_enabled=false\n")
        cx_check._seed_user_config(src=BUNDLED, dest=self.cfg)
        with open(self.cfg, "r", encoding="utf-8") as f:
            self.assertEqual(
                sum(1 for l in f if l.strip().lstrip("#").startswith("cx_kics_scanner_enabled")), 1)

    def test_admin_keys_not_copied(self):
        self.write("cx_asca_scanner_enabled=true\n")
        cx_check._seed_user_config(src=BUNDLED, dest=self.cfg)
        with open(self.cfg, "r", encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("\ncx_tenant=", text)
        self.assertNotIn("\ncx_base_auth_uri=", text)

    def test_crlf_file_stays_crlf(self):
        self.write("cx_asca_scanner_enabled=true\r\n", newline="")
        cx_check._seed_user_config(src=BUNDLED, dest=self.cfg)
        with open(self.cfg, "rb") as f:
            raw = f.read()
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))

    def test_complete_file_not_rewritten(self):
        cx_check._seed_user_config(src=BUNDLED, dest=self.cfg)
        before = os.stat(self.cfg).st_mtime_ns
        self.assertFalse(cx_check._merge_new_properties(BUNDLED, self.cfg))
        self.assertEqual(os.stat(self.cfg).st_mtime_ns, before)

    def test_merge_failure_never_raises(self):
        self.assertFalse(cx_check._merge_new_properties(BUNDLED, os.path.join(self.home, "nope")))


class AdminConfigPrecedence(_TempHome):
    """cx_base_auth_uri / cx_tenant: a valid value in the user's ~/.checkmarx copy wins over the bundled
    file, per key; an invalid user value never reaches the login command."""

    def setUp(self):
        super().setUp()
        self.bundle = os.path.join(self.home, "bundle.properties")
        self._orig_admin = cx_check._admin_config_path
        cx_check._admin_config_path = lambda: self.bundle

    def tearDown(self):
        cx_check._admin_config_path = self._orig_admin
        super().tearDown()

    def _bundle(self, body):
        with open(self.bundle, "w", encoding="utf-8", newline="") as f:
            f.write(body)

    def test_user_value_overrides_bundle(self):
        self._bundle("cx_base_auth_uri=https://eu.ast.checkmarx.net\ncx_tenant=bundle-t\n")
        self.write("cx_base_auth_uri=https://us.ast.checkmarx.net\ncx_tenant=user-t\n")
        self.assertEqual(cx_check._load_admin_config(), {
            "cx_base_auth_uri": "https://us.ast.checkmarx.net", "cx_tenant": "user-t"})

    def test_keys_resolve_independently(self):
        self._bundle("cx_base_auth_uri=https://eu.ast.checkmarx.net\n")
        self.write("cx_tenant=user-t\n")
        self.assertEqual(cx_check._load_admin_config(), {
            "cx_base_auth_uri": "https://eu.ast.checkmarx.net", "cx_tenant": "user-t"})

    def test_bundle_used_if_no_user_file(self):
        self._bundle("cx_tenant=bundle-t\n")
        self.assertEqual(cx_check._load_admin_config(), {"cx_tenant": "bundle-t"})

    def test_invalid_value_uses_bundle(self):
        self._bundle("cx_base_auth_uri=https://eu.ast.checkmarx.net\ncx_tenant=bundle-t\n")
        self.write("cx_base_auth_uri=http://evil.example\ncx_tenant=-rf --proxy x\n")
        self.assertEqual(cx_check._load_admin_config(), {
            "cx_base_auth_uri": "https://eu.ast.checkmarx.net", "cx_tenant": "bundle-t"})

    def test_invalid_value_no_bundle(self):
        self._bundle("# nothing\n")
        self.write("cx_base_auth_uri=https://host/path\ncx_tenant=a b\n")
        self.assertEqual(cx_check._load_admin_config(), {})

    def test_commented_example_no_override(self):
        self._bundle("cx_tenant=bundle-t\n")
        self.write("# cx_tenant=your-tenant\n")
        self.assertEqual(cx_check._load_admin_config(), {"cx_tenant": "bundle-t"})

    def test_explicit_path_reads_that_file(self):
        self._bundle("cx_tenant=bundle-t\n")
        self.write("cx_tenant=user-t\n")
        self.assertEqual(cx_check._load_admin_config(self.bundle), {"cx_tenant": "bundle-t"})

    def test_values_reach_login_command(self):
        self._bundle("# nothing\n")
        self.write("cx_base_auth_uri=https://eu.ast.checkmarx.net\ncx_tenant=acme\n")
        bullet = cx_check._oauth_recovery_bullet(cx_check._load_admin_config(), history=[])
        self.assertIn("--base-auth-uri https://eu.ast.checkmarx.net --tenant acme", bullet)
        self.assertIn("PRECONFIGURED", bullet)


class SwitchesOnlyNarrowTheGate(_TempHome):
    """The secrets switch is the only one the gate reads, and it can only narrow it: with secrets off,
    a file only the secret engine would scan is not gated. ASCA / KICS / SCA files stay gated whatever
    their switches say (those are applied by the skills only)."""

    _PY_WRITE = {"tool_name": "Write", "tool_input": {"file_path": "app.py", "content": "x=1"}}
    _MD_WRITE = {"tool_name": "Write", "tool_input": {"file_path": "README.md", "content": "x"}}
    _ENV_EDIT = {"tool_name": "Edit", "tool_input": {"file_path": "config/app.env",
                                                     "old_string": "a", "new_string": "b"}}

    def test_secrets_on_gates_every_file(self):
        for body in (_props(), _props(**{k: "false" for k in _OTHER_SWITCHES})):
            self.write(body)
            for payload in (self._PY_WRITE, self._MD_WRITE, self._ENV_EDIT):
                self.assertTrue(cx_check._is_scannable_file(payload))

    def test_secrets_off_narrows_to_other_engines(self):
        self.write(_props(**{_SECRET_SWITCH: "false"}))
        self.assertTrue(cx_check._is_scannable_file(self._PY_WRITE))
        self.assertFalse(cx_check._is_scannable_file(self._MD_WRITE))
        self.assertFalse(cx_check._is_scannable_file(self._ENV_EDIT))

    def test_secrets_off_non_file_tools_stay_gated(self):
        self.write(_props(**{_SECRET_SWITCH: "false"}))
        self.assertTrue(cx_check._is_scannable_file({"tool_name": "Bash",
                                                     "tool_input": {"command": "x"}}))
        self.assertTrue(cx_check._is_scannable_file({"tool_name": "mcp__Checkmarx__codeRemediation",
                                                     "tool_input": {"file_path": "README.md"}}))

    def _gate(self, hook_input):
        orig = (cx_check._read_hook_input, cx_check.shutil.which, cx_check._cx_exe_with_tier)
        cx_check._read_hook_input = lambda: hook_input
        cx_check.shutil.which = lambda name: None
        cx_check._cx_exe_with_tier = lambda: ("cx", "path")   # hermetic: no canonical-store cx
        buf, code = io.StringIO(), 0
        try:
            with redirect_stdout(buf):
                try:
                    cx_check.cx_check()
                except SystemExit as e:
                    code = e.code or 0
        finally:
            cx_check._read_hook_input, cx_check.shutil.which, cx_check._cx_exe_with_tier = orig
        out = buf.getvalue().strip()
        return (json.loads(out) if out else None), code

    def _assert_denied(self, hook_input):
        out, code = self._gate(hook_input)
        self.assertEqual(code, 2)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_all_off_still_denies_scannable_write_when_cx_absent(self):
        self.write(_props(**{k: "false" for k in _KEYS}))
        self._assert_denied(self._PY_WRITE)

    def test_secrets_on_denies_any_write_when_cx_absent(self):
        self.write(_props(**{k: "false" for k in _OTHER_SWITCHES}))
        self._assert_denied(self._MD_WRITE)

    def test_secrets_off_allows_secrets_only_write_when_cx_absent(self):
        self.write(_props(**{_SECRET_SWITCH: "false"}))
        out, code = self._gate(self._MD_WRITE)
        self.assertEqual(code, 0)
        self.assertIsNone(out)


def _home_env(home):
    """Subprocess env whose home resolves to `home` on every OS (HOME for POSIX/Git Bash,
    USERPROFILE for Windows Python's expanduser)."""
    env = dict(os.environ)
    env.update({"HOME": home, "USERPROFILE": home, "CX_LOG_DISABLE": "1"})
    env.pop("CX_BINARY", None)
    return env


class SeedOnlyCli(unittest.TestCase):
    """`cx_check.py seed-user-config` creates the user copy and exits 0 without printing."""

    def test_seeds_and_is_silent(self):
        home = tempfile.mkdtemp(prefix="cx-claude-switches-seed-")
        try:
            proc = subprocess.run([sys.executable, "-I", CX_CHECK_PY, "seed-user-config"],
                                  env=_home_env(home), capture_output=True, timeout=60)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, b"")
            self.assertTrue(os.path.isfile(os.path.join(home, ".checkmarx", "cx-onboarding.properties")))
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def test_record_login_also_seeds_and_exits_zero(self):
        home = tempfile.mkdtemp(prefix="cx-claude-switches-rl-")
        try:
            proc = subprocess.run([sys.executable, "-I", CX_CHECK_PY, "record-login"],
                                  input=b'{"tool_name":"Bash","tool_input":{"command":"ls"}}',
                                  env=_home_env(home), capture_output=True, timeout=60)
            self.assertEqual(proc.returncode, 0)
            self.assertTrue(os.path.isfile(os.path.join(home, ".checkmarx", "cx-onboarding.properties")))
        finally:
            shutil.rmtree(home, ignore_errors=True)


@unittest.skipUnless(_BASH, "bash not found on PATH")
class CxRunShSeeds(unittest.TestCase):
    """Any cx_run.sh call — e.g. the MCP bridge spawn at session start — re-creates a deleted copy."""

    def test_non_scan_call_seeds_config(self):
        home = tempfile.mkdtemp(prefix="cx-claude-switches-runseed-")
        try:
            stub = os.path.join(home, "cx-stub")
            with open(stub, "w", newline="\n") as f:
                f.write("#!/bin/sh\ncat >/dev/null\n")
            os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR)
            env = _home_env(home)
            env["CX_BINARY"] = stub
            subprocess.run([_BASH, CX_RUN_SH, "hooks", "claude-stop"], input=b"{}", env=env,
                           capture_output=True, timeout=60)
            self.assertTrue(os.path.isfile(os.path.join(home, ".checkmarx", "cx-onboarding.properties")))
        finally:
            shutil.rmtree(home, ignore_errors=True)


@unittest.skipUnless(_BASH, "bash not found on PATH")
class CxRunShSyntax(unittest.TestCase):
    def test_script_still_parses(self):
        proc = subprocess.run([_BASH, "-n", CX_RUN_SH], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
