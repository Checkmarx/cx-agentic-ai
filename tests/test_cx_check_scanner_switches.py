"""Tests for the user-editable scanner switches (~/.checkmarx/cx-onboarding.properties) in the
Copilot CLI plugin: first-run seeding, parsing defaults, the all-disabled gate stand-down, and the
cx_run.sh stage-2 skip.

Dependency-free (stdlib unittest) so it runs on every OS. Run from the repo root:
    python -m unittest discover -s tests -p test_cx_check_scanner_switches.py -v

ONE PROCESS: this imports copilot-devassist's cx_check, so run-tests.sh gives it its own interpreter
(one process can only hold one module named `cx_check`).
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

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PLUGIN = os.path.join(_REPO_ROOT, "plugins", "copilot-devassist")
_HOOKS_DIR = os.path.join(_PLUGIN, "hooks")
sys.path.insert(0, _HOOKS_DIR)
os.environ.setdefault("CX_LOG_DISABLE", "1")
import cx_check  # noqa: E402

CX_CHECK_PY = os.path.join(_HOOKS_DIR, "cx_check.py")
# Forward slashes: the hook is launched as `sh "$HOME/.../cx_run.sh"`, and cx_run.sh derives its own
# directory from $0 by splitting on "/" — a backslash path would not resolve its sibling scripts.
CX_RUN_SH = os.path.join(_HOOKS_DIR, "cx_run.sh").replace("\\", "/")
BUNDLED = os.path.join(_PLUGIN, "config", "cx-onboarding.properties")
_BASH = shutil.which("bash")

_KEYS = ("cx_asca_scanner_enabled", "cx_sca_scanner_enabled",
         "cx_kics_scanner_enabled", "cx_secret_scanner_enabled")


def _props(**values):
    """A properties body; every scanner key defaults to 'true' unless overridden."""
    merged = {k: "true" for k in _KEYS}
    merged.update(values)
    return "".join("{0}={1}\n".format(k, v) for k, v in merged.items())


class _TempHome(unittest.TestCase):
    """A throwaway HOME with a ~/.checkmarx dir; cx_check._user_config_path is pointed at it."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="cx-switches-")
        self.cfg_dir = os.path.join(self.home, ".checkmarx")
        os.makedirs(self.cfg_dir)
        self.cfg = os.path.join(self.cfg_dir, "cx-onboarding.properties")
        self._orig = cx_check._user_config_path
        cx_check._user_config_path = lambda: self.cfg
        # The VS Code IDE state file lives in the same throwaway ~/.checkmarx (absent unless a test
        # writes it), so the developer's real VS Code Self-Healing setting never leaks in.
        self.ide_cfg = os.path.join(self.cfg_dir, "cx-onboarding-ide.properties")
        self._orig_ide = cx_check._ide_config_path
        cx_check._ide_config_path = lambda: self.ide_cfg

    def tearDown(self):
        cx_check._user_config_path = self._orig
        cx_check._ide_config_path = self._orig_ide
        shutil.rmtree(self.home, ignore_errors=True)

    def write(self, body, newline="\n", encoding="utf-8"):
        with open(self.cfg, "w", encoding=encoding, newline=newline) as f:
            f.write(body)


class LoadScannerSwitches(_TempHome):
    def test_bundled_defaults_all_on(self):
        # The shipped file must never ship with a scanner off.
        self.assertEqual(cx_check._load_scanner_switches(BUNDLED), {k: True for k in _KEYS})

    def test_missing_file_all_enabled(self):
        if os.path.exists(self.cfg):
            os.remove(self.cfg)
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

    def test_comments_unknown_ignored(self):
        self.write("# cx_asca_scanner_enabled=false\nsome_other=false\n")
        self.assertEqual(cx_check._load_scanner_switches(), {k: True for k in _KEYS})

    def test_windows_notepad_bom_and_crlf(self):
        self.write("﻿" + _props(cx_secret_scanner_enabled="false"), newline="\r\n")
        self.assertFalse(cx_check._load_scanner_switches()["cx_secret_scanner_enabled"])

    def test_oversized_file_fails_soft(self):
        self.write("# pad\n" * 5000 + _props(**{k: "false" for k in _KEYS}))
        self.assertTrue(any(cx_check._load_scanner_switches().values()))

    def test_undecodable_file_fails_soft(self):
        with open(self.cfg, "wb") as f:
            f.write(b"\xff\xfe\x00\xd8garbage")
        self.assertEqual(cx_check._load_scanner_switches(), {k: True for k in _KEYS})


class SeedUserConfig(_TempHome):
    def test_copies_bundle_when_absent(self):
        self.assertTrue(cx_check._seed_user_config(src=BUNDLED, dest=self.cfg))
        with open(BUNDLED, "rb") as a, open(self.cfg, "rb") as b:
            self.assertEqual(a.read(), b.read())

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
        with open(self.cfg, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("cx_asca_scanner_enabled=false", text)          # user's value kept
        self.assertEqual(text.count("cx_asca_scanner_enabled"), 1)    # not duplicated
        self.assertIn("# New engine\n# second line\ncx_new_scanner_enabled=true", text)

    def test_existing_lines_kept_in_order(self):
        original = "# my notes\ncx_sca_scanner_enabled=off\n\n# keep\ncx_tenant=acme\n"
        self.write(original)
        cx_check._seed_user_config(src=BUNDLED, dest=self.cfg)
        with open(self.cfg, encoding="utf-8") as f:
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
        with open(self.cfg, encoding="utf-8") as f:
            self.assertEqual(sum(1 for l in f if l.strip().lstrip("#").startswith("cx_kics_scanner_enabled")), 1)

    def test_admin_keys_not_copied(self):
        self.write("cx_asca_scanner_enabled=true\n")
        cx_check._seed_user_config(src=BUNDLED, dest=self.cfg)
        with open(self.cfg, encoding="utf-8") as f:
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
        cx_check._seed_user_config(src=BUNDLED, dest=self.cfg) if not os.path.exists(self.cfg) else None
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

    def test_user_only_if_bundle_lacks(self):
        self._bundle("# nothing set\n")
        self.write("cx_base_auth_uri=https://anz.ast.checkmarx.net\ncx_tenant=t1\n")
        self.assertEqual(len(cx_check._load_admin_config()), 2)

    def test_bundle_used_if_no_user_file(self):
        self._bundle("cx_tenant=bundle-t\n")
        if os.path.exists(self.cfg):
            os.remove(self.cfg)
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

    def test_bundle_has_no_url_or_tenant(self):
        # The shipped defaults must not pre-fill anyone's environment.
        self.assertEqual(cx_check._parse_admin_file(BUNDLED), {})

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


class SecretsSwitchNarrowsGate(_TempHome):
    """With the secrets scanner off, a file only the secrets engine would scan (app.env) is not gated."""

    _ENV_FILE = {"tool_name": "create", "tool_input": {"path": "config/app.env", "file_text": "A=1"}}
    _PY_FILE = {"tool_name": "create", "tool_input": {"path": "app.py", "file_text": "x=1"}}

    def test_secrets_on_gates_env_file(self):
        self.write(_props())
        self.assertTrue(cx_check._is_scannable_file(self._ENV_FILE))

    def test_secrets_off_env_not_gated(self):
        self.write(_props(cx_secret_scanner_enabled="false"))
        self.assertFalse(cx_check._is_scannable_file(self._ENV_FILE))

    def test_secrets_off_source_gated(self):
        self.write(_props(cx_secret_scanner_enabled="false"))
        self.assertTrue(cx_check._is_scannable_file(self._PY_FILE))

    def test_secrets_off_non_file_tools(self):
        self.write(_props(cx_secret_scanner_enabled="false"))
        self.assertTrue(cx_check._is_scannable_file({"tool_name": "bash", "tool_input": {"command": "x"}}))


class GateKeepsDenyingWhenSecretsOn(_TempHome):
    """Switches other than secrets-off never relax the gate."""

    def _gate(self, hook_input, **run_kwargs):
        orig = (cx_check._read_hook_input, cx_check.shutil.which, sys.argv)
        orig_exe = cx_check._cx_exe_with_tier
        # Hermetic: pretend cx is not installed even on a machine that has it in the canonical store.
        cx_check._cx_exe_with_tier = lambda: ("cx", "path")
        cx_check._read_hook_input = lambda: hook_input
        cx_check.shutil.which = lambda name: run_kwargs.get("which")
        sys.argv = ["cx_check.py", "--copilot-cli"]
        buf = io.StringIO()
        code = 0
        try:
            with redirect_stdout(buf):
                try:
                    cx_check.cx_check()
                except SystemExit as e:
                    code = e.code or 0
        finally:
            cx_check._read_hook_input, cx_check.shutil.which, sys.argv = orig
            cx_check._cx_exe_with_tier = orig_exe
        out = buf.getvalue().strip()
        return (json.loads(out) if out else None), code

    _WRITE = {"toolName": "create", "toolArgs": json.dumps({"path": "app.py", "file_text": "x=1"})}
    _WRITE_UNIX = {"tool_name": "create", "tool_input": {"path": "app.py", "file_text": "x=1"}}

    def test_one_scanner_on_keeps_gate(self):
        self.write(_props(**{k: "false" for k in _KEYS[:3]}))
        out, _code = self._gate(self._WRITE_UNIX, which=None)
        self.assertEqual(out and out.get("permissionDecision"), "deny")

    def test_default_config_keeps_the_gate(self):
        self.write(_props())
        out, _code = self._gate(self._WRITE_UNIX, which=None)
        self.assertEqual(out and out.get("permissionDecision"), "deny")


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
        home = tempfile.mkdtemp(prefix="cx-switches-seed-")
        try:
            proc = subprocess.run([sys.executable, "-I", CX_CHECK_PY, "seed-user-config"],
                                  env=_home_env(home), capture_output=True, timeout=60)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, b"")
            self.assertTrue(os.path.isfile(os.path.join(home, ".checkmarx", "cx-onboarding.properties")))
        finally:
            shutil.rmtree(home, ignore_errors=True)


@unittest.skipUnless(_BASH, "bash not found on PATH")
class CxRunShSeeds(unittest.TestCase):
    """Any cx_run.sh call — e.g. the MCP bridge spawn at session start — re-creates a deleted copy."""

    def test_non_scan_call_seeds_config(self):
        home = tempfile.mkdtemp(prefix="cx-switches-runseed-")
        try:
            stub = os.path.join(home, "cx-stub")
            with open(stub, "w", newline="\n") as f:
                f.write("#!/bin/sh\ncat >/dev/null\n")
            os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR)
            env = _home_env(home)
            env["CX_BINARY"] = stub
            subprocess.run([_BASH, CX_RUN_SH, "hooks", "copilot-cli-stop"], input=b"{}", env=env,
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
