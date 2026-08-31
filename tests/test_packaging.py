"""Packaging invariants — guard the Phase-4 release contract (stdlib only).

These fail fast if the plugin's identity ever drifts: a single version identity, no redundant
`mcpServers` declaration (the `.mcp.json` is auto-discovered), the four synced CX_MIN_VERSION
sites agreeing, the marketplace pointing at a real plugin, and — on a tag build — the release tag
matching `plugin.json`.

Run: python tests/test_packaging.py
"""

import importlib.util
import json
import os
import re
import subprocess
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CLAUDE_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, "..", "plugins", "cx-devassist"))
_COPILOT_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, "..", "plugins", "copilot-devassist"))
_CURSOR_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, "..", "plugins", "cursor-devassist"))
_REPO_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


def _claude_manifest():
    return json.loads(_read(_CLAUDE_PLUGIN_ROOT, ".claude-plugin", "plugin.json"))


class TestClaudePluginManifest(unittest.TestCase):
    def test_valid_and_semver(self):
        data = _claude_manifest()
        for key in ("name", "version", "description"):
            self.assertIn(key, data, "plugin.json missing %r" % key)
        self.assertEqual(data["name"], "cx-devassist")
        self.assertRegex(data["version"], _SEMVER)

    def test_no_redundant_mcpservers_field(self):
        # .mcp.json is auto-discovered at the plugin root; declaring it again in plugin.json
        # risks a double-register (undocumented merge semantics). Keep exactly one declaration.
        self.assertNotIn("mcpServers", _claude_manifest())
        mcp = json.loads(_read(_CLAUDE_PLUGIN_ROOT, ".mcp.json"))
        self.assertIn("Checkmarx", mcp.get("mcpServers", {}))

    def test_readme_present(self):
        self.assertTrue(os.path.isfile(os.path.join(_CLAUDE_PLUGIN_ROOT, "README.md")))


class TestMarketplace(unittest.TestCase):
    def test_references_plugin_with_real_source(self):
        mp = json.loads(_read(_REPO_ROOT, ".claude-plugin", "marketplace.json"))
        entry = next((p for p in mp.get("plugins", []) if p.get("name") == "cx-devassist"), None)
        self.assertIsNotNone(entry, "marketplace.json has no cx-devassist plugin entry")
        src = os.path.normpath(os.path.join(_REPO_ROOT, entry["source"]))
        self.assertTrue(os.path.isdir(src), "marketplace source path missing: %s" % src)

    def test_copilot_marketplace_references_plugin_with_real_source(self):
        mp = json.loads(_read(_REPO_ROOT, ".github", "plugin", "marketplace.json"))
        entry = next((p for p in mp.get("plugins", []) if p.get("name") == "cx-devassist"), None)
        self.assertIsNotNone(entry, ".github/plugin/marketplace.json has no cx-devassist entry")
        src = os.path.normpath(os.path.join(_REPO_ROOT, entry["source"]))
        self.assertTrue(os.path.isdir(src), "copilot marketplace source path missing: %s" % src)


class TestMinVersionSync(unittest.TestCase):
    """The numeric floor lives in four synced sites (search marker: CX_MIN_VERSION).
    Both the Claude and Copilot plugin roots are checked independently."""

    def _canonical(self, plugin_root):
        for line in _read(plugin_root, "scripts", "cx-min-version").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                return s
        self.fail("no version line found in %s/scripts/cx-min-version" % plugin_root)

    def _check_four_sites(self, plugin_root):
        canon = self._canonical(plugin_root)
        self.assertRegex(canon, _SEMVER)

        py = _read(plugin_root, "hooks", "cx_check.py")
        m = re.search(r"_MIN_VERSION_FALLBACK\s*=\s*\((\d+),\s*(\d+),\s*(\d+)\)", py)
        self.assertIsNotNone(m, "cx_check.py: _MIN_VERSION_FALLBACK not found")
        self.assertEqual(".".join(m.groups()), canon,
                         "cx_check.py fallback != cx-min-version")

        sh = _read(plugin_root, "scripts", "cx-bootstrap.sh")
        m2 = re.search(r'MIN_CX_VERSION_FALLBACK="([^"]+)"', sh)
        self.assertIsNotNone(m2, "cx-bootstrap.sh: MIN_CX_VERSION_FALLBACK not found")
        self.assertEqual(m2.group(1), canon, "cx-bootstrap.sh fallback != cx-min-version")

        guard = _read(plugin_root, "scripts", "cx-mcp-guard.sh")
        m3 = re.search(r'_CXMCP_FALLBACK="\$\{2:-([^}]+)\}"', guard)
        self.assertIsNotNone(m3, "cx-mcp-guard.sh: cx_mcp_load_min_version fallback not found")
        self.assertEqual(m3.group(1), canon, "cx-mcp-guard.sh fallback != cx-min-version")

    def test_claude_four_sites_agree(self):
        self._check_four_sites(_CLAUDE_PLUGIN_ROOT)

    def test_copilot_four_sites_agree(self):
        self._check_four_sites(_COPILOT_PLUGIN_ROOT)


class TestReleaseTag(unittest.TestCase):
    def test_tag_matches_plugin_version(self):
        # On a tag build CI sets CX_RELEASE_TAG (e.g. cx-devassist-v1.6.0). Locally it's unset → skip.
        tag = os.environ.get("CX_RELEASE_TAG", "").strip()
        if not tag:
            self.skipTest("CX_RELEASE_TAG not set (not a tag build)")
        m = re.search(r"(\d+\.\d+\.\d+)$", tag)
        self.assertIsNotNone(m, "release tag %r has no semver suffix" % tag)
        self.assertEqual(m.group(1), _claude_manifest()["version"],
                         "release tag %s does not match plugin.json version" % tag)


class TestShippedBytes(unittest.TestCase):
    """The shell scripts + the version-floor data file must ship LF-only, and cx-min-version must
    be pure ASCII. Both plugin roots are checked. A stray CR breaks bootstrap on Linux/macOS (and
    can fail the gate OPEN); a non-ASCII byte in cx-min-version can crash the gate = fail OPEN."""

    _LF_FILES = [
        ("scripts", "cx-bootstrap.sh"),
        ("scripts", "cx-asset-resolver.sh"),
        ("scripts", "cx-path-probe.sh"),
        ("scripts", "cx-mcp-guard.sh"),
        ("scripts", "cx-min-version"),
        ("hooks", "cx_check.sh"),
        ("hooks", "cx_check.py"),
        ("hooks", "cx_run.sh"),
        ("hooks", "cx_record_login.sh"),
        ("hooks", "cx_log.py"),
    ]

    def _bytes(self, plugin_root, *parts):
        with open(os.path.join(plugin_root, *parts), "rb") as f:
            return f.read()

    def test_no_carriage_returns(self):
        for plugin_root in (_CLAUDE_PLUGIN_ROOT, _COPILOT_PLUGIN_ROOT):
            for parts in self._LF_FILES:
                self.assertNotIn(b"\r", self._bytes(plugin_root, *parts),
                                 "%s/%s contains CR bytes — must be LF-only" % (
                                     os.path.basename(plugin_root), parts[-1]))

    def test_cx_min_version_is_pure_ascii(self):
        for plugin_root in (_CLAUDE_PLUGIN_ROOT, _COPILOT_PLUGIN_ROOT):
            try:
                self._bytes(plugin_root, "scripts", "cx-min-version").decode("ascii")
            except UnicodeDecodeError as e:
                self.fail("%s/scripts/cx-min-version is not pure ASCII "
                          "(would crash the gate under LANG=C): %s" % (
                              os.path.basename(plugin_root), e))


class TestHookWiring(unittest.TestCase):
    """Stage-2 scanning must run through cx_run.sh (canonical-path resolution, no PATH dependency),
    and the remediation MCP must stay a single `cx` server (activates after one /reload-plugins)."""

    def test_stage2_routes_through_cx_run(self):
        hooks = json.loads(_read(_CLAUDE_PLUGIN_ROOT, "hooks", "hooks.json"))
        cmds = [h["command"] for entry in hooks["hooks"]["PreToolUse"]
                for h in entry["hooks"] if h.get("type") == "command"]
        scanner_cmds = [c for c in cmds if "hooks claude-pre" in c]
        self.assertTrue(scanner_cmds, "no stage-2 scanner commands found in hooks.json")
        for c in scanner_cmds:
            self.assertIn("cx_run.sh", c, "stage-2 must resolve cx via cx_run.sh, got: %s" % c)
            self.assertFalse(c.startswith("cx hooks"), "stage-2 must not call bare cx: %s" % c)

    def test_cx_run_wrapper_present(self):
        for plugin_root in (_CLAUDE_PLUGIN_ROOT, _COPILOT_PLUGIN_ROOT):
            self.assertTrue(
                os.path.isfile(os.path.join(plugin_root, "hooks", "cx_run.sh")),
                "cx_run.sh missing in %s" % os.path.basename(plugin_root))

    def test_hook_referenced_scripts_are_shipped(self):
        # Every script a hook config invokes must exist in its plugin root AND be tracked by git.
        # Regression guard: cx_record_login.sh and config/cx-scannable-files were both present in
        # the working tree but UNTRACKED in copilot-devassist, so neither reached the released
        # plugin. The missing hook made Copilot's fail-closed preToolUse abort with "No such file
        # or directory" on every shell call; the missing config made _load_scannable_files() return
        # None, which gates (and therefore denies) every file write, not just scannable ones.
        tracked = set(subprocess.run(
            ["git", "ls-files"], cwd=_REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.splitlines())
        hook_configs = [
            (_CLAUDE_PLUGIN_ROOT, "hooks.json"),
            (_COPILOT_PLUGIN_ROOT, "hooks-copilot-cli.json"),
        ]
        for plugin_root, cfg in hook_configs:
            name = os.path.basename(plugin_root)
            required = set(re.findall(r"[\w./-]*?(?:hooks|scripts)/([\w.-]+\.(?:sh|py))",
                                      _read(plugin_root, "hooks", cfg)))
            self.assertTrue(required, "%s/%s references no hook scripts" % (name, cfg))
            required.add("config/cx-scannable-files")
            for rel in sorted(required):
                rel = rel if "/" in rel else "hooks/" + rel
                self.assertTrue(os.path.isfile(os.path.join(plugin_root, rel)),
                                "%s references %s but the file is missing" % (cfg, rel))
                repo_rel = "plugins/%s/%s" % (name, rel)
                self.assertTrue(repo_rel in tracked,
                                "%s exists but is UNTRACKED by git — it will not ship" % repo_rel)

    def test_no_bare_cx_in_hook_commands(self):
        # Every cx invocation in the hook configs must route through cx_run.sh (absolute-path
        # resolution). A bare `cx …` fails on a locked-down / first-install machine and (for the
        # scanners) fails OPEN. Regression guard for the clean-flow contract.
        hook_configs = [
            (_CLAUDE_PLUGIN_ROOT, "hooks.json"),
            (_COPILOT_PLUGIN_ROOT, "hooks-copilot-cli.json"),
        ]
        for plugin_root, cfg in hook_configs:
            data = json.loads(_read(plugin_root, "hooks", cfg))
            cmds = []

            def _walk(o):
                if isinstance(o, dict):
                    if o.get("type") == "command" and isinstance(o.get("command"), str):
                        cmds.append(o["command"])
                    for v in o.values():
                        _walk(v)
                elif isinstance(o, list):
                    for v in o:
                        _walk(v)

            _walk(data)
            for c in cmds:
                self.assertNotRegex(
                    c, r'(^|[\s"])cx\s+hooks\b',
                    "%s has a bare `cx hooks` command (must route via cx_run.sh): %s" % (cfg, c))

    def test_mcp_resolves_cx_via_cx_run(self):
        # The remediation MCP must resolve cx by absolute path (canonical store) through cx_run.sh —
        # NOT bare `cx` — so it can start on a locked-down / first-install machine after one
        # /reload-plugins, with no restart. Checked for both plugin roots.
        for plugin_root in (_CLAUDE_PLUGIN_ROOT, _COPILOT_PLUGIN_ROOT):
            mcp = json.loads(_read(plugin_root, ".mcp.json"))
            servers = mcp.get("mcpServers", {})
            self.assertEqual(list(servers), ["Checkmarx"],
                             "%s: unexpected MCP servers" % os.path.basename(plugin_root))
            srv = servers["Checkmarx"]
            self.assertEqual(srv["command"], "sh")
            self.assertTrue(any("cx_run.sh" in a for a in srv["args"]),
                            "MCP must invoke cx_run.sh in %s, got args: %s" % (
                                os.path.basename(plugin_root), srv["args"]))
            self.assertIn("bridge", srv["args"])


class TestAgentLogDirIsolation(unittest.TestCase):
    """Each plugin must keep its caches, login history and jsonl in its OWN
    ~/.checkmarx/agent-logs/<client>/ subdirectory.

    copilot-devassist shipped without the leaf, so _agent_log_dir() resolved to the SHARED
    agent-logs root: cx_auth_cache / cx_version_cache / cx_scanner_cache / cx_login_history.json
    from Copilot collided with the identically named files the Claude and Cursor plugins write,
    and sat outside the directory cx-bootstrap.sh clears after an install, so a stale version
    cache survived every upgrade. cx_log.py additionally defaulted CX_ASSISTANT to "claude",
    which split the jsonl away from the state files whenever the env var was not set.
    """

    _CLIENTS = [
        (_CLAUDE_PLUGIN_ROOT, "claude"),
        (_COPILOT_PLUGIN_ROOT, "copilot-cli"),
        (_CURSOR_PLUGIN_ROOT, "cursor"),
    ]

    @staticmethod
    def _load(path, name):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_state_and_jsonl_share_the_client_subdir(self):
        expected_home = os.path.join(os.path.expanduser("~"), ".checkmarx", "agent-logs")
        for i, (plugin_root, client) in enumerate(self._CLIENTS):
            name = os.path.basename(plugin_root)
            gate = self._load(os.path.join(plugin_root, "hooks", "cx_check.py"), "chk%d" % i)
            logger = self._load(os.path.join(plugin_root, "hooks", "cx_log.py"), "log%d" % i)
            want = os.path.join(expected_home, client)

            # The gate's state dir. Skip only if it fell back to a private temp dir (the
            # documented degraded path when the per-user dir cannot be created).
            if gate._AGENT_LOG_DIR and gate._AGENT_LOG_DIR.startswith(expected_home):
                self.assertEqual(os.path.normcase(gate._AGENT_LOG_DIR), os.path.normcase(want),
                                 "%s: cx_check.py state dir is not the %s subdir" % (name, client))

            # The jsonl dir with CX_ASSISTANT UNSET must land in the same place, so a hook
            # config that omits the env block cannot split the two apart.
            prev = os.environ.pop("CX_ASSISTANT", None)
            try:
                self.assertEqual(os.path.normcase(logger._log_dir()), os.path.normcase(want),
                                 "%s: cx_log.py default dir is not the %s subdir" % (name, client))
            finally:
                if prev is not None:
                    os.environ["CX_ASSISTANT"] = prev

    def test_bootstrap_clears_the_cache_the_gate_writes(self):
        # cx-bootstrap.sh deletes cx_version_cache after an install/upgrade so the next hook fire
        # re-probes. It must name the SAME directory _agent_log_dir() builds.
        for plugin_root, client in self._CLIENTS:
            name = os.path.basename(plugin_root)
            boot = _read(plugin_root, "scripts", "cx-bootstrap.sh")
            # The leaf may be joined onto the agent-logs literal ("agent-logs/claude") or onto an
            # intermediate base variable ("$_LOG_BASE/copilot-cli/cx_version_cache"). Accept either
            # spelling; both prove the client leaf is part of the cleared path. Neither appearing is
            # the original bug — the bootstrap then clears a directory the gate never writes to.
            self.assertTrue(
                ("agent-logs/%s" % client) in boot or ("%s/cx_version_cache" % client) in boot,
                "%s/scripts/cx-bootstrap.sh never joins the %r leaf onto its cx_version_cache "
                "path, so it cannot clear the cache the gate writes" % (name, client))

    def test_cx_log_default_assistant_matches_the_plugin(self):
        for plugin_root, client in self._CLIENTS:
            name = os.path.basename(plugin_root)
            src = _read(plugin_root, "hooks", "cx_log.py")
            m = re.search(r'os\.environ\.get\("CX_ASSISTANT", ""\)\)? or "([\w-]+)"', src)
            self.assertIsNotNone(m, "%s: cx_log.py _assistant() fallback not found" % name)
            self.assertEqual(m.group(1), client,
                             "%s: cx_log.py falls back to %r but this plugin ships to %r"
                             % (name, m.group(1), client))



if __name__ == "__main__":
    unittest.main(verbosity=2)
