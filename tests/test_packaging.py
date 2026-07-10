"""Packaging invariants — guard the Phase-4 release contract (stdlib only).

These fail fast if the plugin's identity ever drifts: a single version identity, no redundant
`mcpServers` declaration (the `.mcp.json` is auto-discovered), the four synced CX_MIN_VERSION
sites agreeing, the marketplace pointing at a real plugin, and — on a tag build — the release tag
matching `plugin.json`.

Run: python tests/test_packaging.py
"""

import json
import os
import re
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, "..", "plugins", "cx-devassist"))
_REPO_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


def _plugin_manifest():
    return json.loads(_read(_PLUGIN_ROOT, ".claude-plugin", "plugin.json"))


class TestPluginManifest(unittest.TestCase):
    def test_valid_and_semver(self):
        data = _plugin_manifest()
        for key in ("name", "version", "description"):
            self.assertIn(key, data, "plugin.json missing %r" % key)
        self.assertEqual(data["name"], "cx-devassist")
        self.assertRegex(data["version"], _SEMVER)

    def test_no_redundant_mcpservers_field(self):
        # .mcp.json is auto-discovered at the plugin root; declaring it again in plugin.json
        # risks a double-register (undocumented merge semantics). Keep exactly one declaration.
        self.assertNotIn("mcpServers", _plugin_manifest())
        mcp = json.loads(_read(_PLUGIN_ROOT, ".mcp.json"))
        self.assertIn("Checkmarx", mcp.get("mcpServers", {}))

    def test_readme_present(self):
        self.assertTrue(os.path.isfile(os.path.join(_PLUGIN_ROOT, "README.md")))


class TestMarketplace(unittest.TestCase):
    def test_references_plugin_with_real_source(self):
        mp = json.loads(_read(_REPO_ROOT, ".claude-plugin", "marketplace.json"))
        entry = next((p for p in mp.get("plugins", []) if p.get("name") == "cx-devassist"), None)
        self.assertIsNotNone(entry, "marketplace.json has no cx-devassist plugin entry")
        src = os.path.normpath(os.path.join(_REPO_ROOT, entry["source"]))
        self.assertTrue(os.path.isdir(src), "marketplace source path missing: %s" % src)


class TestMinVersionSync(unittest.TestCase):
    """The numeric floor lives in four synced sites (search marker: CX_MIN_VERSION)."""

    def _canonical(self):
        for line in _read(_PLUGIN_ROOT, "scripts", "cx-min-version").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                return s
        self.fail("no version line found in scripts/cx-min-version")

    def test_four_sites_agree(self):
        canon = self._canonical()
        self.assertRegex(canon, _SEMVER)

        py = _read(_PLUGIN_ROOT, "hooks", "cx_check.py")
        m = re.search(r"_MIN_VERSION_FALLBACK\s*=\s*\((\d+),\s*(\d+),\s*(\d+)\)", py)
        self.assertIsNotNone(m, "cx_check.py: _MIN_VERSION_FALLBACK not found")
        self.assertEqual(".".join(m.groups()), canon,
                         "cx_check.py fallback != cx-min-version")

        sh = _read(_PLUGIN_ROOT, "scripts", "cx-bootstrap.sh")
        m2 = re.search(r'MIN_CX_VERSION_FALLBACK="([^"]+)"', sh)
        self.assertIsNotNone(m2, "cx-bootstrap.sh: MIN_CX_VERSION_FALLBACK not found")
        self.assertEqual(m2.group(1), canon, "cx-bootstrap.sh fallback != cx-min-version")

        guard = _read(_PLUGIN_ROOT, "scripts", "cx-mcp-guard.sh")
        m3 = re.search(r'_CXMCP_FALLBACK="\$\{2:-([^}]+)\}"', guard)
        self.assertIsNotNone(m3, "cx-mcp-guard.sh: cx_mcp_load_min_version fallback not found")
        self.assertEqual(m3.group(1), canon, "cx-mcp-guard.sh fallback != cx-min-version")


class TestReleaseTag(unittest.TestCase):
    def test_tag_matches_plugin_version(self):
        # On a tag build CI sets CX_RELEASE_TAG (e.g. cx-devassist-v1.6.0). Locally it's unset → skip.
        tag = os.environ.get("CX_RELEASE_TAG", "").strip()
        if not tag:
            self.skipTest("CX_RELEASE_TAG not set (not a tag build)")
        m = re.search(r"(\d+\.\d+\.\d+)$", tag)
        self.assertIsNotNone(m, "release tag %r has no semver suffix" % tag)
        self.assertEqual(m.group(1), _plugin_manifest()["version"],
                         "release tag %s does not match plugin.json version" % tag)


class TestShippedBytes(unittest.TestCase):
    """The shell scripts + the version-floor data file must ship LF-only, and cx-min-version must
    be pure ASCII. A stray CR breaks the bootstrap on Linux/macOS (and can fail the gate OPEN);
    a non-ASCII byte in cx-min-version can crash the gate under an ASCII/C locale = fail OPEN."""

    _LF_FILES = [
        ("scripts", "cx-bootstrap.sh"),
        ("scripts", "cx-asset-resolver.sh"),
        ("scripts", "cx-path-probe.sh"),
        ("scripts", "cx-mcp-guard.sh"),
        ("scripts", "cx-min-version"),
        ("hooks", "cx_check.sh"),
        ("hooks", "cx_check.py"),
        ("hooks", "cx_run.sh"),
        ("hooks", "cx_log.py"),
    ]

    def _bytes(self, *parts):
        with open(os.path.join(_PLUGIN_ROOT, *parts), "rb") as f:
            return f.read()

    def test_no_carriage_returns(self):
        for parts in self._LF_FILES:
            self.assertNotIn(b"\r", self._bytes(*parts),
                             "%s contains CR bytes — must be LF-only" % parts[-1])

    def test_cx_min_version_is_pure_ascii(self):
        try:
            self._bytes("scripts", "cx-min-version").decode("ascii")
        except UnicodeDecodeError as e:
            self.fail("cx-min-version is not pure ASCII (would crash the gate under LANG=C): %s" % e)


class TestHookWiring(unittest.TestCase):
    """Stage-2 scanning must run through cx_run.sh (canonical-path resolution, no PATH dependency),
    and the remediation MCP must stay a single `cx` server (activates after one /reload-plugins)."""

    def test_stage2_routes_through_cx_run(self):
        hooks = json.loads(_read(_PLUGIN_ROOT, "hooks", "hooks.json"))
        cmds = [h["command"] for entry in hooks["hooks"]["PreToolUse"]
                for h in entry["hooks"] if h.get("type") == "command"]
        scanner_cmds = [c for c in cmds if "hooks claude-pre" in c]
        self.assertTrue(scanner_cmds, "no stage-2 scanner commands found in hooks.json")
        for c in scanner_cmds:
            self.assertIn("cx_run.sh", c, "stage-2 must resolve cx via cx_run.sh, got: %s" % c)
            self.assertFalse(c.startswith("cx hooks"), "stage-2 must not call bare cx: %s" % c)

    def test_cx_run_wrapper_present(self):
        self.assertTrue(os.path.isfile(os.path.join(_PLUGIN_ROOT, "hooks", "cx_run.sh")))

    def test_no_bare_cx_in_hook_commands(self):
        # Every cx invocation in the hook configs must route through cx_run.sh (absolute-path
        # resolution). A bare `cx …` fails on a locked-down / first-install machine and (for the
        # scanners) fails OPEN. Regression guard for the clean-flow contract, incl. Stop + Copilot.
        for cfg in ("hooks.json", "hooks-copilot-cli.json"):
            data = json.loads(_read(_PLUGIN_ROOT, "hooks", cfg))
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
        # /reload-plugins, with no restart.
        mcp = json.loads(_read(_PLUGIN_ROOT, ".mcp.json"))
        servers = mcp.get("mcpServers", {})
        self.assertEqual(list(servers), ["Checkmarx"])
        srv = servers["Checkmarx"]
        self.assertEqual(srv["command"], "sh")
        self.assertTrue(any("cx_run.sh" in a for a in srv["args"]),
                        "MCP must invoke cx_run.sh, got args: %s" % srv["args"])
        self.assertIn("bridge", srv["args"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
