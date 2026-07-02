"""Packaging invariants — guard the Phase-4 release contract (stdlib only).

These fail fast if the plugin's identity ever drifts: a single version identity, no redundant
`mcpServers` declaration (the `.mcp.json` is auto-discovered), the three synced CX_MIN_VERSION
sites agreeing, the marketplace pointing at a real plugin, and — on a tag build — the release tag
matching `plugin.json`.

Run: python tests/test_packaging.py
"""

import json
import os
import re
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, "..", "plugins", "cx-security"))
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
        self.assertEqual(data["name"], "cx-security")
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
        entry = next((p for p in mp.get("plugins", []) if p.get("name") == "cx-security"), None)
        self.assertIsNotNone(entry, "marketplace.json has no cx-security plugin entry")
        src = os.path.normpath(os.path.join(_REPO_ROOT, entry["source"]))
        self.assertTrue(os.path.isdir(src), "marketplace source path missing: %s" % src)


class TestMinVersionSync(unittest.TestCase):
    """The numeric floor lives in three synced sites (search marker: CX_MIN_VERSION)."""

    def _canonical(self):
        for line in _read(_PLUGIN_ROOT, "scripts", "cx-min-version").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                return s
        self.fail("no version line found in scripts/cx-min-version")

    def test_three_sites_agree(self):
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


class TestReleaseTag(unittest.TestCase):
    def test_tag_matches_plugin_version(self):
        # On a tag build CI sets CX_RELEASE_TAG (e.g. cx-security-v1.6.0). Locally it's unset → skip.
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
        ("scripts", "cx-min-version"),
        ("hooks", "cx_check.sh"),
        ("hooks", "cx_check.py"),
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
