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
_CLAUDE_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, "..", "plugins", "cx-devassist"))
_COPILOT_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, "..", "plugins", "copilot-devassist"))
_GEMINI_PLUGIN_ROOT = os.path.normpath(os.path.join(_HERE, ".."))
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


class TestClaudeHookTriage(unittest.TestCase):
    """Claude plugin hook-deny triage contract (parity with Gemini GEMINI.md)."""

    def test_claude_md_present_and_requires_triage(self):
        path = os.path.join(_CLAUDE_PLUGIN_ROOT, "CLAUDE.md")
        self.assertTrue(os.path.isfile(path), "CLAUDE.md missing at plugin root")
        ctx = _read(path)
        self.assertIn("remediate** it", ctx)
        self.assertIn("suppress** it", ctx)
        self.assertIn("Never auto-remediate", ctx)

    def test_asca_skill_requires_hook_triage(self):
        asca = _read(_CLAUDE_PLUGIN_ROOT, "skills", "cx-devassist-asca", "SKILL.md")
        self.assertIn("Flow 1b: Hook Triage", asca)
        self.assertIn("remediate** it", asca)
        self.assertIn("suppress** it", asca)
        self.assertNotIn("skip Flow 1 entirely", asca.lower())

    def test_sca_skill_requires_hook_triage(self):
        sca = _read(_CLAUDE_PLUGIN_ROOT, "skills", "cx-devassist-sca", "SKILL.md")
        self.assertIn("Flow 1b: Hook Triage", sca)
        self.assertIn("remediate** it", sca)
        self.assertIn("suppress** it", sca)
        self.assertNotIn("skip Flow 1", sca.lower())

    def test_gemini_oauth_admin_prefill_skip(self):
        oauth = _read(_GEMINI_PLUGIN_ROOT, "skills", "cx-cli-setup", "references", "oauth.md")
        self.assertIn("SKIP Question 2", oauth)
        self.assertIn("preconfigured", oauth.lower())

    def test_gemini_cx_check_incapable_deny_mentions_gemini_hooks(self):
        py = _read(_GEMINI_PLUGIN_ROOT, "hooks", "cx_check.py")
        m = re.search(
            r'if state == "incapable":.*?reason_code="capability_missing"',
            py, re.DOTALL)
        self.assertIsNotNone(m, "incapable deny block not found")
        block = m.group(0)
        self.assertIn("gemini-before-*", block)
        self.assertNotIn("claude-*", block)

    def test_gemini_capability_probes_match_hooks_json(self):
        py = _read(_GEMINI_PLUGIN_ROOT, "hooks", "cx_check.py")
        start = py.find("_CAPABILITY_PROBES")
        self.assertNotEqual(start, -1, "_CAPABILITY_PROBES not found")
        block = py[start:start + 800]
        for route in ("gemini-before-tool", "gemini-before-file-tool", "gemini-after-agent"):
            self.assertIn(route, block, "missing %s in _CAPABILITY_PROBES" % route)
        self.assertNotIn("claude-pre", block)
        self.assertNotIn("claude-stop", block)
        self.assertNotIn("gemini-before-agent", block)

    def test_bootstrap_probes_gemini_file_scanner(self):
        sh = _read(_GEMINI_PLUGIN_ROOT, "scripts", "cx-bootstrap.sh")
        self.assertIn("gemini-before-file-tool", sh)
        self.assertNotIn("claude-pre-tool-use", sh)


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

    def test_gemini_four_sites_agree(self):
        self._check_four_sites(_GEMINI_PLUGIN_ROOT)


class TestGeminiExtension(unittest.TestCase):
    """Gemini CLI extension manifest and skill-routing contract."""

    def test_context_file_present(self):
        manifest = json.loads(_read(_GEMINI_PLUGIN_ROOT, "gemini-extension.json"))
        ctx = manifest.get("contextFileName", "GEMINI.md")
        self.assertTrue(
            os.path.isfile(os.path.join(_GEMINI_PLUGIN_ROOT, ctx)),
            "gemini-extension.json contextFileName %r is missing" % ctx)

    def test_sca_skill_not_triggered_on_manifest_edits(self):
        sca = _read(_GEMINI_PLUGIN_ROOT, "skills", "cx-devassist-sca", "SKILL.md")
        self.assertIn("Do NOT activate", sca,
                      "SCA skill must warn against activation on manifest create/edit")
        self.assertIn("BeforeTool", sca,
                      "SCA skill must reference automatic hook scanning")

    def test_file_write_matcher_includes_writefile(self):
        hooks = json.loads(_read(_GEMINI_PLUGIN_ROOT, "hooks", "hooks.json"))
        matchers = [e.get("matcher", "") for e in hooks["hooks"]["BeforeTool"]]
        file_matchers = [m for m in matchers if "write" in m.lower() or "replace" in m]
        self.assertTrue(file_matchers, "no file-write BeforeTool matcher found")
        combined = "|".join(file_matchers)
        self.assertRegex(combined, r"WriteFile",
                         "file-write matcher must include WriteFile (Gemini CLI tool name)")

    def test_tool_policy_matcher_present(self):
        hooks = json.loads(_read(_GEMINI_PLUGIN_ROOT, "hooks", "hooks.json"))
        cmds = []
        for entry in hooks["hooks"]["BeforeTool"]:
            if "mcp_" in entry.get("matcher", ""):
                for h in entry.get("hooks", []):
                    cmds.append(h.get("command", ""))
        self.assertTrue(any("gemini-before-tool" in c for c in cmds),
                        "mcp_.* must route to gemini-before-tool")

    def test_run_shell_command_is_observer_only(self):
        hooks = json.loads(_read(_GEMINI_PLUGIN_ROOT, "hooks", "hooks.json"))
        shell_entries = [e for e in hooks["hooks"]["BeforeTool"]
                         if e.get("matcher") == "run_shell_command"]
        self.assertEqual(1, len(shell_entries), "run_shell_command must have exactly one matcher entry")
        cmds = [h.get("command", "") for h in shell_entries[0].get("hooks", [])]
        self.assertTrue(any("cx_record_login.sh" in c for c in cmds),
                        "run_shell_command must route only to cx_record_login.sh")
        self.assertFalse(any("cx_check.sh" in c for c in cmds),
                         "run_shell_command must not run the readiness gate")

    def test_after_agent_wires_session_end_hook(self):
        """Peer of Claude's Stop → claude-stop; Gemini uses AfterAgent → gemini-after-agent."""
        hooks = json.loads(_read(_GEMINI_PLUGIN_ROOT, "hooks", "hooks.json"))
        entries = hooks["hooks"].get("AfterAgent", [])
        self.assertTrue(entries, "AfterAgent lifecycle hook must be wired")
        cmds = [h.get("command", "") for e in entries for h in e.get("hooks", [])]
        self.assertTrue(any("gemini-after-agent" in c for c in cmds), cmds)
        self.assertNotIn("BeforeAgent", hooks["hooks"])

    def test_scannable_files_config_present(self):
        path = os.path.join(_GEMINI_PLUGIN_ROOT, "config", "cx-scannable-files")
        self.assertTrue(os.path.isfile(path), "config/cx-scannable-files must ship with the extension")
        with open(path, "rb") as f:
            self.assertIn(b"ext:.py", f.read())

    def test_cx_record_login_script_present(self):
        self.assertTrue(os.path.isfile(os.path.join(_GEMINI_PLUGIN_ROOT, "hooks", "cx_record_login.sh")))

    def test_asca_skill_requires_hook_triage(self):
        asca = _read(_GEMINI_PLUGIN_ROOT, "skills", "cx-devassist-asca", "SKILL.md")
        self.assertIn("Flow 1b: Hook Triage", asca)
        self.assertIn("remediate** it", asca)
        self.assertIn("suppress** it", asca)
        self.assertNotIn("skip Flow 1 entirely", asca.lower())

    def test_gemini_md_requires_hook_triage(self):
        ctx = _read(_GEMINI_PLUGIN_ROOT, "GEMINI.md")
        self.assertIn("remediate** it", ctx)
        self.assertIn("suppress** it", ctx)
        self.assertIn("Never auto-remediate", ctx)

    def test_gemini_md_requires_post_remediation_rescan(self):
        ctx = _read(_GEMINI_PLUGIN_ROOT, "GEMINI.md")
        self.assertIn("Step 4 re-scan is mandatory", ctx)
        self.assertIn("retry the original blocked", ctx)

    def test_asca_skill_requires_step4_rescan(self):
        asca = _read(_GEMINI_PLUGIN_ROOT, "skills", "cx-devassist-asca", "SKILL.md")
        self.assertIn("Step 4 — Re-scan (mandatory)", asca)
        self.assertIn("Do not skip Step 4", asca)
        self.assertIn("file-write tool", asca)

    def test_skill_files_have_no_utf8_bom(self):
        """Gemini CLI's SKILL.md parser requires frontmatter to start with '---'; a UTF-8 BOM breaks discovery."""
        skills_root = os.path.join(_GEMINI_PLUGIN_ROOT, "skills")
        skill_files = []
        for root, _dirs, files in os.walk(skills_root):
            for name in files:
                if name == "SKILL.md":
                    skill_files.append(os.path.join(root, name))
        self.assertGreaterEqual(len(skill_files), 3, "expected at least 3 SKILL.md files")
        for path in skill_files:
            with open(path, "rb") as f:
                head = f.read(3)
            self.assertNotEqual(head, b"\xef\xbb\xbf",
                                "%s has UTF-8 BOM — Gemini will not discover this skill" % path)

    def test_gemini_deny_uses_exit_zero_and_system_message(self):
        py = _read(_GEMINI_PLUGIN_ROOT, "hooks", "cx_check.py")
        m = re.search(r'def _deny\(.*?sys\.exit\(_deny_exit\)', py, re.DOTALL)
        self.assertIsNotNone(m, "_deny() not found")
        block = m.group(0)
        self.assertIn("systemMessage", block)
        self.assertIn("_deny_exit = 0 if _GEMINI_CLI_MODE else 2", block)

    def test_gemini_cx_run_absent_uses_exit_zero(self):
        sh = _read(_GEMINI_PLUGIN_ROOT, "hooks", "cx_run.sh")
        self.assertIn("systemMessage", sh)
        self.assertIn("*gemini-before*) exit 0", sh.replace("\n", " ").replace("  ", " ") or sh)
        # literal check without whitespace normalization issues
        self.assertRegex(sh, r'\*gemini-before\*\)\s*exit 0')


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
        ("hooks", "cx_log.py"),
    ]

    _GEMINI_ONLY_LF_FILES = [
        ("config", "cx-scannable-files"),
    ]

    def _bytes(self, plugin_root, *parts):
        with open(os.path.join(plugin_root, *parts), "rb") as f:
            return f.read()

    def test_no_carriage_returns(self):
        for plugin_root in (_CLAUDE_PLUGIN_ROOT, _COPILOT_PLUGIN_ROOT, _GEMINI_PLUGIN_ROOT):
            for parts in self._LF_FILES:
                self.assertNotIn(b"\r", self._bytes(plugin_root, *parts),
                                 "%s/%s contains CR bytes — must be LF-only" % (
                                     os.path.basename(plugin_root), parts[-1]))
        for parts in self._GEMINI_ONLY_LF_FILES:
            self.assertNotIn(b"\r", self._bytes(_GEMINI_PLUGIN_ROOT, *parts),
                             "cx-agentic-ai/%s contains CR bytes — must be LF-only" % parts[-1])

    def test_cx_min_version_is_pure_ascii(self):
        for plugin_root in (_CLAUDE_PLUGIN_ROOT, _COPILOT_PLUGIN_ROOT, _GEMINI_PLUGIN_ROOT):
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
        for plugin_root in (_CLAUDE_PLUGIN_ROOT, _COPILOT_PLUGIN_ROOT, _GEMINI_PLUGIN_ROOT):
            self.assertTrue(
                os.path.isfile(os.path.join(plugin_root, "hooks", "cx_run.sh")),
                "cx_run.sh missing in %s" % os.path.basename(plugin_root))

    def test_no_bare_cx_in_hook_commands(self):
        # Every cx invocation in the hook configs must route through cx_run.sh (absolute-path
        # resolution). A bare `cx …` fails on a locked-down / first-install machine and (for the
        # scanners) fails OPEN. Regression guard for the clean-flow contract.
        hook_configs = [
            (_CLAUDE_PLUGIN_ROOT, "hooks.json"),
            (_COPILOT_PLUGIN_ROOT, "hooks-copilot-cli.json"),
            (_GEMINI_PLUGIN_ROOT, "hooks.json"),
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
