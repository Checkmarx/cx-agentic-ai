"""Unit tests for the Dev Assist analytics telemetry module (hooks/cx_telemetry.py) and its wiring into
each plugin's readiness gate.

Each plugin ships its own copy of cx_telemetry.py. The checks below run for every plugin that ships one
(a branch may carry only some of them); every copy must be identical.

Run: python3 tests/test_cx_telemetry.py    (stdlib only — no pytest needed)
"""

import importlib.util
import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("CX_TELEMETRY_DISABLE", "1")

_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# plugin -> (hooks dir, manifest path parts)
_PLUGINS = {
    "claude": (("plugins", "cx-devassist", "hooks"), ("plugins", "cx-devassist", ".claude-plugin", "plugin.json")),
    "copilot": (("plugins", "copilot-devassist", "hooks"), ("plugins", "copilot-devassist", "plugin.json")),
    "gemini": (("hooks",), ("gemini-extension.json",)),
    "cursor": (("plugins", "cursor-devassist", "hooks"), ("plugins", "cursor-devassist", ".cursor-plugin", "plugin.json")),
    "codex": (("plugins", "codex-devassist", "hooks"), ("plugins", "codex-devassist", ".codex-plugin", "plugin.json")),
}


def _hooks(name):
    return os.path.join(_ROOT, *_PLUGINS[name][0])


_SHIPPED = [n for n in _PLUGINS if os.path.isfile(os.path.join(_hooks(n), "cx_telemetry.py"))]


def _read(path):
    """Bytes of a file inside this repository. The path is normalized and must stay under the repo
    root and exist."""
    target = os.path.normpath(os.path.abspath(path))
    if os.path.commonpath([target, _ROOT]) != _ROOT or not os.path.isfile(target):
        raise ValueError("not a file inside the repository: %s" % path)
    with open(target, "rb") as f:
        return f.read()


def _load(name):
    spec = importlib.util.spec_from_file_location(
        "cx_telemetry_" + name, os.path.join(_hooks(name), "cx_telemetry.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cx_telemetry = _load(_SHIPPED[0]) if _SHIPPED else None


@unittest.skipUnless(_SHIPPED, "no plugin ships cx_telemetry.py on this branch")
class CopiesTest(unittest.TestCase):
    def test_every_shipped_copy_is_identical(self):
        reference = _read(os.path.join(_hooks(_SHIPPED[0]), "cx_telemetry.py"))
        for name in _SHIPPED:
            with self.subTest(plugin=name):
                self.assertEqual(_read(os.path.join(_hooks(name), "cx_telemetry.py")), reference,
                                 "cx_telemetry.py drifted in %s" % name)

    def test_each_shipping_plugin_is_wired(self):
        for name in _SHIPPED:
            with self.subTest(plugin=name):
                gate = _read(os.path.join(_hooks(name), "cx_check.py")).decode("utf-8")
                for needle in ("import cx_telemetry", '"--agent", _telemetry_agent_label()',
                               '_telemetry("note_unauthenticated", _credential_mtime())',
                               '_telemetry("on_gate_pass"', "cred_mtime=_credential_mtime()",
                               '_telemetry("note_login_command"', "cx_telemetry.credential_mtime("):
                    self.assertIn(needle, gate)
                run = _read(os.path.join(_hooks(name), "cx_run.sh")).decode("utf-8")
                self.assertIn("CX_AGENT_VERSION | CX_PLUGIN_VERSION | CX_PLUGIN_TYPE", run)
                log = _read(os.path.join(_hooks(name), "cx_log.py")).decode("utf-8")
                self.assertIn('"telemetry": {', log)

    def test_plugin_version_reads_each_manifest(self):
        for name in _SHIPPED:
            with self.subTest(plugin=name):
                want = json.loads(_read(os.path.join(_ROOT, *_PLUGINS[name][1])).decode("utf-8-sig"))["version"]
                self.assertEqual(_load(name).plugin_version(), want)


@unittest.skipUnless(_SHIPPED, "no plugin ships cx_telemetry.py on this branch")
class HelpersTest(unittest.TestCase):
    def test_agent_labels_match_ast_cli(self):
        expected = {"claude": "Claude-cli", "copilot-cli": "Copilot-cli", "copilot-vscode": "Copilot-VSCode",
                    "gemini-cli": "Gemini-cli", "cursor": "Cursor-cli", "codex": "Codex-cli", "nope": ""}
        for client, label in expected.items():
            self.assertEqual(cx_telemetry.agent_label(client), label)

    def test_auth_method_for_command(self):
        f = cx_telemetry.auth_method_for_command
        self.assertEqual(f("cx auth login --base-auth-uri https://x --tenant t"), "OAuth")
        self.assertEqual(f('"C:/cx/cx.exe" configure set --prop-name cx_apikey --prop-value k'), "APIKey")
        self.assertEqual(f("cx auth validate --apikey k"), "APIKey")
        self.assertEqual(f("cx configure set --prop-name cx_tenant --prop-value t"), "")
        self.assertEqual(f(""), "")

    def test_safe_strips_everything_but_version_characters(self):
        self.assertEqual(cx_telemetry._safe("2.1.4 (Claude Code)"), "2.1.4ClaudeCode")
        self.assertEqual(cx_telemetry._safe("1.0;rm -rf /"), "1.0rm-rf")
        self.assertEqual(cx_telemetry._safe(None), "")

    def test_auth_command(self):
        cmd = cx_telemetry.auth_command("cx", "claude", "2.1.4", "1.0.3", "OAuth")
        self.assertEqual(cmd[:3], ["cx", "telemetry", "ai"])
        for flag, value in (("--agent", "Claude-cli"), ("--type", "authentication"), ("--status", "success"),
                            ("--plugin-type", "CLI"), ("--agent-version", "2.1.4"),
                            ("--cx-plugin-version", "1.0.3"), ("--event-attributes", "authMethod=OAuth")):
            self.assertEqual(cmd[cmd.index(flag) + 1], value)

    def test_auth_command_omits_unknown_values(self):
        cmd = cx_telemetry.auth_command("cx", "codex", "", "", "")
        for flag in ("--agent-version", "--cx-plugin-version", "--event-attributes"):
            self.assertNotIn(flag, cmd)


class _TempDirs(unittest.TestCase):
    """A temp plugin state dir and a temp ~/.checkmarx (credential file + alias file)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cx-telemetry-state-")
        self.cxdir = tempfile.mkdtemp(prefix="cx-telemetry-home-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.addCleanup(shutil.rmtree, self.cxdir, True)
        cfg = mock.patch.object(cx_telemetry, "_cx_config_dir", return_value=self.cxdir)
        cfg.start()
        self.addCleanup(cfg.stop)
        env = mock.patch.dict(os.environ, {"CX_TELEMETRY_DISABLE": ""})
        env.start()
        self.addCleanup(env.stop)

    def state(self):
        with open(os.path.join(self.dir, cx_telemetry.STATE_FILE), "r", encoding="utf-8") as f:
            return json.load(f)

    def write_credential(self, mtime):
        path = os.path.join(self.cxdir, "checkmarxcli.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("cx_apikey: x\n")
        os.utime(path, (mtime, mtime))


@unittest.skipUnless(_SHIPPED, "no plugin ships cx_telemetry.py on this branch")
class GatePassTest(_TempDirs):
    def setUp(self):
        super().setUp()
        self.spawned = []
        spawn = mock.patch.object(cx_telemetry, "_spawn_worker", side_effect=self.spawned.append)
        spawn.start()
        self.addCleanup(spawn.stop)

    def mark_sent(self):
        state = self.state() if os.path.exists(os.path.join(self.dir, cx_telemetry.STATE_FILE)) else {}
        state.pop("auth_inflight", None)
        state["auth_sent"] = True
        with open(os.path.join(self.dir, cx_telemetry.STATE_FILE), "w", encoding="utf-8") as f:
            json.dump(state, f)
        cx_telemetry.write_context(self.dir, "2.1.4", "1.0.3")

    def test_first_pass_starts_a_sender_and_does_not_mark_it_sent(self):
        self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "claude", "cx", cred_mtime=100.0), "auth")
        state = self.state()
        self.assertNotIn("auth_sent", state, "only the worker marks it sent, after cx succeeds")
        self.assertIn("auth_inflight", state)

    def test_no_second_sender_while_one_is_in_flight(self):
        cx_telemetry.on_gate_pass(self.dir, "claude", "cx", cred_mtime=100.0)
        cx_telemetry.write_context(self.dir, "2.1.4", "1.0.3")
        self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "claude", "cx", cred_mtime=100.0), "")
        self.assertEqual(len(self.spawned), 1)

    def test_failed_send_is_retried_after_the_retry_window(self):
        now = time.time()
        cx_telemetry.on_gate_pass(self.dir, "claude", "cx", cred_mtime=100.0, now=now)
        later = now + cx_telemetry.AUTH_RETRY_AFTER + 1
        self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "claude", "cx", cred_mtime=100.0, now=later), "auth")

    def test_sent_and_fresh_is_a_no_op(self):
        self.mark_sent()
        self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "claude", "cx", cred_mtime=100.0), "")
        self.assertEqual(self.spawned, [])

    def test_new_login_sends_with_the_observed_method(self):
        self.mark_sent()
        cx_telemetry.note_unauthenticated(self.dir, 100.0)
        cx_telemetry.note_login_command(self.dir, "cx auth login --base-auth-uri https://x --tenant t")
        self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "claude", "cx", cred_mtime=200.0), "auth")
        args = self.spawned[-1]
        self.assertEqual(args[args.index("--auth-method") + 1], "OAuth")

    def test_timeout_without_a_credential_change_is_not_a_login(self):
        self.mark_sent()
        cx_telemetry.note_unauthenticated(self.dir, 100.0)
        self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "claude", "cx", cred_mtime=100.0), "")
        self.assertNotIn("pending_login", self.state(), "the pending login is dropped")
        self.assertEqual(self.spawned, [])

    def test_method_is_not_reported_for_the_first_ever_event(self):
        cx_telemetry.note_login_command(self.dir, "cx auth login --base-auth-uri https://x --tenant t")
        cx_telemetry.on_gate_pass(self.dir, "claude", "cx", cred_mtime=100.0)
        args = self.spawned[-1]
        self.assertEqual(args[args.index("--auth-method") + 1], "")

    def test_stale_context_only_refreshes_the_context(self):
        self.mark_sent()
        old = time.time() - cx_telemetry.CONTEXT_TTL - 60
        os.utime(os.path.join(self.dir, cx_telemetry.CONTEXT_FILE), (old, old))
        self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "claude", "cx", "9.9.9", cred_mtime=1.0), "context")
        self.assertNotIn("--auth-method", self.spawned[-1])

    def test_disabled_is_a_no_op(self):
        with mock.patch.dict(os.environ, {"CX_TELEMETRY_DISABLE": "1"}):
            self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "claude", "cx"), "")
            cx_telemetry.note_unauthenticated(self.dir, 1.0)
        self.assertEqual(self.spawned, [])
        self.assertFalse(os.path.exists(os.path.join(self.dir, cx_telemetry.STATE_FILE)))

    def test_never_raises_on_bad_input(self):
        missing = os.path.join(self.dir, "missing")
        self.assertEqual(cx_telemetry.on_gate_pass(missing, "claude", "cx"), "")
        self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "unknown-client", "cx"), "")
        cx_telemetry.note_unauthenticated(missing, 1.0)
        cx_telemetry.note_login_command(missing, "cx auth login")
        with open(os.path.join(self.dir, cx_telemetry.STATE_FILE), "w", encoding="utf-8") as f:
            f.write("{not json")
        self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "claude", "cx"), "auth")

    def test_spawn_failure_is_swallowed(self):
        with mock.patch.object(cx_telemetry, "_spawn_worker", side_effect=OSError("boom")):
            self.assertEqual(cx_telemetry.on_gate_pass(self.dir, "claude", "cx"), "")


@unittest.skipUnless(_SHIPPED, "no plugin ships cx_telemetry.py on this branch")
class SendTest(_TempDirs):
    def fake_run(self, supported=True, code=0, rewrite_to=None):
        calls = []

        def run(cmd, timeout):
            calls.append(list(cmd))
            if list(cmd[1:4]) == ["telemetry", "ai", "--help"]:
                return (0, "--event-attributes --agent-version") if supported else (1, "unknown flag")
            if rewrite_to is not None:  # cx writes the new session id into the credential file
                self.write_credential(rewrite_to)
            return code, ""
        return run, calls

    def send(self, **kw):
        run, calls = self.fake_run(**kw)
        with mock.patch.object(cx_telemetry, "_run", side_effect=run):
            ok = cx_telemetry.send_auth_event(self.dir, "cursor", "cx", "1.7.2", "1.0.3", "OAuth")
        return ok, calls

    def test_success_marks_sent_and_clears_the_pending_login(self):
        cx_telemetry.note_unauthenticated(self.dir, 1.0)
        ok, calls = self.send()
        self.assertTrue(ok)
        self.assertEqual(self.state(), {"auth_sent": True})
        sends = [c for c in calls if "--type" in c]
        self.assertEqual(sends[0][sends[0].index("--agent") + 1], "Cursor-cli")

    def test_failure_leaves_it_unsent(self):
        ok, _ = self.send(code=1)
        self.assertFalse(ok)
        self.assertFalse(os.path.exists(os.path.join(self.dir, cx_telemetry.STATE_FILE)))

    def test_old_cx_sends_nothing(self):
        ok, calls = self.send(supported=False)
        self.assertFalse(ok)
        self.assertFalse([c for c in calls if "--type" in c])

    def test_the_session_id_write_is_not_a_credential_change(self):
        self.write_credential(1000.0)
        self.send(rewrite_to=2000.0)
        self.assertEqual(cx_telemetry.credential_mtime(self.dir, 2000.0), 1000.0)
        self.assertEqual(cx_telemetry.credential_mtime(self.dir, 3000.0), 3000.0, "a real change stays")
        self.assertIsNone(cx_telemetry.credential_mtime(self.dir, None))

    def test_aliases_chain_across_sends(self):
        self.write_credential(1000.0)
        self.send(rewrite_to=2000.0)
        self.send(rewrite_to=3000.0)
        self.assertEqual(cx_telemetry.credential_mtime(self.dir, 3000.0), 1000.0)

    def test_hook_context_prepares_cold_copilot_scan_without_sending_authentication(self):
        state_dir = os.path.join(self.dir, "cold")
        args = ["hook-context", "--state-dir", state_dir, "--client", "copilot-cli"]
        with mock.patch.object(cx_telemetry, "detect_agent_version", return_value="1.0.116") as version, \
                mock.patch.object(cx_telemetry, "plugin_version", return_value="1.0.5"), \
                mock.patch.object(cx_telemetry, "send_auth_event") as auth:
            self.assertEqual(cx_telemetry.worker_main(args), 0)
            self.assertEqual(cx_telemetry.worker_main(args), 0)
        version.assert_called_once_with("copilot-cli", "", timeout=cx_telemetry.HOOK_VERSION_TIMEOUT)
        auth.assert_not_called()
        with open(os.path.join(state_dir, cx_telemetry.CONTEXT_FILE), "rb") as f:
            self.assertEqual(f.read(),
                             b"CX_AGENT_VERSION=1.0.116\nCX_PLUGIN_VERSION=1.0.5\nCX_PLUGIN_TYPE=CLI\n")

    def test_worker_writes_the_context(self):
        run, _ = self.fake_run()
        args = ["context", "--state-dir", self.dir, "--client", "cursor", "--cx", "cx", "--agent-version", "1.7.2"]
        with mock.patch.object(cx_telemetry, "_run", side_effect=run):
            self.assertEqual(cx_telemetry.worker_main(args), 0)
        with open(os.path.join(self.dir, cx_telemetry.CONTEXT_FILE), "r", encoding="utf-8") as f:
            context = f.read()
        self.assertIn("CX_AGENT_VERSION=1.7.2\n", context)
        self.assertIn("CX_PLUGIN_TYPE=CLI\n", context)

    def test_bad_arguments_exit_cleanly(self):
        self.assertEqual(cx_telemetry.worker_main([]), 0)
        self.assertEqual(cx_telemetry.worker_main(["auth", "--client", "claude"]), 0)
        self.assertEqual(cx_telemetry.worker_main(["other"]), 0)


if __name__ == "__main__":
    unittest.main()
