"""cx_telemetry — Dev Assist analytics events sent from the readiness gate (cx_check.py).

The scan and remediation events are sent by `cx hooks` itself (ast-cli). This module covers what only
the plugin can see:

  * the AUTHENTICATION event — sent once on the first authenticated gate pass, and again each time the
    gate goes from unauthenticated back to authenticated (a new login). `cx telemetry ai --type
    authentication --status success` is also what creates the session id the later scan and
    remediation events carry, so this event must be sent for those to join up.
  * the plugin CONTEXT file — agent version, plugin version and plugin type, which hooks/cx_run.sh
    exports as CX_AGENT_VERSION / CX_PLUGIN_VERSION / CX_PLUGIN_TYPE so `cx hooks` can add them to its
    own events.

A new login is detected as: the gate saw cx unauthenticated, and on a later authenticated pass the
credential file (~/.checkmarx/checkmarxcli.yaml) has changed since then. API-key logins happen in the
developer's own terminal, out of the gate's sight, so this is the one signal both login kinds share.
Requiring the credential change means a backend timeout (which the gate cannot tell apart from
"unauthenticated") is not counted as a login.

Sending the authentication event makes cx write the new session id into that same file. The worker
records the file's mtime before and after its own send (cx_telemetry_cred.json, shared by every
plugin), and credential_mtime() maps the "after" value back to "before", so the gate's credential
checks (scanner cache key, fresh-login window, login history) never mistake that write for a login.

The capability check and authentication telemetry POST run in a detached worker. Copilot CLI can
also prepare the context synchronously before its first scan, using a bounded local version probe.
Errors go to a module logger with only a NullHandler, keeping hook output clear.

This file is IDENTICAL in every plugin (cx-devassist, copilot-devassist, cursor-devassist,
codex-devassist, and the Gemini extension's root hooks/); tests/test_cx_telemetry.py enforces that.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time

_LOG = logging.getLogger("cx_telemetry")
_LOG.addHandler(logging.NullHandler())
_LOG.propagate = False

STATE_FILE = "cx_telemetry_state.json"
CONTEXT_FILE = "cx_telemetry_context"
CONTEXT_TTL = 24 * 60 * 60  # refresh the agent/plugin versions once a day
HOOK_VERSION_TIMEOUT = 3  # bound the local version probe on a cold scan
_CLOCK_SKEW = 5 * 60
# An authentication send that has not reported success within this window is retried. It also spaces
# out retries when the installed cx cannot send (too old), instead of a worker on every gate pass.
AUTH_RETRY_AFTER = 30 * 60
CRED_ALIAS_FILE = "cx_telemetry_cred.json"
_MAX_CRED_ALIASES = 5
PLUGIN_TYPE = "CLI"

# Auth-method labels from the analytics design (eventAttributes.authMethod). Labels, not credentials.
AUTH_METHOD_OAUTH = "OAuth"
AUTH_METHOD_APIKEY = os.environ.get("CX_TELEMETRY_AUTH_METHOD_APIKEY_LABEL", "APIKey")
AUTH_STATUS_RESULT = "Authentication successful."

# Client key -> (telemetry agent label, command printing the agent's version or None). The labels match
# what ast-cli's hostenv.TelemetryAgent sends for the scan/remediation events ("<Agent>-cli", and
# "Copilot-VSCode" for Copilot inside VS Code), so all of a developer's events share one agent value.
_CLIENTS = {
    "claude": ("Claude-cli", ("claude", "--version")),
    "copilot-cli": ("Copilot-cli", ("copilot", "--version")),
    "copilot-vscode": ("Copilot-VSCode", None),
    "gemini-cli": ("Gemini-cli", ("gemini", "--version")),
    "cursor": ("Cursor-cli", None),  # the version comes from the hook payload's cursor_version
    "codex": ("Codex-cli", ("codex", "--version")),
}

# The plugin manifest, relative to this hooks/ directory. Each plugin ships exactly one of these.
_MANIFESTS = (
    ("..", "gemini-extension.json"),
    ("..", "plugin.json"),
    ("..", ".claude-plugin", "plugin.json"),
    ("..", ".cursor-plugin", "plugin.json"),
    ("..", ".codex-plugin", "plugin.json"),
)

_SAFE_VALUE_RE = re.compile(r"[^A-Za-z0-9._+\-]")
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?")
_AUTH_LOGIN_RE = re.compile(r"\bauth\s+login\b")
_APIKEY_RE = re.compile(r"\bconfigure\s+set\b.*\bcx_apikey\b|--apikey\b", re.IGNORECASE)
_MAX_STATE_BYTES = 4096

_WIN_CREATE_NO_WINDOW = 0x08000000
_WIN_DETACHED_PROCESS = 0x00000008
_WIN_NEW_PROCESS_GROUP = 0x00000200


# --- small helpers --------------------------------------------------------------------------------

def disabled():
    """CX_TELEMETRY_DISABLE=1 turns every gate hook below into a no-op (the test suites set it, so a
    test run never starts a worker that could send a real event)."""
    return os.environ.get("CX_TELEMETRY_DISABLE") == "1"


def agent_label(client):
    """The telemetry agent label for a client key, or "" for an unknown client."""
    entry = _CLIENTS.get(client)
    return entry[0] if entry else ""


def _safe(value, limit=64):
    """A value safe to write into the context file and to pass on a command line."""
    return _SAFE_VALUE_RE.sub("", str(value or ""))[:limit]


def _path(state_dir, name):
    """The state file `name` inside state_dir. state_dir is normalized and must be an existing
    directory; `name` is always one of this module's fixed file names."""
    base = os.path.normpath(os.path.abspath(state_dir or ""))
    if not state_dir or not os.path.isdir(base):
        raise ValueError("telemetry state directory is not an existing directory")
    if name not in (STATE_FILE, CONTEXT_FILE):
        raise ValueError("unexpected telemetry state file name")
    return os.path.join(base, name)


def _read_state(state_dir):
    try:
        with open(_path(state_dir, STATE_FILE), "r", encoding="utf-8") as f:
            raw = f.read(_MAX_STATE_BYTES + 1)
        if len(raw) > _MAX_STATE_BYTES:
            return {}
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_atomic(path, text):
    """Write text to path via a temporary sibling file. Both paths are normalized, the parent
    directory must exist, and the temporary file must stay inside that same directory."""
    target = os.path.normpath(os.path.abspath(path))
    parent = os.path.dirname(target)
    if not os.path.isdir(parent):
        raise ValueError("telemetry state directory does not exist")
    tmp = os.path.normpath(os.path.abspath("%s.%d.tmp" % (target, os.getpid())))
    if os.path.dirname(tmp) != parent:
        raise ValueError("temporary telemetry file escapes the state directory")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, target)


def _write_state(state_dir, state):
    _write_atomic(_path(state_dir, STATE_FILE), json.dumps(state, sort_keys=True))


def _context_is_fresh(state_dir, now=None):
    try:
        age = (now or time.time()) - os.path.getmtime(_path(state_dir, CONTEXT_FILE))
    except (OSError, ValueError):
        return False
    # A file written moments ago can carry an mtime slightly AHEAD of time.time() (filesystem
    # timestamp granularity, clock adjustments), so allow a small negative age.
    return -_CLOCK_SKEW < age < CONTEXT_TTL


def _cx_config_dir():
    return os.path.normpath(os.path.join(os.path.expanduser("~"), ".checkmarx"))


def _cred_alias_path():
    """~/.checkmarx/cx_telemetry_cred.json — next to the credential file, shared by every plugin."""
    base = _cx_config_dir()
    if not os.path.isdir(base):
        raise ValueError("cx config directory does not exist")
    return os.path.join(base, CRED_ALIAS_FILE)


def _credential_file_mtime():
    try:
        return os.path.getmtime(os.path.join(_cx_config_dir(), "checkmarxcli.yaml"))
    except OSError:
        return None


def _read_cred_aliases():
    try:
        with open(_cred_alias_path(), "r", encoding="utf-8") as f:
            raw = f.read(_MAX_STATE_BYTES + 1)
        pairs = json.loads(raw) if len(raw) <= _MAX_STATE_BYTES else []
    except (OSError, ValueError):
        return []
    if not isinstance(pairs, list):
        return []
    return [p for p in pairs if isinstance(p, list) and len(p) == 2
            and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in p)]


def _record_cred_alias(before, after):
    """Remember that our own `cx telemetry ai` call moved the credential mtime from before to after."""
    pairs = [p for p in _read_cred_aliases() if p[1] != after]
    pairs.append([before, after])
    _write_atomic(_cred_alias_path(), json.dumps(pairs[-_MAX_CRED_ALIASES:]))


def credential_mtime(state_dir, mtime):
    """The credential mtime the gate should see: `mtime`, with every change made by a telemetry send
    (ours or another plugin's) undone. state_dir is unused; it keeps the gate's call shape uniform."""
    if mtime is None:
        return None
    try:
        pairs = _read_cred_aliases()
        for _ in range(len(pairs)):
            earlier = [b for b, a in pairs if a == mtime]
            if not earlier:
                break
            mtime = earlier[-1]
    except Exception as e:
        _LOG.error("credential_mtime failed: %s", type(e).__name__)
    return mtime


def auth_method_for_command(command):
    """OAuth for `cx auth login`, the API-key label for setting cx_apikey / --apikey, else ""."""
    if not command:
        return ""
    if _AUTH_LOGIN_RE.search(command):
        return AUTH_METHOD_OAUTH
    if _APIKEY_RE.search(command):
        return AUTH_METHOD_APIKEY
    return ""


# --- called by the gate (must be cheap and never raise) -------------------------------------------

def note_unauthenticated(state_dir, cred_mtime=None):
    """The gate found cx unauthenticated. If the credential has changed by the next authenticated pass,
    that pass is a new login. cred_mtime is the gate's (alias-resolved) credential mtime right now."""
    if disabled():
        return
    try:
        state = _read_state(state_dir)
        if not state.get("pending_login"):
            state["pending_login"] = True
            state["pending_cred"] = cred_mtime
            _write_state(state_dir, state)
    except Exception as e:
        _LOG.error("note_unauthenticated failed: %s", type(e).__name__)


def note_login_command(state_dir, command):
    """Remember how the developer is signing in, from a login command the gate observed."""
    if disabled():
        return
    try:
        method = auth_method_for_command(command)
        if not method:
            return
        state = _read_state(state_dir)
        if state.get("auth_method") != method:
            state["auth_method"] = method
            _write_state(state_dir, state)
    except Exception as e:
        _LOG.error("note_login_command failed: %s", type(e).__name__)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def on_gate_pass(state_dir, client, cx_exe, agent_version="", cred_mtime=None, now=None):
    """The gate passed (authenticated, scanner ready). Starts the detached worker when the
    authentication event is due or the context file is stale; otherwise costs one read and one stat.
    cred_mtime is the gate's (alias-resolved) credential mtime. Returns the worker mode started
    ("auth", "context") or "" — for tests and logging."""
    if disabled():
        return ""
    try:
        if not state_dir or client not in _CLIENTS:
            return ""
        now = now or time.time()
        state = _read_state(state_dir)
        changed = False
        login = False
        if state.get("pending_login"):
            if cred_mtime != state.get("pending_cred"):
                login = True  # the credential changed since cx looked unauthenticated: a new login
            else:
                # Same credential as when cx looked unauthenticated: the backend was slow or
                # unreachable, which the gate cannot tell apart from "unauthenticated". Not a login.
                state.pop("pending_login", None)
                state.pop("pending_cred", None)
                changed = True
        auth_due = login or not state.get("auth_sent")
        inflight = state.get("auth_inflight")
        if auth_due and _is_number(inflight) and 0 <= now - inflight < AUTH_RETRY_AFTER:
            auth_due = False  # a worker is sending now, or one failed recently: retry later
        if not auth_due and _context_is_fresh(state_dir, now):
            if changed:
                _write_state(state_dir, state)
            return ""
        args = ["--state-dir", state_dir, "--client", client, "--cx", cx_exe or "cx",
                "--agent-version", _safe(agent_version)]
        if auth_due:
            method = state.get("auth_method") if login else ""
            args += ["--auth-method", _safe(method)]
            # Recorded BEFORE spawning so concurrent gate passes do not each start a sender. The
            # worker marks the event sent only after cx reports success; otherwise it is retried
            # after AUTH_RETRY_AFTER.
            state["auth_inflight"] = now
            changed = True
        if changed:
            _write_state(state_dir, state)
        mode = "auth" if auth_due else "context"
        _spawn_worker([mode] + args)
        return mode
    except Exception as e:
        _LOG.error("on_gate_pass failed: %s", type(e).__name__)
        return ""


def _spawn_worker(args):
    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
              "stderr": subprocess.DEVNULL, "close_fds": True}
    if os.name == "nt":
        kwargs["creationflags"] = _WIN_DETACHED_PROCESS | _WIN_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen([sys.executable, os.path.abspath(__file__)] + list(args), **kwargs)


# --- the detached worker ---------------------------------------------------------------------------

def _run(cmd, timeout):
    """Run a command without a console window; returns (exit code, combined output) or (None, "")."""
    kwargs = {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
              "stderr": subprocess.STDOUT, "timeout": timeout}
    if os.name == "nt":
        kwargs["creationflags"] = _WIN_CREATE_NO_WINDOW
    try:
        result = subprocess.run(list(cmd), **kwargs)
        return result.returncode, result.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError, ValueError):
        return None, ""


def plugin_version():
    base = os.path.dirname(os.path.abspath(__file__))
    for parts in _MANIFESTS:
        try:
            with open(os.path.join(base, *parts), "r", encoding="utf-8-sig") as f:
                version = _safe(json.load(f).get("version", ""))
            if version:
                return version
        except (OSError, ValueError, AttributeError):
            continue
    return ""


def detect_agent_version(client, given="", timeout=10):
    if given:
        return _safe(given)
    entry = _CLIENTS.get(client)
    if not entry or not entry[1]:
        return ""
    exe = shutil.which(entry[1][0])
    if not exe:
        return ""
    code, out = _run((exe,) + tuple(entry[1][1:]), timeout=timeout)
    match = _VERSION_RE.search(out) if code == 0 else None
    return _safe(match.group(0)) if match else ""


def write_context(state_dir, agent_version, plugin_ver):
    lines = ["CX_AGENT_VERSION=" + _safe(agent_version),
             "CX_PLUGIN_VERSION=" + _safe(plugin_ver),
             "CX_PLUGIN_TYPE=" + PLUGIN_TYPE]
    _write_atomic(_path(state_dir, CONTEXT_FILE), "\n".join(lines) + "\n")


def telemetry_supported(cx_exe):
    """True when this cx accepts the analytics flags (older builds reject unknown flags)."""
    code, out = _run((cx_exe, "telemetry", "ai", "--help"), timeout=15)
    return code == 0 and "--event-attributes" in out and "--agent-version" in out


def auth_command(cx_exe, client, agent_version, plugin_ver, auth_method):
    cmd = [cx_exe, "telemetry", "ai",
           "--type", "authentication", "--sub-type", "authentication",
           "--agent", agent_label(client),
           "--plugin-type", PLUGIN_TYPE,
           "--status", "success", "--status-result", AUTH_STATUS_RESULT]
    if agent_version:
        cmd += ["--agent-version", agent_version]
    if plugin_ver:
        cmd += ["--cx-plugin-version", plugin_ver]
    if auth_method in (AUTH_METHOD_OAUTH, AUTH_METHOD_APIKEY):
        cmd += ["--event-attributes", "authMethod=" + auth_method]
    return cmd


def _parse_args(argv):
    opts = {}
    i = 0
    while i < len(argv) - 1:
        if argv[i].startswith("--"):
            opts[argv[i][2:]] = argv[i + 1]
            i += 2
        else:
            i += 1
    return opts


def worker_main(argv):
    if not argv or argv[0] not in ("auth", "context", "hook-context"):
        return 0
    mode = argv[0]
    opts = _parse_args(argv[1:])
    state_dir, client = opts.get("state-dir", ""), opts.get("client", "")
    if not state_dir or client not in _CLIENTS:
        return 0
    if mode == "hook-context" and (disabled() or _context_is_fresh(state_dir)):
        return 0
    version_timeout = HOOK_VERSION_TIMEOUT if mode == "hook-context" else 10
    agent_ver = detect_agent_version(client, opts.get("agent-version", ""), timeout=version_timeout)
    plugin_ver = plugin_version()
    try:
        if mode == "hook-context":
            # The scanner can start before the readiness gate creates the state directory.
            os.makedirs(state_dir, mode=0o700, exist_ok=True)
            if _context_is_fresh(state_dir):
                return 0
        write_context(state_dir, agent_ver, plugin_ver)
    except (OSError, ValueError) as e:
        _LOG.error("write_context failed: %s", type(e).__name__)
    if mode == "auth":
        send_auth_event(state_dir, client, opts.get("cx", "cx"), agent_ver, plugin_ver,
                        opts.get("auth-method", ""))
    return 0


def send_auth_event(state_dir, client, cx_exe, agent_ver, plugin_ver, auth_method):
    """Send the authentication event; mark it sent only when cx reports success. Returns True on
    success. Records the credential-file mtime change cx makes while sending (see credential_mtime)."""
    if not telemetry_supported(cx_exe):
        return False
    before = _credential_file_mtime()
    code, _ = _run(auth_command(cx_exe, client, agent_ver, plugin_ver, auth_method), timeout=60)
    after = _credential_file_mtime()
    if before is not None and after is not None and after != before:
        try:
            _record_cred_alias(before, after)
        except (OSError, ValueError) as e:
            _LOG.error("recording the credential alias failed: %s", type(e).__name__)
    if code != 0:
        return False
    try:
        state = _read_state(state_dir)
        for key in ("pending_login", "pending_cred", "auth_method", "auth_inflight"):
            state.pop(key, None)
        state["auth_sent"] = True
        _write_state(state_dir, state)
    except (OSError, ValueError) as e:
        _LOG.error("marking the authentication event sent failed: %s", type(e).__name__)
    return True


if __name__ == "__main__":
    try:
        sys.exit(worker_main(sys.argv[1:]))
    except Exception as e:
        _LOG.error("telemetry worker failed: %s", type(e).__name__)
        sys.exit(0)
