"""Shared helper: enforces that the cx CLI is installed, recent enough, and authenticated
before any gated tool call runs. Fail-closed: if cx is missing, unrunnable, or below the
minimum version, every Bash/Write/Edit/mcp__* call is BLOCKED — even offline. The only
escape from the block is running the plugin's own bundled bootstrap (or an audited
CX_ALLOW_UNSCANNED=1)."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# Structured logging is OPTIONAL and must NEVER break the gate: a missing/broken cx_log, or any
# error inside it, is swallowed and the gate proceeds exactly as before.
try:
    import cx_log
except Exception:
    cx_log = None


def _log(event, **fields):
    """Emit a redacted structured event, dropping None-valued kwargs. Never raises."""
    if cx_log is None:
        return
    try:
        cx_log.log_event(event, **{k: v for k, v in fields.items() if v is not None})
    except Exception:
        pass


# Minimum cx version — a NUMERIC FLOOR only. The single source of truth is scripts/cx-min-version;
# this tuple is the fail-closed fallback used only when that file is missing or garbled. The floor
# is a fast pre-filter: capability is decided by the probe below (_capabilities_present), not by
# this number. Keep IDENTICAL to scripts/cx-min-version and scripts/cx-bootstrap.sh.
# (search marker: CX_MIN_VERSION)
_MIN_VERSION_FALLBACK = (2, 3, 54)

# The cx executable the GATE invokes for its own probes. CX_BINARY pins the gate to a specific
# cx by ABSOLUTE path (e.g. when several cx builds exist) instead of whatever PATH resolves; it
# must be an absolute path to an existing executable. A set-but-invalid value is reported as an
# error so the gate fails CLOSED rather than silently falling back to a different binary. Note:
# the native scanner (hooks.json) and the remediation MCP (.mcp.json) still run bare `cx` from
# PATH and do NOT honor CX_BINARY, so cx_check() additionally REQUIRES that PATH cx exists and
# resolves to the SAME file as CX_BINARY — otherwise the gate could pass while the scanner that
# actually blocks bad writes can't run (fail open). CX_BINARY is a pin, not a PATH replacement.
def _cx_binary():
    """Return (exe, error): exe is the validated CX_BINARY override, else 'cx' (PATH). error is
    a human string when CX_BINARY is set but invalid (not absolute / missing / not executable),
    else None."""
    override = os.environ.get("CX_BINARY")
    if not override:
        return "cx", None
    if not os.path.isabs(override):
        return None, "CX_BINARY must be an absolute path (got: {0})".format(override)
    if not os.path.isfile(override):
        return None, "CX_BINARY does not point to an existing file: {0}".format(override)
    if os.name != "nt" and not os.access(override, os.X_OK):
        return None, "CX_BINARY is not executable: {0}".format(override)
    return override, None


def _cx_exe():
    """The cx executable string for subprocess calls — the valid override or 'cx'. Lenient:
    strict validation + the fail-closed deny happen once in cx_check() via _cx_binary()."""
    exe, err = _cx_binary()
    return exe if err is None else "cx"


def _same_file(a, b):
    """True iff a and b are the SAME on-disk file (st_dev/st_ino on POSIX, file id on Windows),
    resolving symlinks/hardlinks and path-spelling differences. Both must exist; any error →
    False, so an indeterminate comparison is treated fail-CLOSED (a mismatch)."""
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


# Keep auth validation fast: no retries, short network timeout. Built per call so it honors a
# CX_BINARY override.
def _auth_validate_cmd():
    return [_cx_exe(), "auth", "validate", "--retry", "0", "--timeout", "5s"]

def _chmod_600(path):
    """Best-effort 0600 on a per-user state file. POSIX only — on Windows the file already
    sits under the user's profile (NTFS ACLs restrict it); never raise on failure."""
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _agent_log_dir():
    """Per-user directory for the gate's caches and bypass audit (and, later, structured
    logs). Default ~/.checkmarx/agent-logs/claude/ — a user-owned 0700 dir, so these
    predictable filenames can't be pre-planted by another local user the way world-writable
    OS-temp files could. CX_LOG_DIR overrides the location. Falls back to the OS temp dir
    only if the per-user dir can't be created, so caching/auditing degrade gracefully and
    this never raises into the gate."""
    override = os.environ.get("CX_LOG_DIR")
    target = override or os.path.join(
        os.path.expanduser("~"), ".checkmarx", "agent-logs", "claude"
    )
    try:
        os.makedirs(target, exist_ok=True)
        if os.name != "nt":
            os.chmod(target, 0o700)
        return target
    except OSError:
        # Do NOT fall back to the SHARED OS temp dir: another local user could pre-plant a
        # predictable cx_auth_cache / cx_version_cache there to spoof a cached pass. Use a freshly
        # created PRIVATE (0700) temp dir; if even that fails, return None and callers skip caching/
        # auditing entirely (correctness over caching — the gate itself still runs fail-closed).
        try:
            return tempfile.mkdtemp(prefix="cx-agent-logs-")
        except OSError:
            return None


_AGENT_LOG_DIR = _agent_log_dir()


def _state_path(name):
    """Absolute path to a per-user state file under _AGENT_LOG_DIR, or None when no private dir is
    available — callers then skip caching/auditing rather than touch a world-writable location."""
    return os.path.join(_AGENT_LOG_DIR, name) if _AGENT_LOG_DIR else None


# Per-user state lives under _AGENT_LOG_DIR (default ~/.checkmarx/agent-logs/claude, 0700),
# NOT the world-writable OS temp dir, so these predictable filenames can't be pre-planted.
# Each may be None if no private state dir could be created (then caching/auditing is skipped).
_AUTH_CACHE_FILE = _state_path("cx_auth_cache")
_AUTH_CACHE_TTL = 30 * 60  # 30 minutes

# Version probe is cached the same way as auth: spawning `cx version` on every gated tool
# call is wasteful. The bootstrap deletes this file after install/upgrade so the next hook
# fire re-probes immediately.
_VERSION_CACHE_FILE = _state_path("cx_version_cache")
_VERSION_CACHE_TTL = 30 * 60  # 30 minutes

# Audit log for CX_ALLOW_UNSCANNED escapes — a durable record that scanning was bypassed.
_UNSCANNED_AUDIT_FILE = _state_path("cx_unscanned_audit.log")

# Credential-recovery commands must be allowed even when unauthenticated — otherwise
# the auth gate blocks the very command that fixes auth (a chicken-and-egg that forces
# users to fall back to the shell `!` prefix). Matches a bare `cx auth ...` /
# `cx configure ...` invocation; redirects (e.g. `1>/dev/null`) are fine, but chaining /
# substitution metacharacters disqualify it so a benign prefix can't smuggle another
# command past the gate.
_AUTH_RECOVERY_RE = re.compile(r"^\s*cx\s+(?:auth|configure)\b")
_SHELL_CHAINING = (";", "|", "&", "`", "$(", "\n")

# A bare `bash "<bootstrap>" <install|upgrade>` invocation — the ONLY command allowed to run
# while the gate is blocking, because it's how the missing/outdated cx gets fixed. The mode is
# REQUIRED (a bare `bash "<bootstrap>"` is not a sanctioned action); the path is validated
# separately (must resolve to the plugin's own bootstrap); the regex pins the shape so no extra
# arguments or a `-c` payload can ride along.
_BOOTSTRAP_RE = re.compile(r'^\s*bash\s+"?(?P<path>[^"]+?)"?\s+(?:install|upgrade)\s*$')


def _normalize_path(p):
    """Normalize for cross-format comparison: absolute, real-cased on Windows, forward
    slashes. Lets a path the agent typed (possibly with the Windows `\\` cx_check.py's
    __file__ produced) compare equal to the resolved bootstrap path."""
    try:
        p = os.path.abspath(os.path.normpath(p))
    except (OSError, ValueError):
        return None
    if os.name == "nt":
        p = p.casefold()
    return p.replace("\\", "/")


def _bootstrap_script_path():
    """Resolved absolute path to scripts/cx-bootstrap.sh, relative to this file."""
    return os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "cx-bootstrap.sh")
    )


def _bootstrap_command_str(mode):
    """The exact command the agent should run to escape the block — embedded in deny
    messages so the agent doesn't need ${CLAUDE_PLUGIN_ROOT} (which is empty in its shell)."""
    return 'bash "{0}" {1}'.format(_bootstrap_script_path(), mode)


def _load_min_version(path=None):
    """Read scripts/cx-min-version (first non-comment, non-empty line). Fail CLOSED to the
    hardcoded fallback if missing/garbled/undecodable — never to (0,0,0)/allow. `path` is an
    injection point for tests; production callers pass nothing."""
    if path is None:
        path = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "cx-min-version")
        )
    # encoding="utf-8" (not the locale default): under LANG=C/POSIX a non-ASCII byte in this file
    # would raise UnicodeDecodeError on read — NOT an OSError — and, uncaught, exit 1 = FAIL OPEN.
    # Decode failures fall CLOSED to _MIN_VERSION_FALLBACK instead.
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = _parse_semver(line)
                if parsed is not None:
                    return parsed
                break  # first value line was garbage — fall closed
    except (OSError, UnicodeDecodeError):
        pass
    return _MIN_VERSION_FALLBACK


def _parse_semver(text):
    """Extract the first MAJOR.MINOR.PATCH from arbitrary text → (int, int, int) or None."""
    if not isinstance(text, str):
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _cx_version():
    """Run `cx version` and return its combined output, or None if cx can't run at all."""
    try:
        # NB: stdout=/stderr=PIPE (not capture_output=) — capture_output is Python 3.7+, but
        # cx_check.sh admits any Python 3; on 3.6 (RHEL 8 / Ubuntu 18.04) capture_output raises
        # TypeError, which — uncaught — would exit 1 and FAIL OPEN. PIPE works since 3.5.
        result = subprocess.run(
            [_cx_exe(), "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, TypeError):
        return None
    out = (result.stdout or b"") + b" " + (result.stderr or b"")
    return out.decode("utf-8", "replace")


# The numeric version is only a fast pre-filter: a build can satisfy the minimum version
# yet still LACK the agent-security subcommands (a PUBLIC min-version build predates
# `cx mcp bridge` / `cx hooks claude-*`). The real gate is whether those subcommands exist,
# so probe them with --help (local, no network). All must exit 0 to count as capable.
# Probe EVERY cx subcommand the hooks.json wiring actually invokes (the MCP bridge + all four
# claude-* hook subcommands), not just two — otherwise a partial build that has pre-tool-use but
# lacks e.g. claude-pre-file-write passes the gate, then the Write/Edit native scanner exits 1
# (non-blocking) and the write goes UNSCANNED.
_CAPABILITY_PROBES = (
    ("mcp", "bridge", "--help"),
    ("hooks", "claude-pre-tool-use", "--help"),
    ("hooks", "claude-pre-file-write", "--help"),
    ("hooks", "claude-stop", "--help"),
)


def _capabilities_present():
    """True iff every required cx subcommand responds to --help with exit 0. Any non-zero
    exit, missing subcommand, timeout, or spawn error → False (fail-closed). Each probe is
    `--help` only — purely local, no network — so a tight 3s timeout is ample; keeping it
    tight bounds the gate's worst-case latency under the hooks.json hook timeout."""
    exe = _cx_exe()
    for probe in _CAPABILITY_PROBES:
        try:
            result = subprocess.run(
                [exe, *probe], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError, TypeError):
            return False
        if result.returncode != 0:
            return False
    return True


def _version_state_uncached():
    """Classify the installed cx: 'ok' | 'below' | 'incapable' | 'dev' | 'unrunnable'.
    Parse a real semver first; a build that reports a bare `dev` sentinel (internal builds)
    bypasses the numeric gate; anything else (cx won't run / no parseable version) is
    'unrunnable'. A build that clears the numeric/dev pre-filter but is MISSING the required
    subcommands (`cx mcp bridge` / `cx hooks claude-*`) is 'incapable' — the real gate, since
    a numeric version match alone does not guarantee the scanner/MCP exist."""
    output = _cx_version()
    if output is None:
        return "unrunnable"
    parsed = _parse_semver(output)
    if parsed is not None:
        if parsed < _load_min_version():
            return "below"
        numeric = "ok"
    elif re.search(r"\bdev\b", output, re.IGNORECASE):
        numeric = "dev"
    else:
        return "unrunnable"
    if not _capabilities_present():
        return "incapable"
    return numeric


def _binary_identity():
    """(resolved cx path, mtime) — the identity used to invalidate cached gate state (version AND
    auth) when the binary changes. Best-effort: an unresolvable binary yields a None mtime, which
    differs from any real cached value and triggers a safe re-probe."""
    exe = _cx_exe()
    resolved = exe if os.path.isabs(exe) else (shutil.which(exe) or exe)
    try:
        mtime = os.path.getmtime(resolved)
    except OSError:
        mtime = None
    return resolved, mtime


def _version_cache_key(identity=None):
    """Identity of the inputs that determine the version state: the RESOLVED cx binary, its
    mtime, and the configured minimum version. A cached 'ok'/'dev' is only reusable while all
    three are unchanged — otherwise it is stale (e.g. PATH cx was swapped for an older/incapable
    build, or cx was upgraded in place, or cx-min-version changed) and must be re-probed even
    inside the TTL. `identity` lets the caller pass ONE binary-identity snapshot (taken once per
    gate invocation) so the version/auth/scanner caches all key off the same (path, mtime)."""
    cx, mtime = identity if identity is not None else _binary_identity()
    return {"cx": cx, "mtime": mtime, "min": ".".join(str(n) for n in _load_min_version())}


def _version_state(identity=None):
    """Cached _version_state_uncached(): reuse a fresh result to avoid spawning cx on every
    gated call. Only 'ok'/'dev' are cached (a passing state is stable); failing states are
    re-checked every time so a just-completed install/upgrade is picked up instantly even if the
    bootstrap didn't clear the cache. The cache is KEYED to _version_cache_key() (resolved binary
    + mtime + min-version), so a different/updated cx within the TTL re-probes instead of riding a
    stale 'ok' = fail open."""
    key = _version_cache_key(identity)
    try:
        if _VERSION_CACHE_FILE and (time.time() - os.path.getmtime(_VERSION_CACHE_FILE)) < _VERSION_CACHE_TTL:
            with open(_VERSION_CACHE_FILE, encoding="utf-8") as f:
                cached = json.loads(f.read())
            if (isinstance(cached, dict) and cached.get("state") in ("ok", "dev")
                    and cached.get("cx") == key["cx"]
                    and cached.get("mtime") == key["mtime"]
                    and cached.get("min") == key["min"]):
                return cached["state"]
    except (OSError, ValueError, TypeError):
        pass
    state = _version_state_uncached()
    if state in ("ok", "dev") and _VERSION_CACHE_FILE:
        try:
            record = {"state": state}
            record.update(key)
            with open(_VERSION_CACHE_FILE, "w", encoding="utf-8") as f:
                f.write(json.dumps(record))
            _chmod_600(_VERSION_CACHE_FILE)
        except OSError:
            pass
    return state


def _auth_cache_valid(identity=None):
    """A cached auth pass is reusable only while fresh AND for the SAME resolved cx binary — a
    swapped/replaced binary (potentially different credentials) must re-validate. None path (no
    private state dir) → never cached. `identity` lets the caller pass ONE binary-identity snapshot
    (taken once per gate invocation) so a mid-invocation binary swap can't poison the cache."""
    if not _AUTH_CACHE_FILE:
        return False
    try:
        with open(_AUTH_CACHE_FILE, encoding="utf-8") as f:
            cached = json.loads(f.read())
    except (OSError, ValueError, TypeError):
        return False
    if not isinstance(cached, dict):
        return False
    cx, mtime = identity if identity is not None else _binary_identity()
    if cached.get("cx") != cx or cached.get("mtime") != mtime:
        return False
    ts = cached.get("ts")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return False
    return (time.time() - ts) < _AUTH_CACHE_TTL


def _write_auth_cache(identity=None):
    if not _AUTH_CACHE_FILE:
        return
    cx, mtime = identity if identity is not None else _binary_identity()
    try:
        with open(_AUTH_CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "cx": cx, "mtime": mtime}))
        _chmod_600(_AUTH_CACHE_FILE)
    except OSError:
        pass


def _is_authenticated(identity=None):
    """Return True if cx can reach and authenticate with Checkmarx One. NOTE: this is the GATE's
    notion of authenticated (`cx auth validate`), which accepts an OAuth refresh token. It is NOT
    sufficient on its own — the native scanner authenticates differently (see _scanner_state)."""
    if _auth_cache_valid(identity):
        return True
    try:
        result = subprocess.run(
            _auth_validate_cmd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=6,
        )
        if result.returncode == 0:
            _write_auth_cache(identity)
            return True
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, TypeError):
        return False


# --- Scanner readiness: detect the native scanner's SILENT pass-through (the OAuth fail-open) -------
# The gate's auth check (`cx auth validate`, _is_authenticated) and the native scanner's auth are
# DIFFERENT notions. `cx auth validate` accepts an OAuth refresh token (from `cx auth login`); but
# `cx hooks claude-*` authenticates ONLY by extracting a Checkmarx API key, and when it cannot it
# runs in SILENT PASS-THROUGH — returning permissionDecision:allow for every file write / command
# WITHOUT scanning (a textbook command-injection file slips straight through). So a
# "validate-OK but scanner-pass-through" state is a silent fail-OPEN, and it is exactly what an OAuth
# login produces. cx exposes NO --strict/--require-auth/--fail-closed flag to force the scanner
# closed, so the only available signal is the scanner's own --debug stderr marker below. (cx-side
# dependency: `cx hooks` should fail CLOSED when unauthenticated AND accept the same OAuth credential
# `cx auth validate` already accepts; until then the agent-hooks scanner requires an API key.)
_SCANNER_SCAN = "scan"                # scanner is authenticated → it will actually scan
_SCANNER_PASSTHROUGH = "passthrough"  # scanner is unauthenticated → silent allow-everything, NO scan
_SCANNER_UNKNOWN = "unknown"          # probe inconclusive (spawn error / timeout) → defer to stage 2
_SCANNER_PASSTHROUGH_MARKER = "pass-through mode (not authenticated)"
_SCANNER_PROBE_TIMEOUT = 8

_SCANNER_CACHE_FILE = _state_path("cx_scanner_cache")
_SCANNER_CACHE_TTL = 30 * 60  # 30 minutes


def _credential_mtime():
    """Best-effort mtime of the cx credential file (~/.checkmarx/checkmarxcli.yaml). Folded into the
    scanner-cache key so switching the stored credential (e.g. OAuth token → API key) within the TTL
    invalidates a cached 'will-scan' pass and forces a re-probe. None on any error (then the cache
    keys on binary identity alone)."""
    try:
        return os.path.getmtime(
            os.path.join(os.path.expanduser("~"), ".checkmarx", "checkmarxcli.yaml"))
    except OSError:
        return None


def _probe_scanner_passthrough():
    """Run `cx hooks claude-pre-file-write --debug` on a BENIGN in-memory payload and inspect stderr.
    A PreToolUse hook only INSPECTS the proposed content — it never writes the file — and benign
    content yields no finding even when the scanner does run, so the probe has no side effect and
    never blocks on a real vuln. Returns _SCANNER_PASSTHROUGH when the scanner reports it is
    unauthenticated, _SCANNER_SCAN when it ran without that marker, _SCANNER_UNKNOWN on any spawn
    error/timeout. Never raises."""
    probe_path = _state_path("cx_scanner_probe.txt") or os.path.join(
        tempfile.gettempdir(), "cx_scanner_probe.txt")
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": probe_path, "content": "x"},
    }).encode("utf-8")
    try:
        result = subprocess.run(
            [_cx_exe(), "hooks", "claude-pre-file-write", "--debug"],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_SCANNER_PROBE_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, TypeError, ValueError):
        return _SCANNER_UNKNOWN
    stderr = (result.stderr or b"").decode("utf-8", "replace")
    if _SCANNER_PASSTHROUGH_MARKER in stderr:
        return _SCANNER_PASSTHROUGH
    return _SCANNER_SCAN


def _scanner_cache_valid(identity=None):
    """A cached scanner-WILL-SCAN pass is reusable only while fresh AND for the SAME resolved cx
    binary AND the SAME credential file. ONLY a positive (scan) result is ever cached — a
    pass-through is NEVER cached, so it can never be masked. None path (no private state dir) →
    never cached (mirrors the auth/version None-guard: a read-only home just re-probes)."""
    if not _SCANNER_CACHE_FILE:
        return False
    try:
        with open(_SCANNER_CACHE_FILE, encoding="utf-8") as f:
            cached = json.loads(f.read())
    except (OSError, ValueError, TypeError):
        return False
    if not isinstance(cached, dict):
        return False
    cx, mtime = identity if identity is not None else _binary_identity()
    if cached.get("cx") != cx or cached.get("mtime") != mtime:
        return False
    if cached.get("cred") != _credential_mtime():
        return False
    ts = cached.get("ts")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return False
    return (time.time() - ts) < _SCANNER_CACHE_TTL


def _write_scanner_cache(identity=None):
    if not _SCANNER_CACHE_FILE:
        return
    cx, mtime = identity if identity is not None else _binary_identity()
    try:
        with open(_SCANNER_CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.time(), "cx": cx, "mtime": mtime, "cred": _credential_mtime()}))
        _chmod_600(_SCANNER_CACHE_FILE)
    except OSError:
        pass


def _scanner_state(identity=None):
    """Cached scanner readiness: _SCANNER_SCAN (cached on success), _SCANNER_PASSTHROUGH, or
    _SCANNER_UNKNOWN. Only the positive scan result is cached; pass-through/unknown always re-probe
    so a credential fix (or break) is reflected on the next gated call."""
    if _scanner_cache_valid(identity):
        return _SCANNER_SCAN
    state = _probe_scanner_passthrough()
    if state == _SCANNER_SCAN:
        _write_scanner_cache(identity)
    return state


def _deny(reason: str, context: str, *, reason_code=None, tool_name=None, version_state=None) -> None:
    _log("gate_decision", decision="deny", reason_code=reason_code, tool_name=tool_name,
         version_state=version_state, exit_code=2)
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
            "additionalContext": context,
        }
    }
    print(json.dumps(output))
    sys.exit(2)


def _allow_with_warning(context: str, *, reason_code=None, tool_name=None) -> None:
    _log("gate_decision", decision="allow", reason_code=reason_code, tool_name=tool_name, exit_code=0)
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "additionalContext": context,
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def _read_hook_input():
    """Parse the PreToolUse JSON Claude Code sends on stdin. Returns {} on any problem
    (no stdin / empty / non-JSON) so the normal gate still runs."""
    try:
        if sys.stdin.isatty():
            return {}
        raw = sys.stdin.read()
    except Exception:
        return {}
    if not raw or not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _bash_command(hook_input):
    """The command string of a Bash tool call, or '' if this isn't a Bash call."""
    if hook_input.get("tool_name") != "Bash":
        return ""
    tool_input = hook_input.get("tool_input")
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
    return command if isinstance(command, str) else ""


def _is_auth_recovery_command(hook_input):
    """True only for a bare `cx auth ...` / `cx configure ...` Bash command with no
    command chaining — the credential-recovery path that must run even when
    unauthenticated, so the auth gate never blocks the command that fixes auth."""
    command = _bash_command(hook_input)
    if not command or not _AUTH_RECOVERY_RE.match(command):
        return False
    return not any(tok in command for tok in _SHELL_CHAINING)


def _is_bootstrap_command(hook_input):
    """True only for a bare `bash "<bootstrap>" <install|upgrade>` Bash command where <bootstrap>
    resolves to THIS plugin's own scripts/cx-bootstrap.sh — the single escape hatch from the
    fail-closed block. Independent defenses: Bash-only, no shell chaining, a REQUIRED install/
    upgrade mode (shape), and a path that must equal the bundled bootstrap. The literal
    ${CLAUDE_PLUGIN_ROOT} placeholder (which the agent's shell does NOT expand) is honored only
    after expanding it from the gate's own environment and proving it resolves to the bundled
    bootstrap — never blessed blindly."""
    command = _bash_command(hook_input)
    if not command:
        return False
    if any(tok in command for tok in _SHELL_CHAINING):
        return False
    m = _BOOTSTRAP_RE.match(command)
    if not m:
        return False
    raw_path = m.group("path").strip()
    if raw_path == "${CLAUDE_PLUGIN_ROOT}/scripts/cx-bootstrap.sh":
        # Claude Code sets CLAUDE_PLUGIN_ROOT in the hook (gate) environment; an unset or foreign
        # value cannot be proven to be the bundled bootstrap → fail CLOSED.
        root = os.environ.get("CLAUDE_PLUGIN_ROOT")
        if not root:
            return False
        raw_path = os.path.join(root, "scripts", "cx-bootstrap.sh")
    candidate = _normalize_path(raw_path)
    expected = _normalize_path(_bootstrap_script_path())
    return candidate is not None and candidate == expected


def cx_check():
    hook_input = _read_hook_input()
    tool = hook_input.get("tool_name")

    # 1. The bootstrap is the ONLY way out of the block — must be checked first.
    if _is_bootstrap_command(hook_input):
        _log("gate_decision", decision="allow", reason_code="bootstrap", tool_name=tool)
        return

    # 2. Audited manual override. Loud, durable, and explicitly opt-in.
    if os.environ.get("CX_ALLOW_UNSCANNED") == "1":
        audit = "CX_ALLOW_UNSCANNED=1 bypassed scanning for tool={0} at {1}".format(
            tool or "<unknown>", time.time())
        print("WARNING: " + audit, file=sys.stderr)
        # The bypass is permitted ONLY if it can be DURABLY AUDITED. If the audit record cannot be
        # written (no writable state dir, etc.), refuse it — an UNAUDITED unscanned run would defeat
        # the escape hatch's only safeguard. Fail CLOSED.
        try:
            if not _UNSCANNED_AUDIT_FILE:
                raise OSError("no audit-log location available")
            with open(_UNSCANNED_AUDIT_FILE, "a", newline="\n") as f:
                f.write(audit + "\n")
            _chmod_600(_UNSCANNED_AUDIT_FILE)
        except (OSError, TypeError) as exc:
            _deny(
                reason=(
                    "CX_ALLOW_UNSCANNED=1 was set, but the unscanned-bypass AUDIT record could not "
                    "be written — an unaudited bypass is refused, so this operation is BLOCKED."
                ),
                context=(
                    "The CX_ALLOW_UNSCANNED escape hatch requires a durable audit record and that "
                    "write failed ({0}). Make the agent-log directory writable (set CX_LOG_DIR to a "
                    "writable path) or unset CX_ALLOW_UNSCANNED. All agent actions remain blocked "
                    "fail-closed.".format(exc)
                ),
                reason_code="unscanned_audit_failed",
                tool_name=tool,
            )
        _log("unscanned_override", tool_name=tool)
        _allow_with_warning(
            context=(
                "WARNING: scanning was BYPASSED via CX_ALLOW_UNSCANNED=1. This operation ran "
                "UNSCANNED and was recorded to the audit log. Unset CX_ALLOW_UNSCANNED to "
                "restore enforcement."
            ),
            reason_code="unscanned_override",
            tool_name=tool,
        )

    # 2.5 CX_BINARY override: validate before trusting it. A set-but-invalid value fails CLOSED
    #     (never silently use a different binary). When valid, every gate probe below uses it,
    #     and the version/capability/auth gates then prove it's a real, recent, capable, authed cx.
    cx_path, cx_err = _cx_binary()
    if cx_err is not None:
        _deny(
            reason=(
                "The Checkmarx CLI override CX_BINARY is set but invalid, so the security gate "
                "cannot run. This operation is BLOCKED until CX_BINARY is fixed or unset."
            ),
            context=(
                cx_err + ". Set CX_BINARY to the ABSOLUTE path of a real, executable cx binary, "
                "or unset it to use cx from PATH. All agent actions are blocked fail-closed."
            ),
            reason_code="cx_binary_invalid",
            tool_name=tool,
        )

    # 3. cx absent → block (even offline). No network-reachability allow path.
    #    The native scanner (hooks.json: `cx hooks claude-*`) and the remediation MCP
    #    (.mcp.json: `cx mcp bridge`) ALWAYS run bare `cx` resolved from PATH — they do NOT
    #    honor CX_BINARY. So the cx the gate proves recent/capable/authed must be the cx ON
    #    PATH, or the gate fails OPEN: it could bless an off-PATH CX_BINARY and pass while the
    #    PATH-resolved scanner (absent, older, or incapable) exits non-blocking and the action
    #    runs UNSCANNED. Therefore PATH cx must exist regardless of CX_BINARY, and when CX_BINARY
    #    is set it must point at the SAME file as PATH cx.
    path_cx = shutil.which("cx")
    if path_cx is None:
        if cx_path != "cx":
            _deny(
                reason=(
                    "The Checkmarx CLI override CX_BINARY is set, but `cx` is not on PATH. The "
                    "native security scanner and the remediation MCP run `cx` from PATH, so cx "
                    "must be installed on PATH too — CX_BINARY alone is not enough. This operation "
                    "is BLOCKED."
                ),
                context=(
                    "CX_BINARY validated, but `cx` is not resolvable on PATH. hooks.json runs "
                    "`cx hooks claude-*` and .mcp.json runs `cx mcp bridge`, both via PATH — so a "
                    "gate that trusted only CX_BINARY would pass while the scanner could not run "
                    "(fail open). Put the SAME cx on PATH (or unset CX_BINARY and install cx "
                    "normally), then retry. All agent actions are blocked fail-closed. To "
                    "self-install now, run the plugin's bundled bootstrap by its resolved absolute "
                    "path:\n    " + _bootstrap_command_str("install")
                ),
                reason_code="cx_binary_not_on_path",
                tool_name=tool,
            )
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is not installed. Security scanning cannot run, so this "
                "operation is BLOCKED. Run /cx-cli-setup to install and authenticate it, then retry."
            ),
            context=(
                "cx CLI is not installed on this machine. All agent actions are blocked fail-closed "
                "until it is installed and authenticated. IMMEDIATELY invoke the cx-cli-setup skill "
                "(via /cx-cli-setup). To self-install now, run the plugin's bundled bootstrap by its "
                "resolved absolute path (its directory is empty in ${CLAUDE_PLUGIN_ROOT} in your "
                "shell, so use this literal command):\n    " + _bootstrap_command_str("install")
            ),
            reason_code="cx_absent",
            tool_name=tool,
        )
    if cx_path != "cx" and not _same_file(path_cx, cx_path):
        _deny(
            reason=(
                "The Checkmarx CLI override CX_BINARY points to a DIFFERENT cx than the one on "
                "PATH. The native scanner and MCP run cx from PATH, so the gate cannot vouch for a "
                "different binary. This operation is BLOCKED until they are the same cx."
            ),
            context=(
                "CX_BINARY ({0}) and the cx on PATH ({1}) are not the same file. The gate validates "
                "CX_BINARY, but hooks.json / .mcp.json invoke PATH cx — a mismatch could let an "
                "unvalidated (older / incapable) scanner run = fail open. Point CX_BINARY at the "
                "same cx that is on PATH, or unset it. All agent actions are blocked "
                "fail-closed.".format(cx_path, path_cx)
            ),
            reason_code="cx_binary_mismatch",
            tool_name=tool,
        )

    # Snapshot the cx binary identity ONCE so the auth and scanner-readiness caches key off the
    # SAME (path, mtime): an atomic cx replace mid-invocation can't poison one cache with another
    # binary's identity (which could let a stale 'authenticated'/'will-scan' ride a swapped cx).
    identity = _binary_identity()

    # 4. Version gate — BEFORE auth-recovery, so a below-min cx can't sneak through via
    #    `cx auth login`. A below-min build lacks `cx mcp bridge` / `cx auth login`.
    state = _version_state(identity)
    if state == "below":
        min_ver = ".".join(str(n) for n in _load_min_version())
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is older than the required v{0} and cannot run the scanner "
                "or the remediation MCP. This operation is BLOCKED until cx is upgraded.".format(min_ver)
            ),
            context=(
                "cx is below the minimum supported version (v{0}). All agent actions are blocked "
                "fail-closed — including `cx auth login`, which this old build may not support — until "
                "cx is upgraded. Invoke /cx-cli-setup (Phase 1b — Upgrade). To self-upgrade now, run "
                "the plugin's bundled bootstrap by its resolved absolute path:\n    {1}".format(
                    min_ver, _bootstrap_command_str("upgrade")
                )
            ),
            reason_code="below_min",
            tool_name=tool,
            version_state="below",
        )
    if state == "unrunnable":
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is on PATH but `cx version` did not run or did not report a "
                "usable version. Scanning cannot be confirmed, so this operation is BLOCKED."
            ),
            context=(
                "`cx version` failed or returned no parseable version (corrupt install, wrong binary, "
                "or a hung process). All agent actions are blocked fail-closed. Invoke /cx-cli-setup. "
                "To reinstall now, run the plugin's bundled bootstrap by its resolved absolute path:\n    "
                + _bootstrap_command_str("install")
            ),
            reason_code="unrunnable",
            tool_name=tool,
            version_state="unrunnable",
        )
    if state == "incapable":
        min_ver = ".".join(str(n) for n in _load_min_version())
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is installed but MISSING the security-scanner subcommands "
                "(cx mcp bridge / cx hooks claude-*). This build cannot run the gate or the "
                "remediation MCP, so this operation is BLOCKED until cx is upgraded to a build that "
                "includes them."
            ),
            context=(
                "cx ran `cx version` but one or more of the `cx mcp bridge` / `cx hooks claude-*` "
                "--help probes failed — this build predates (some of) the agent-security hooks "
                "(capability_missing). A numeric version match is NOT sufficient. All agent actions "
                "are blocked fail-closed until cx is upgraded to a capable build (>= v{0} WITH the "
                "agent-hooks subcommands). Invoke /cx-cli-setup (Upgrade). To self-upgrade now, run "
                "the plugin's bundled bootstrap by its resolved absolute path:\n    {1}".format(
                    min_ver, _bootstrap_command_str("upgrade")
                )
            ),
            reason_code="capability_missing",
            tool_name=tool,
            version_state="incapable",
        )
    # state in ("ok", "dev") with required subcommands present → continue.

    # 5. Allow credential-recovery commands (cx auth / cx configure) through even when
    #    unauthenticated, so the auth gate never blocks the command that fixes auth.
    if _is_auth_recovery_command(hook_input):
        _log("gate_decision", decision="allow", reason_code="auth_recovery", tool_name=tool,
             version_state=state)
        return

    # 6. Authenticated? (the gate's notion: `cx auth validate`, which accepts an OAuth token.)
    if not _is_authenticated(identity):
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is installed but not authenticated. "
                "Run /cx-cli-setup to configure and authenticate, then retry."
            ),
            context=(
                "cx auth validate failed — the CLI could not reach Checkmarx One or credentials are "
                "expired/missing. You can FIX THIS YOURSELF: the gate allows credential-recovery "
                "commands (`cx auth …` / `cx configure …` / `cx auth validate`) through the Bash tool "
                "even while it blocks everything else — so run `cx auth login --base-auth-uri <url> "
                "--tenant <tenant>` (browser sign-in) or `cx configure set --prop-name cx_apikey "
                "--prop-value <key>` (API key) DIRECTLY; do NOT hand the command to the developer with "
                "the `!` prefix. `cx auth login` opens the browser automatically and blocks until login "
                "finishes (~5 min) — run it with a long timeout or in the background. Invoke the "
                "cx-cli-setup skill (/cx-cli-setup) for the guided flow. Only those credential-recovery "
                "commands run until authentication succeeds."
            ),
            reason_code="unauthenticated",
            tool_name=tool,
            version_state=state,
        )

    # 6b. Scanner readiness. `cx auth validate` (step 6) and the native scanner authenticate
    #     DIFFERENTLY: validate accepts an OAuth refresh token, but `cx hooks claude-*` only
    #     extracts an API key and otherwise runs in SILENT PASS-THROUGH (allow everything, NO scan).
    #     A validate-OK-but-scanner-pass-through state is therefore a silent fail-OPEN — exactly the
    #     gap an OAuth `cx auth login` opens. Treat it as NOT authenticated for scanning and fail
    #     CLOSED with the same visible /cx-cli-setup message. UNKNOWN (probe error/timeout) defers to
    #     the real stage-2 scanner — no worse than before — so a flaky probe can't over-block a
    #     genuinely-authenticated user. (Carve-outs in steps 1/2/5 already returned, so the bootstrap,
    #     CX_ALLOW_UNSCANNED, and `cx auth`/`cx configure` recovery commands never reach this probe.)
    if _scanner_state(identity) == _SCANNER_PASSTHROUGH:
        _deny(
            reason=(
                "The Checkmarx CLI authenticated, but its security SCANNER could not — it is running "
                "in pass-through (allow everything, NO scan) because it cannot establish an "
                "authenticated session from the current credential. This operation is BLOCKED."
            ),
            context=(
                "`cx auth validate` passed, but `cx hooks claude-pre-file-write` reports 'pass-through "
                "mode (not authenticated)' — the native scanner could not authenticate with the "
                "current stored credential (it may be stale or expired, or the backend was "
                "unreachable when it tried) and would silently allow everything UNSCANNED. IMMEDIATELY "
                "invoke the cx-cli-setup skill (via /cx-cli-setup) and RE-AUTHENTICATE — a fresh "
                "`cx auth login`, or set a valid API key: cx configure set --prop-name cx_apikey "
                "--prop-value <key>. Run these recovery commands YOURSELF via the Bash tool — the gate "
                "allows `cx auth …` / `cx configure …` through even while blocking, so do NOT hand them "
                "to the developer with the `!` prefix (`cx auth login` opens the browser automatically). "
                "Only those recovery commands run until the scanner itself is authenticated."
            ),
            reason_code="scanner_passthrough",
            tool_name=tool,
            version_state=state,
        )

    # cx is installed, recent enough, authenticated, and the scanner WILL actually scan.
    _log("gate_decision", decision="pass", reason_code="ok", tool_name=tool, version_state=state)


def _fail_closed_on_crash():
    """Last-resort deny printed if the gate itself crashes. A fail-CLOSED guard: an unexpected
    error inside cx_check() must BLOCK (exit 2), never exit 1 — Claude Code treats a non-2 exit
    as a non-blocking hook error, which would let the tool call through UNSCANNED (fail open)."""
    try:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "The Checkmarx security gate hit an internal error and could not evaluate this "
                    "action, so it is BLOCKED fail-closed."
                ),
                "additionalContext": (
                    "An unexpected error occurred inside cx_check.py. All agent actions remain "
                    "blocked until it is resolved. Re-run /cx-cli-setup, or set CX_ALLOW_UNSCANNED=1 "
                    "to bypass scanning (audited)."
                ),
            }
        }))
    except Exception:
        pass


def main():
    # _deny()/_allow_with_warning() raise SystemExit with the real allow(0)/deny(2) code — let it
    # propagate. ANY other exception is an internal gate failure → fail CLOSED (deny, exit 2),
    # never an uncaught traceback (exit 1, which Claude Code treats as non-blocking = fail OPEN).
    try:
        cx_check()
    except SystemExit:
        raise
    except BaseException:
        _fail_closed_on_crash()
        sys.exit(2)


if __name__ == "__main__":
    main()
