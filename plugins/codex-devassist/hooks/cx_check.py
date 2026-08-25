"""Shared helper: enforces that the cx CLI is installed, recent enough, and authenticated
before any gated tool call runs. Fail-closed: if cx is missing, unrunnable, or below the
minimum version, every Bash/Write/Edit/mcp__* call is BLOCKED — even offline. The only
escape from the block is running the plugin's own bundled bootstrap."""

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
_MIN_VERSION_FALLBACK = (2, 3, 58)

# The cx executable the GATE invokes for its own probes, resolved by ABSOLUTE path where possible so
# the gate works the instant cx is installed — even before it is on PATH. A freshly-installed cx in
# the canonical store is invisible to this frozen-PATH session (setx/shell-profile only affect
# FUTURE sessions), so relying on PATH alone would keep the gate blocked until a restart. Resolution
# precedence: CX_BINARY (explicit pin) -> the canonical per-OS store the bootstrap installs to -> PATH.
# The stage-2 scanner runs through hooks/cx_run.sh, which uses the SAME precedence, so whatever the
# gate validates (version/capability/auth) is exactly what scans — no PATH dependency, no fail-open.
# (The remediation MCP resolves cx the SAME way, via hooks/cx_run.sh, so it is not a bare-PATH
# consumer either; it activates after one /restart, no scan is bypassed.) CX_BINARY must be valid.
def _cx_binary():
    """Return (exe, error): exe is the validated CX_BINARY override, else 'cx'. error is a human
    string when CX_BINARY is set but invalid (not absolute / missing / not executable), else None."""
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


def _canonical_cx():
    """Absolute path of cx in the canonical per-OS store the bootstrap installs to, if it exists and
    is executable — else None. Windows: %LOCALAPPDATA%\\Checkmarx\\cx\\cx.exe ; Unix: ~/.checkmarx/bin/cx.
    Lets the gate resolve cx by absolute path without waiting for a PATH / new-session refresh."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local")
        p = os.path.join(base, "Checkmarx", "cx", "cx.exe")
    else:
        p = os.path.join(os.path.expanduser("~"), ".checkmarx", "bin", "cx")
    try:
        if os.path.isfile(p) and (os.name == "nt" or os.access(p, os.X_OK)):
            return p
    except OSError:
        return None
    return None


def _cx_exe_with_tier():
    """Same resolution as _cx_exe(), but also returns WHICH tier supplied it: 'binary' | 'canonical'
    | 'path'. Lets a below/incapable/unrunnable deny explain WHY re-running the upgrade bootstrap
    won't help when CX_BINARY is pinned to an old/unfit binary — the bootstrap only ever writes the
    canonical store, and CX_BINARY takes priority over it in every resolution (this gate's own, and
    cx_run.sh's for the MCP bridge), so upgrading the canonical store changes nothing observable."""
    exe, err = _cx_binary()
    if err is None and exe != "cx":
        return exe, "binary"
    canon = _canonical_cx()
    if canon:
        return canon, "canonical"
    return "cx", "path"


def _cx_exe():
    """The cx executable for subprocess calls, resolved by absolute path where possible:
    a valid CX_BINARY -> the canonical store -> 'cx' (PATH). Lenient: strict CX_BINARY validation +
    the fail-closed deny happen once in cx_check() via _cx_binary()."""
    exe, _tier = _cx_exe_with_tier()
    return exe


def _cx_binary_pin_note(tier):
    """An extra, explicit note to append to a below/incapable/unrunnable deny's context when the
    unfit binary came from a CX_BINARY pin (tier == 'binary') — empty string otherwise. Re-running
    the upgrade bootstrap does NOT fix this case: the bootstrap only ever writes the canonical
    store, which a CX_BINARY pin continues to shadow, so an agent could loop re-running the
    suggested upgrade command forever with no visible effect. Phrased as an instruction to the
    agent (mirrors the "Tell the developer …" pattern already used elsewhere in this file) so the
    note actually reaches the human instead of being silently absorbed."""
    if tier != "binary":
        return ""
    return (
        "\nNote: CX_BINARY is pinned to this exact binary and takes priority over the canonical "
        "store, so running the bootstrap (install OR upgrade mode) will NOT fix this — the "
        "bootstrap only ever writes the canonical store, which CX_BINARY continues to shadow. Tell "
        "the developer to do ONE of: unset CX_BINARY (so resolution falls through to the canonical "
        "store), replace the binary AT the CX_BINARY path directly, or run the bootstrap normally "
        "and then repoint CX_BINARY at the resulting canonical store path. Do not just re-run the "
        "bootstrap and expect it to take effect."
    )


# Single-shot auth validate. The gate's OWN retry lives in _auth_probe_with_grace — it retries only in
# the transient post-login window, which is smarter than cx's --retry (that covers network errors, not
# the "freshly-issued token not yet accepted" invalid we actually hit right after `cx auth login`).
# Keep this one attempt bounded and cheap so the grace retry + the scanner probe all fit the
# cx_check.sh 45s hook budget. Built per call so it honors a CX_BINARY override.
def _auth_validate_cmd():
    return [_cx_exe(), "auth", "validate", "--retry", "0", "--timeout", "10s"]

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
    logs). Default ~/.checkmarx/agent-logs/codex/ — a user-owned 0700 dir, so these
    predictable filenames can't be pre-planted by another local user the way world-writable
    OS-temp files could. CX_LOG_DIR overrides the location. Falls back to the OS temp dir
    only if the per-user dir can't be created, so caching/auditing degrade gracefully and
    this never raises into the gate."""
    override = os.environ.get("CX_LOG_DIR")
    target = override or os.path.join(
        os.path.expanduser("~"), ".checkmarx", "agent-logs", "codex"
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


# Credential-recovery commands must be allowed even when unauthenticated — otherwise
# the auth gate blocks the very command that fixes auth (a chicken-and-egg that forces
# users to fall back to the shell `!` prefix). Matches a bare `cx auth ...` /
# `cx configure ...` invocation. The shared _bare_bash_command guard then disqualifies chaining /
# substitution metacharacters AND any redirect to a real file (a null-sink `1>/dev/null` is fine) —
# so a benign prefix can neither smuggle another command nor exfiltrate the live token past the gate.
_AUTH_RECOVERY_RE = re.compile(r"^\s*cx\s+(?:auth|configure)\b")
_SHELL_CHAINING = (";", "|", "&", "`", "$(", "\n")

# A bare `bash "<bootstrap>" <install|upgrade>` invocation — the ONLY command allowed to run
# while the gate is blocking, because it's how the missing/outdated cx gets fixed. The mode is
# REQUIRED (a bare `bash "<bootstrap>"` is not a sanctioned action); the path is validated
# separately (must resolve to the plugin's own bootstrap); the regex pins the shape so no extra
# arguments or a `-c` payload can ride along.
_BOOTSTRAP_RE = re.compile(r'^\s*(?:bash|sh)\s+"?(?P<path>[^"]+?)"?\s+(?:install|upgrade)\s*$')

# Read-only Bash programs that cannot write code to disk or execute another program — safe to run
# WITHOUT the cx readiness/auth gate, so a plain `ls`/`cat` works during setup instead of being blocked
# with "cx not installed". Matched ONLY as a BARE command (via _bare_bash_command: no chaining /
# substitution / unsafe redirect) whose FIRST token equals one of these. Programs with a write or exec
# form are deliberately EXCLUDED — find (-exec/-delete), sed (-i), awk (system), sort (-o), tee, env /
# command / type / xargs (run others), git (push/commit/config …) — so this can never smuggle a write
# or a command. Bash-tool only (PowerShell stays fully gated). Disable with CX_GATE_ALL_COMMANDS=1.
_READONLY_COMMANDS = frozenset({
    "ls", "pwd", "cat", "head", "tail", "echo", "whoami", "id", "date", "hostname", "uname",
    "wc", "which", "stat", "file", "basename", "dirname", "realpath", "readlink", "tree",
    "df", "du", "ps", "grep", "rg", "cut", "uniq", "cmp", "cksum", "md5sum", "sha256sum",
})


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
    messages so the agent doesn't need ${PLUGIN_ROOT} (which is empty in its shell).
    Uses `sh` with forward slashes so it works on Windows (bash fails with backslash paths
    in WSL-less Git Bash contexts)."""
    path = _bootstrap_script_path().replace("\\", "/")
    return 'sh "{0}" {1}'.format(path, mode)


def _bootstrap_copilot_cli_instruction(mode):
    """Copilot CLI-specific bootstrap instruction embedded in deny messages.
    The agent must run the bootstrap command EXACTLY as shown — using `sh`, not a
    platform-native shell invocation — and with NO chaining (no `;`, `|`, `&&`, `2>&1`,
    `if(...)`, etc.) — because the hook's bootstrap carve-out rejects any command that
    contains shell-chaining tokens.
    On Windows the powershell tool accepts `sh "..." mode` directly via Git Bash's sh.exe.
    On macOS/Linux the bash tool runs it via the system sh. Both forms pass the carve-out."""
    cmd = _bootstrap_command_str(mode)
    shell_tool = "powershell" if os.name == "nt" else "bash"
    return (
        "To unblock, use the {0} tool to run this command EXACTLY as shown below "
        "(do NOT rewrite as a native shell invocation, do NOT add `2>&1`, `if(...)`, "
        "or any other chaining — the security hook only allows this exact bare form):\n    {1}".format(
            shell_tool, cmd
        )
    )


def _cx_bash_token():
    """The gate's resolved cx as a single Bash-safe token, for embedding in deny messages the agent
    runs in its OWN shell. On a first-install session cx sits in the canonical store but NOT on the
    frozen PATH, so a bare `cx` would exit 127 — emit the resolved ABSOLUTE path instead (forward
    slashes so Git-Bash doesn't treat backslashes as escapes; double-quoted so a path with spaces
    survives). Falls back to bare 'cx' when only PATH resolution is available (later sessions / manual
    install), so the guidance degrades cleanly with no regression."""
    exe = _cx_exe()
    if os.path.isabs(exe):
        return '"{0}"'.format(exe.replace("\\", "/"))
    return "cx"


def _cx_recovery_command_str(args):
    """A ready-to-run `cx auth …` / `cx configure …` recovery command using the gate's resolved cx
    (absolute path when cx isn't yet on PATH). In Copilot CLI mode on Windows the command uses the
    PowerShell `&` call operator and `1>$null` null-sink — both are needed for the gate's
    PowerShell auth-recovery carve-out to admit the command."""
    if _COPILOT_CLI_MODE and os.name == "nt":
        exe = _cx_exe()
        if os.path.isabs(exe):
            # PowerShell form: `& "abs/path/cx.exe" auth … 1>$null`
            path_token = '"{0}"'.format(exe.replace("\\", "/"))
            return "& {0} {1} 1>$null".format(path_token, args)
    return "{0} {1}".format(_cx_bash_token(), args)


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
# `cx mcp bridge` / `cx hooks codex-*`). The real gate is whether those subcommands exist,
# so probe them with --help (local, no network). All must exit 0 to count as capable.
# Probe EVERY cx subcommand this plugin's hooks.json wiring actually invokes (the MCP bridge +
# all codex-* hook subcommands) — otherwise a partial build that has pre-tool-use but lacks
# e.g. codex-pre-file-write passes the gate, then the apply_patch native scanner exits 1
# (non-blocking) and the write goes UNSCANNED.
_CAPABILITY_PROBES = (
    ("mcp", "bridge", "--help"),
    ("hooks", "codex-pre-tool-use", "--help"),
    ("hooks", "codex-pre-file-write", "--help"),
    ("hooks", "codex-stop", "--help"),
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


def _binary_identity(resolved=None):
    """(resolved cx path, mtime) — the identity used to invalidate cached gate state (version AND
    auth) when the binary changes. Pass an already-resolved path to skip re-running _cx_exe() +
    shutil.which() (the gate resolves once per call and threads it through). Best-effort: an
    unresolvable binary yields a None mtime, which differs from any real cached value → safe re-probe."""
    if resolved is None:
        exe = _cx_exe()
        resolved = exe if os.path.isabs(exe) else (shutil.which(exe) or exe)
    try:
        mtime = os.path.getmtime(resolved)
    except OSError:
        mtime = None
    return resolved, mtime


def _cached_probe(cache_file, ttl, key, probe, should_cache):
    """Memoize probe() to `cache_file` for `ttl` seconds, keyed on the dict `key` (the resolved-binary
    identity plus any extra invalidators — min version, credential mtime). A cached value is reused
    ONLY while every `key` field still matches and its timestamp is within `ttl`; and ONLY results for
    which should_cache(result) is True are ever written — so a failing/pass-through probe can never be
    masked (the fail-open a stale positive would cause). A falsy `cache_file` (no private state dir)
    disables caching — re-probe every call. Never raises: any I/O or decode error falls through to a
    live probe (fail-safe). This is the single home for the gate's version/auth/scanner caching."""
    if cache_file:
        try:
            with open(cache_file, encoding="utf-8") as f:
                cached = json.loads(f.read())
            ts = cached.get("ts") if isinstance(cached, dict) else None
            if (isinstance(cached, dict) and "value" in cached
                    and isinstance(ts, (int, float)) and not isinstance(ts, bool)
                    and (time.time() - ts) < ttl
                    and all(cached.get(k) == v for k, v in key.items())):
                return cached["value"]
        except (OSError, ValueError, TypeError):
            pass
    result = probe()
    if cache_file and should_cache(result):
        try:
            record = {"value": result, "ts": time.time()}
            record.update(key)
            with open(cache_file, "w", encoding="utf-8") as f:
                f.write(json.dumps(record))
            _chmod_600(cache_file)
        except OSError:
            pass
    return result


def _version_state(identity=None):
    """Cached _version_state_uncached(): reuse a fresh 'ok'/'dev' to avoid spawning cx on every gated
    call. Failing states are re-probed every time so a just-completed install/upgrade is picked up
    instantly. Keyed on the resolved binary (path + mtime) + the configured minimum version, so a
    different/updated cx or a changed floor re-probes instead of riding a stale 'ok' = fail open."""
    cx, mtime = identity if identity is not None else _binary_identity()
    key = {"cx": cx, "mtime": mtime, "min": ".".join(str(n) for n in _load_min_version())}
    return _cached_probe(_VERSION_CACHE_FILE, _VERSION_CACHE_TTL, key,
                         _version_state_uncached, lambda s: s in ("ok", "dev"))


def _auth_validate_probe():
    """True iff `cx auth validate` succeeds (the gate's notion of authenticated; accepts an OAuth
    refresh token). Never raises — any spawn/timeout error is a non-authenticated result."""
    try:
        # Outer kill just needs to exceed the single inner attempt (--timeout 10s) + spawn overhead.
        # The retry is one level up (_auth_probe_with_grace), so two full probes + the scanner probe
        # still fit the 45s cx_check.sh hook budget.
        result = subprocess.run(_auth_validate_cmd(), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=13)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, TypeError):
        return False


def _auth_probe_with_grace():
    """`cx auth validate`, with ONE short retry when the credential was JUST written (fresh login). A
    freshly-issued token has a brief window where validate returns invalid before the backend accepts
    it, so the gate can deny a genuinely-authenticated session right after login. cx's own --retry
    covers network errors, not this post-login invalid, so retry once after a short sleep — bounded to
    stay within the hook budget. Only True is ever cached, so a transient failure is never memoized."""
    if _auth_validate_probe():
        return True
    if _credential_is_fresh():
        time.sleep(3)
        return _auth_validate_probe()
    return False


def _is_authenticated(identity=None):
    """Return True if cx can reach and authenticate with Checkmarx One. Cached for the SAME resolved
    cx binary only — a swapped binary (possibly different credentials) re-validates. NOTE: this is the
    GATE's notion of authenticated; it is NOT sufficient on its own — the native scanner authenticates
    differently (see _scanner_state)."""
    cx, mtime = identity if identity is not None else _binary_identity()
    return _cached_probe(_AUTH_CACHE_FILE, _AUTH_CACHE_TTL, {"cx": cx, "mtime": mtime},
                         _auth_probe_with_grace, lambda ok: ok is True)


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
_SCANNER_UNLICENSED = "unlicensed"    # authenticated but NO AI-scan license → cx pass-through, NO scan
_SCANNER_PASSTHROUGH_MARKER = "pass-through mode (not authenticated)"  # legacy --debug fallback only
_SCANNER_UNLICENSED_MARKER = "pass-through mode (no AI feature license)"  # legacy --debug fallback only
# `cx hooks check-auth` does the same token exchange as auth validate, so give it comparable room on a
# slow/on-prem backend (a too-tight budget → UNKNOWN → defers, silently skipping the readiness check).

# --- Admin onboarding config (config/cx-onboarding.properties) -------------------------------------
# Official Checkmarx One doc that lists the regional environment base URLs and how to find your
# tenant. Surfaced in the OAuth recovery guidance so a developer can look up their region instead of
# guessing. The concrete region examples are ALSO embedded inline below, so the guidance is useful
# even without opening the page.
_CX_ENV_URLS_DOC = "https://docs.checkmarx.com/en/34965-68530-logging-in-to-checkmarx-one.html"

# STRICT validation for admin-supplied values. These get embedded into the `cx auth login` command
# the AGENT then runs, so the charset must exclude every shell-active and flag-smuggling character:
#   - tenant: must START alphanumeric (bans a leading '-' -> no `--proxy ...`/`--insecure` flag
#     smuggling), then only letters/digits/._- , max 64. No whitespace/quote/$/backtick by construction.
#   - base-auth-uri: https:// + host (+ optional :port) ONLY -- no path/query/userinfo/space, so it
#     cannot carry a second token or a redirect.
# Anything failing these is IGNORED (fall back to the <url>/<tenant> placeholders); a bad value is
# never emitted and never blocks -- this is a convenience, not a gate control (fail SOFT, not closed).
_ADMIN_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
_ADMIN_URL_RE = re.compile(r"^https://[A-Za-z0-9][A-Za-z0-9.\-]{0,127}(?::[0-9]{2,5})?$")
_ADMIN_CONFIG_MAX_BYTES = 8192
_ADMIN_CONFIG_VALIDATORS = {
    "cx_base_auth_uri": _ADMIN_URL_RE,
    "cx_tenant": _ADMIN_TENANT_RE,
}


def _admin_config_path():
    """Absolute path to the bundled admin onboarding config, relative to THIS file (hooks) --
    mirrors _bootstrap_script_path()/_load_min_version(); never uses ${PLUGIN_ROOT} (which is
    empty in the agent shell). Works on every OS via os.path.join."""
    return os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config",
                     "cx-onboarding.properties")
    )


def _load_admin_config(path=None):
    """Read config/cx-onboarding.properties and return ONLY the known, VALIDATED keys as a dict
    (possibly empty). FAIL SOFT: a missing/garbled/oversized/undecodable file, an invalid value, or
    any unexpected error yields {} (no pre-fill). This must NEVER raise -- an escaped exception would
    trip _fail_closed_on_crash and brick every tool call -- and NEVER block. `path` is a test hook."""
    if path is None:
        path = _admin_config_path()
    result = {}
    try:
        # utf-8-sig (not plain utf-8): an admin editing this file with Windows Notepad can prepend
        # a UTF-8 BOM, which would otherwise corrupt the first key name (cx_base_auth_uri ->
        # \ufeffcx_base_auth_uri -> silently dropped). utf-8-sig strips a leading BOM and is a no-op
        # when there isn't one.
        with open(path, "r", encoding="utf-8-sig") as f:
            raw = f.read(_ADMIN_CONFIG_MAX_BYTES + 1)
        if len(raw) <= _ADMIN_CONFIG_MAX_BYTES:
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _sep, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                validator = _ADMIN_CONFIG_VALIDATORS.get(key)
                if validator is None:
                    continue  # unknown key -- silently dropped
                if value and validator.match(value):
                    result[key] = value
                else:
                    _log("admin_config", result="invalid", key=key)
    except (OSError, UnicodeDecodeError, Exception):
        pass
    return result


def _oauth_recovery_bullet(cfg):
    """The 'Browser sign-in (OAuth)' bullet for an auth-recovery deny context, branched on whether the
    admin config supplied a VALIDATED base-auth-uri AND tenant. Both present -> embed the real values
    and tell the agent to use them as-is (skip the URL/tenant question). Otherwise -> the original
    ask-the-developer / never-guess guidance, now with the regional-URLs doc link. The embedded values
    are pre-validated to a shell-inert charset, so the resulting `"<cx>" auth login ...` command still
    passes _is_auth_recovery_command's bare-command guard."""
    base = cfg.get("cx_base_auth_uri")
    tenant = cfg.get("cx_tenant")
    if base and tenant:
        cmd = _cx_recovery_command_str(
            "auth login --base-auth-uri {0} --tenant {1}".format(base, tenant))
        return (
            "- Browser sign-in (OAuth) -- only if the developer picks this: you may run it yourself "
            "(it opens the developer's browser with MFA; no secret passes through you; it resolves cx "
            "by absolute path so it works before cx is on PATH). The --base-auth-uri and --tenant "
            "below were PRECONFIGURED BY YOUR ADMINISTRATOR (the plugin's "
            "config/cx-onboarding.properties) -- use them AS-IS and do NOT ask the developer for a URL "
            "or tenant:\n    " + cmd
        )
    cmd = _cx_recovery_command_str("auth login --base-auth-uri <url> --tenant <tenant>")
    return (
        "- Browser sign-in (OAuth) -- only if the developer picks this: you may run it yourself (it "
        "opens the developer's browser with MFA; no secret passes through you; it resolves cx by "
        "absolute path so it works before cx is on PATH). Only AFTER OAuth is chosen, ask for the "
        "URL/tenant -- NEVER guess or default the --base-auth-uri or --tenant values (e.g. do not try "
        "'iam.checkmarx.net' or a tenant of 'checkmarx') -- ask the developer, per the checkmarx-cli-setup "
        "skill's oauth.md Question 2. Regional URL examples: US https://ast.checkmarx.net, "
        "US2 https://us.ast.checkmarx.net, EU https://eu.ast.checkmarx.net, "
        "ANZ https://anz.ast.checkmarx.net, India https://ind.ast.checkmarx.net, or their on-prem "
        "URL. Full region list + how to find your tenant: " + _CX_ENV_URLS_DOC
        + "\n    " + cmd
    )


_SCANNER_PROBE_TIMEOUT = 12

# Exit codes emitted by `cx hooks check-auth` (the machine-readable readiness probe): 0 = ready
# (authenticated + AI-licensed → will scan), 1 = authenticated but unlicensed (valid user, no scan),
# 2 = not authenticated (silent pass-through — the state we fail CLOSED on).
_CHECK_AUTH_EXIT_READY = 0
_CHECK_AUTH_EXIT_UNLICENSED = 1
_CHECK_AUTH_EXIT_UNAUTHENTICATED = 2

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


def _credential_is_fresh(within_seconds=180):
    """True if the cx credential file was written within the last `within_seconds` — i.e. the user
    just ran `cx auth login` / `cx configure`. Drives (a) a grace-retry of a validate that fails in the
    brief post-login window before the backend accepts the freshly-issued token, and (b) a
    "wait, don't re-login" deny message instead of generic re-auth guidance."""
    mtime = _credential_mtime()
    if mtime is None:
        return False
    try:
        return (time.time() - mtime) < within_seconds
    except (TypeError, ValueError):
        return False


def _probe_scanner_passthrough():
    """Ask the cx CLI whether its scanner is authenticated via the machine-readable
    `cx hooks check-auth` probe (exit code + JSON on stdout) — no --debug log scraping. Maps
    not-authenticated → _SCANNER_PASSTHROUGH (block); authenticated-but-unlicensed → _SCANNER_UNLICENSED
    (block by default — cx runs the scanner in pass-through when unlicensed, so a write would be
    UNSCANNED); ready → _SCANNER_SCAN (allow); any spawn error/timeout → _SCANNER_UNKNOWN (defer to
    stage 2). Falls back to the legacy --debug stderr marker on an OLDER cx that predates `check-auth`
    — detected because the real command always emits a JSON object on stdout and the unknown-subcommand
    error does not. Never raises."""
    try:
        result = subprocess.run(
            [_cx_exe(), "hooks", "check-auth"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_SCANNER_PROBE_TIMEOUT,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, TypeError, ValueError):
        return _SCANNER_UNKNOWN
    # Feature-detect: the real command always prints a JSON object; an older cx that lacks the
    # subcommand prints a cobra "unknown command" error and no JSON, so a parse failure (or a
    # payload without scannerReady) means "old cx" → fall back to the legacy stderr-marker probe.
    try:
        payload = json.loads((result.stdout or b"").decode("utf-8", "replace").strip())
    except (ValueError, TypeError):
        return _legacy_probe_scanner_passthrough()
    if not isinstance(payload, dict) or "scannerReady" not in payload:
        return _legacy_probe_scanner_passthrough()
    if result.returncode == _CHECK_AUTH_EXIT_UNAUTHENTICATED or payload.get("authenticated") is False:
        return _SCANNER_PASSTHROUGH
    if result.returncode == _CHECK_AUTH_EXIT_UNLICENSED or payload.get("licensed") is False:
        return _SCANNER_UNLICENSED
    if payload.get("scannerReady") is True or result.returncode == _CHECK_AUTH_EXIT_READY:
        return _SCANNER_SCAN
    return _SCANNER_UNKNOWN


def _legacy_probe_scanner_passthrough():
    """Fallback for a cx that predates `cx hooks check-auth`: run `cx hooks claude-pre-file-write
    --debug` on a BENIGN in-memory payload and inspect stderr.
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
    if _SCANNER_UNLICENSED_MARKER in stderr:
        return _SCANNER_UNLICENSED
    return _SCANNER_SCAN


def _scanner_state(identity=None):
    """Cached scanner readiness: _SCANNER_SCAN (cached on success), _SCANNER_PASSTHROUGH, or
    _SCANNER_UNKNOWN. Only the positive scan result is cached (a pass-through/unknown is never masked);
    keyed on the resolved cx binary AND the credential-file mtime, so a credential fix (or break) is
    reflected on the next gated call."""
    cx, mtime = identity if identity is not None else _binary_identity()
    key = {"cx": cx, "mtime": mtime, "cred": _credential_mtime()}
    return _cached_probe(_SCANNER_CACHE_FILE, _SCANNER_CACHE_TTL, key,
                         _probe_scanner_passthrough, lambda s: s == _SCANNER_SCAN)


def _setup_invocation() -> str:
    """The skill-invocation string to embed in deny/allow messages, per client convention:
    Codex CLI invokes skills with a `$name` prefix (no slash command, no colon-namespace);
    Claude Code / Copilot CLI use `/checkmarx-cli-setup`. _CODEX_MODE is set once per
    cx_check() call from the --codex argv flag — see cx_check()."""
    return "$cx-cli-setup" if _CODEX_MODE else "/checkmarx-cli-setup"


def _deny(reason: str, context: str, *, reason_code=None, tool_name=None, version_state=None) -> None:
    # Exit-code + output contract differs by client:
    #   Claude Code:  exit 2 + hookSpecificOutput JSON wrapper on stdout — PARSES
    #                 hookSpecificOutput.permissionDecision:"deny" and surfaces the reason.
    #   Codex CLI:    exit 0 + the SAME hookSpecificOutput JSON wrapper on stdout. Codex's own
    #                 docs (https://developers.openai.com/plugins/build/plugins /
    #                 https://learn.chatgpt.com/docs/hooks) confirm exit code is INDEPENDENT of
    #                 the JSON content for Codex: it accepts exit 0 + hookSpecificOutput JSON, OR
    #                 exit 2 + a plain-text reason on STDERR (no JSON) — never exit 2 + JSON on
    #                 stdout. That combination (which matches Claude's contract, not Codex's) was
    #                 confirmed live to produce a generic, reason-less "hook exited with code 1" —
    #                 Codex could not parse a deny out of it. So codex mode reuses Claude's JSON
    #                 shape but with exit 0, matching Codex's actually-documented contract.
    #   Copilot CLI:  exit 0 + FLAT JSON (no hookSpecificOutput wrapper) — Copilot CLI reads
    #                 permissionDecision / permissionDecisionReason at the TOP LEVEL of the
    #                 JSON object (per https://docs.github.com/en/copilot/reference/hooks-reference).
    #                 Using exit 1 also blocks but degrades to a generic "hook errored" with no
    #                 reason shown — the flat-JSON path is strictly better.
    # _COPILOT_CLI_MODE / _CODEX_MODE are set once per cx_check() call from the --copilot-cli /
    # --codex argv flags. Only Claude Code (neither flag set) uses exit 2; Codex CLI and Copilot
    # CLI both use exit 0 for a deny (exit 1 = error = fail-open on all three clients).
    _deny_exit = 0 if (_COPILOT_CLI_MODE or _CODEX_MODE) else 2
    _log("gate_decision", decision="deny", reason_code=reason_code, tool_name=tool_name,
         version_state=version_state, exit_code=_deny_exit)
    if _COPILOT_CLI_MODE:
        # Flat JSON — Copilot CLI reads permissionDecision at the top level.
        # permissionDecisionReason is shown directly to the agent.
        output = {
            "permissionDecision": "deny",
            "permissionDecisionReason": reason + "\n\n" + context,
        }
    elif _CODEX_MODE:
        # Codex CLI renders additionalContext as passive display/log text rather than feeding
        # it back into the model's turn as actionable instruction (confirmed live: the model saw
        # "hook context: ..." in the transcript but never acted on the bootstrap command inside
        # it). Fold reason + context into permissionDecisionReason, same as Copilot, so the
        # actionable command lives in the one field Codex's model actually treats as an
        # instruction to comply with.
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason + "\n\n" + context,
            }
        }
    else:
        # Claude Code nested wrapper format.
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
                "additionalContext": context,
            }
        }
    print(json.dumps(output))
    sys.exit(_deny_exit)


def _allow_with_warning(context: str, *, reason_code=None, tool_name=None) -> None:
    _log("gate_decision", decision="allow", reason_code=reason_code, tool_name=tool_name, exit_code=0)
    if _COPILOT_CLI_MODE:
        # Copilot CLI: flat JSON — embed warning in permissionDecisionReason.
        # permissionDecision:"allow" is not a standard Copilot CLI field but exit 0 = allow;
        # we include it so the agent sees the warning text in the hook output.
        output = {
            "permissionDecision": "allow",
            "permissionDecisionReason": context,
        }
    elif _CODEX_MODE:
        # See _deny(): Codex renders additionalContext as passive display text, not actionable
        # instruction. Use permissionDecisionReason so the warning is actually seen as such.
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": context,
            }
        }
    else:
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
    """Parse the PreToolUse JSON from stdin (Claude Code or Copilot CLI). Returns {} on
    any problem so the normal gate still runs."""
    try:
        if sys.stdin.isatty():
            return {}
        raw = sys.stdin.read()
    except (OSError, ValueError):
        return {}
    if not raw or not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Copilot CLI sends the full hook invocation envelope as stdin:
    #   { "hookInvocationId": "...", "hookType": "preToolUse", "input": { "sessionId": ...,
    #     "cwd": ..., "toolCalls": [...] } }
    # Unwrap to the inner "input" so all downstream helpers (which look for "toolCalls" at the
    # top level) work correctly. Claude Code sends the inner object directly (no envelope).
    if "input" in data and isinstance(data.get("input"), dict) and "hookType" in data:
        return data["input"]
    return data


def _is_copilot_cli_input(hook_input):
    """True when the hook input uses Copilot CLI's actual format.
    Real stdin has 'toolName' + 'toolArgs' at top level (confirmed from diag log).
    Also handles the toolCalls array format seen in events.jsonl."""
    return (
        "toolName" in hook_input or
        "toolArgs" in hook_input or
        isinstance(hook_input.get("toolCalls"), list)
    )


# Set once at the start of cx_check() after parsing the hook input. Read by _deny() and
# _fail_closed_on_crash() to choose the correct deny exit code per client.
_COPILOT_CLI_MODE = False

# Set once at the start of cx_check() from the --codex argv flag ONLY (no stdin-shape
# heuristic — Codex's PreToolUse stdin is Claude-shaped, snake_case, no envelope, so there is
# no distinguishing shape to sniff the way Copilot CLI's toolName/toolCalls envelope requires).
# Read by _setup_invocation() to pick the right skill-invocation string in deny/allow messages.
# Deliberately does NOT affect the JSON output shape or exit code — Codex's deny contract is
# identical to Claude's, so codex mode rides the existing (non-Copilot) branch unchanged.
_CODEX_MODE = False


def _tool_name(hook_input):
    """Extract tool name supporting all client formats:
    - Claude Code snake_case:       hook_input['tool_name']
    - Copilot CLI camelCase:        hook_input['toolName']   ← ACTUAL format confirmed from diag
    - Copilot CLI toolCalls array:  hook_input['toolCalls'][0]['name']
    Returns '' when no recognised key is present."""
    # Claude Code + Copilot CLI actual (toolName at top level)
    v = hook_input.get("tool_name") or hook_input.get("toolName")
    if v:
        return v
    # Copilot CLI toolCalls array format (events.jsonl format — may differ from real stdin)
    calls = hook_input.get("toolCalls")
    if isinstance(calls, list) and calls and isinstance(calls[0], dict):
        return calls[0].get("name") or ""
    return ""


def _tool_input(hook_input):
    """Extract tool input supporting all client formats:
    - Claude Code snake_case:    hook_input['tool_input']  (dict)
    - Copilot CLI actual format: JSON.parse(hook_input['toolArgs'])  ← ACTUAL confirmed from diag
    - Copilot CLI camelCase:     hook_input['toolInput']   (dict)
    - Copilot CLI toolCalls:     JSON.parse(hook_input['toolCalls'][0]['args'])
    Returns {} when no recognised key is present or args can't be parsed."""
    # Claude Code
    v = hook_input.get("tool_input")
    if isinstance(v, dict):
        return v
    # Copilot CLI ACTUAL format: toolArgs is a JSON string at top level
    raw = hook_input.get("toolArgs")
    if raw is not None:
        if isinstance(raw, dict):
            return raw
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            pass
    # Copilot CLI camelCase variant
    v = hook_input.get("toolInput")
    if isinstance(v, dict):
        return v
    # Copilot CLI toolCalls array format
    calls = hook_input.get("toolCalls")
    if isinstance(calls, list) and calls and isinstance(calls[0], dict):
        raw = calls[0].get("args", "{}")
        if isinstance(raw, dict):
            return raw
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


def _bash_command(hook_input):
    """The command string of a shell tool call, or '' if this is not a shell tool.
    Recognises all known shell tool names across clients:
      Claude Code:    tool_name='Bash'
      Copilot CLI:    toolCalls[0].name='powershell' (Windows) or 'bash' (Unix)
      Assumed/legacy: tool_name='command'
    All share the same carve-out guards: bootstrap, auth-recovery, read-only allowlist."""
    _SHELL_TOOLS = ("Bash", "command", "powershell", "bash", "shell")
    if _tool_name(hook_input) not in _SHELL_TOOLS:
        return ""
    command = _tool_input(hook_input).get("command", "")
    return command if isinstance(command, str) else ""


# The ONLY redirect SAFE inside an allow carve-out: suppression to the shell's null device.
# Bash/Git Bash: `/dev/null` (the oauth.md-mandated `1>/dev/null`, with an optional fd or `>>`).
# The null-device name must be a complete shell token — `(?=\s|$)`, not `\b` — so a real file
# whose name merely STARTS with it (`/dev/null.bak`) is not mistaken for suppression. ANY other
# redirect could write the command's stdout — which for `cx auth login` is the LIVE token — to a
# real file, so it disqualifies the carve-out. (fd-dups like `2>&1` contain `&` and are already
# rejected by _SHELL_CHAINING.) Note: `NUL` / `$null` are ORDINARY files in bash, so they are NOT
# safe to allow here — they are handled separately for PowerShell by _is_powershell_auth_recovery_command.
_NULL_REDIRECT_RE = re.compile(r'(?:&|\d)?(?:>>?|<)\s*/dev/null(?=\s|$)')

# PowerShell null-sink redirects: `1>$null`, `>$null`, `2>$null`, `>NUL`, etc.
# Safe to allow in the PowerShell auth-recovery carve-out — they discard stdout only (where the
# live token appears) and leave stderr attached. NOT used with the bash carve-out because `$null`
# and `NUL` are ordinary filenames in bash/Git Bash.
_PS_NULL_REDIRECT_RE = re.compile(r'(?:\d)?>>?\s*(?:\$null|NUL)(?=\s|$)', re.IGNORECASE)


def _has_unsafe_redirect(command):
    """True if the command contains a redirect to anything OTHER than `/dev/null`. A redirect to a
    real file could exfiltrate a command's stdout (e.g. the live token `cx auth login` prints) to an
    attacker-chosen path. The sanctioned `1>/dev/null` suppression stays allowed; any residual `>`/`<`
    after stripping the exact null-device redirects is unsafe."""
    residual = _NULL_REDIRECT_RE.sub(" ", command)
    return ">" in residual or "<" in residual


def _bare_bash_command(hook_input):
    """The Bash command string IFF it is a single BARE command safe to consider for an allow carve-out:
    a Bash tool call, with NO shell chaining/substitution (_SHELL_CHAINING) and NO unsafe redirect
    (_has_unsafe_redirect). Returns None otherwise. This is the one audited guard the bootstrap and
    auth-recovery carve-outs share, so a benign prefix can neither smuggle another command nor
    exfiltrate a command's stdout past the gate."""
    command = _bash_command(hook_input)
    if not command:
        return None
    if any(tok in command for tok in _SHELL_CHAINING):
        return None
    if _has_unsafe_redirect(command):
        return None
    return command


def _is_powershell_auth_recovery_command(hook_input):
    """PowerShell-specific auth recovery: allows `& "abs-cx-path" auth|configure …` with an
    optional PowerShell null-sink redirect (`1>$null` / `1>NUL`).
    The `&` call operator is PowerShell's way of invoking executables whose path contains spaces;
    it is NOT a shell-chaining token in this context — it is mandatory syntax. The regular
    _bare_bash_command guard rejects it because `&` is in _SHELL_CHAINING (which is correct for the
    Bash tool), so we handle the PowerShell form here instead.
    Security: pinned to the gate's OWN resolved cx (_cx_exe) — never an attacker-chosen path; no
    other chaining tokens (`;`, `|`, backtick, `$(`, newline) are allowed after the call operator
    and null-redirect are stripped."""
    if _tool_name(hook_input).lower() != "powershell":
        return False
    command = _bash_command(hook_input)
    if not command:
        return False
    # Strip trailing PowerShell null-sink redirect(s) — safe stdout suppression only.
    stripped = _PS_NULL_REDIRECT_RE.sub("", command).rstrip()
    s = stripped.lstrip()
    # Must start with `& ` (PowerShell call operator + space).
    if not s.startswith("& "):
        return False
    after_amp = s[2:].lstrip()
    # No shell-chaining tokens allowed after the `&` operator (exclude `&` itself — already consumed).
    for tok in _SHELL_CHAINING:
        if tok != "&" and tok in after_amp:
            return False
    # Must be `"abs-cx-path" auth|configure …` pinned to the gate's resolved cx.
    exe = _cx_exe()
    if not os.path.isabs(exe):
        return False
    # Accept both forward-slash and backslash path forms (the agent may use either on Windows).
    for path_form in (exe.replace("\\", "/"), exe):
        tok_re = re.escape(path_form)
        if re.match(r'"?' + tok_re + r'"?\s+(?:auth|configure)\b', after_amp, re.IGNORECASE):
            return True
    return False


def _is_auth_recovery_command(hook_input):
    """True for a credential-recovery command (`cx auth …` / `cx configure …`) that passes the shared
    bare-command guard — the path that must run even when unauthenticated so the auth gate never blocks
    the command that fixes auth. Accepts the BARE form (`cx auth …`, for later sessions / manual install
    where cx is on PATH) AND the resolved ABSOLUTE-path form the deny messages emit (`"<cx>" auth …`) so
    cx resolves on a first-install session before it is on PATH. The absolute form is pinned to the
    gate's OWN resolved cx (_cx_exe) — never an attacker-chosen path.
    Also handles the PowerShell `& "abs-cx-path" auth …` form used by Copilot CLI on Windows."""
    # PowerShell-specific form: `& "abs-cx-path" auth|configure …` with optional $null redirect.
    if _is_powershell_auth_recovery_command(hook_input):
        return True
    command = _bare_bash_command(hook_input)
    if command is None:
        return False
    if _AUTH_RECOVERY_RE.match(command):
        return True
    # The only remaining accepted form is `"<resolved cx>" auth|configure …`, which begins with a
    # quote or an absolute path — so ordinary commands (echo, ls, …) skip the _cx_exe() filesystem
    # stat + dynamic-regex build below.
    s = command.lstrip()
    if not (s[:1] in ('"', "/") or (len(s) >= 2 and s[1] == ":")):
        return False
    exe = _cx_exe()
    if os.path.isabs(exe):
        tok = re.escape(exe.replace("\\", "/"))
        if re.match(r'^\s*"?' + tok + r'"?\s+(?:auth|configure)\b', command):
            return True
    return False


def _is_bootstrap_command(hook_input):
    """True only for a bare `bash "<bootstrap>" <install|upgrade>` Bash command where <bootstrap>
    resolves to THIS plugin's own scripts/cx-bootstrap.sh — the single escape hatch from the
    fail-closed block. Independent defenses: Bash-only, no shell chaining, a REQUIRED install/
    upgrade mode (shape), and a path that must equal the bundled bootstrap. The literal
    ${PLUGIN_ROOT} placeholder (Codex's plugin-root env var, which the agent's shell does NOT
    expand — also accepts the legacy ${CLAUDE_PLUGIN_ROOT} form) is honored only after expanding
    it from the gate's own environment and proving it resolves to the bundled bootstrap — never
    blessed blindly."""
    command = _bare_bash_command(hook_input)
    if command is None:
        return False
    m = _BOOTSTRAP_RE.match(command)
    if not m:
        return False
    raw_path = m.group("path").strip()
    if raw_path in (
        "${PLUGIN_ROOT}/scripts/cx-bootstrap.sh",
        "${CLAUDE_PLUGIN_ROOT}/scripts/cx-bootstrap.sh",
    ):
        # Codex sets PLUGIN_ROOT (Claude Code sets CLAUDE_PLUGIN_ROOT) in the hook (gate)
        # environment; an unset or foreign value cannot be proven to be the bundled bootstrap
        # → fail CLOSED.
        root = os.environ.get("PLUGIN_ROOT") or os.environ.get("CLAUDE_PLUGIN_ROOT")
        if not root:
            return False
        raw_path = os.path.join(root, "scripts", "cx-bootstrap.sh")
    candidate = _normalize_path(raw_path)
    expected = _normalize_path(_bootstrap_script_path())
    return candidate is not None and candidate == expected


def _is_readonly_command(hook_input, tool):
    """True for a BARE shell tool call whose first token is a known read-only program.
    Reuses the same shape-guard; opt out with CX_GATE_ALL_COMMANDS=1."""
    _SHELL_TOOLS = ("Bash", "command", "powershell", "bash", "shell")
    if tool not in _SHELL_TOOLS or os.environ.get("CX_GATE_ALL_COMMANDS") == "1":
        return False
    command = _bare_bash_command(hook_input)
    if not command:
        return False
    parts = command.split()
    return bool(parts) and parts[0] in _READONLY_COMMANDS


def cx_check():
    hook_input = _read_hook_input()
    tool = _tool_name(hook_input)

    # 1. The bootstrap is the ONLY way out of the block — must be checked first.
    if _is_bootstrap_command(hook_input):
        _log("gate_decision", decision="allow", reason_code="bootstrap", tool_name=tool)
        return

    # Set the client mode flag — read by _deny() to choose the correct exit code.
    # Priority: explicit --copilot-cli argv flag (passed from hooks-copilot-cli.json) overrides
    # the stdin-format heuristic. The flag is the reliable signal because Copilot CLI may not
    # include a `toolCalls` key in every hook payload, causing _is_copilot_cli_input() to return
    # False and _deny() to fall back to exit 0 — which Copilot CLI ignores (it only blocks on
    # a non-zero exit). The argv flag makes Copilot CLI mode explicit and format-independent.
    global _COPILOT_CLI_MODE, _CODEX_MODE
    _COPILOT_CLI_MODE = ("--copilot-cli" in sys.argv[1:]) or _is_copilot_cli_input(hook_input)
    _CODEX_MODE = "--codex" in sys.argv[1:]


    # 2. Read-only Bash commands (ls, cat, grep, …) can't write code to disk or run another program,
    #     so there is nothing to scan — allow them WITHOUT requiring cx to be installed/authed. Removes
    #     the friction of gating a plain `ls` during setup. Allowlisted + shape-guarded so it can't be
    #     used to smuggle a write/exec (`ls; rm …`, `cat $(…)`, `> file` are all rejected).
    if _is_readonly_command(hook_input, tool):
        _log("gate_decision", decision="allow", reason_code="read_only", tool_name=tool)
        return

    # 2.5 CX_BINARY override: validate before trusting it. A set-but-invalid value fails CLOSED
    #     (never silently use a different binary). When valid, every gate probe below uses it,
    #     and the version/capability/auth gates then prove it's a real, recent, capable, authed cx.
    _, cx_err = _cx_binary()
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

    # 3. Resolve the effective cx the gate (and the stage-2 hooks/cx_run.sh wrapper) will run:
    #    CX_BINARY -> canonical store -> PATH. Because cx_run.sh uses the SAME precedence, the binary
    #    the gate proves recent/capable/authed below is exactly the one that scans — no PATH
    #    dependency, no fail-open. (The remediation MCP resolves cx the same way via hooks/cx_run.sh,
    #    so it is not a bare-PATH consumer either; if cx is absent it merely doesn't load — non-fail-open
    #    — so it is NOT required here.) A cx just
    #    installed to the canonical store resolves immediately, even before this frozen-PATH session
    #    can see it on PATH — which is what stops a fresh install from reading as "not installed".
    #    If NOTHING resolves, cx is genuinely absent → block.
    effective, effective_tier = _cx_exe_with_tier()
    resolved = effective if os.path.isabs(effective) else shutil.which(effective)
    if resolved is None:
        _install_instruction = (
            _bootstrap_copilot_cli_instruction("install") if _COPILOT_CLI_MODE else
            "To self-install now, run the plugin's bundled bootstrap by its resolved absolute path "
            "(its directory is empty in ${PLUGIN_ROOT} in your shell, so use this literal "
            "command):\n    " + _bootstrap_command_str("install")
        )
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is not installed. Security scanning cannot run, so this "
                "operation is BLOCKED. Run {0} to install and authenticate it, then retry."
            ).format(_setup_invocation()),
            context=(
                "cx CLI is not installed on this machine (not found via CX_BINARY, the canonical "
                "store, or PATH). All agent actions are blocked fail-closed until it is installed and "
                "authenticated. IMMEDIATELY invoke the checkmarx-cli-setup skill (via {0}). ".format(
                    _setup_invocation())
                + _install_instruction
            ),
            reason_code="cx_absent",
            tool_name=tool,
        )

    # Snapshot the cx binary identity ONCE (reusing the `resolved` path from step 3 — no second
    # _cx_exe()/which() walk) so the auth and scanner-readiness caches key off the SAME (path, mtime):
    # an atomic cx replace mid-invocation can't poison one cache with another binary's identity (which
    # could let a stale 'authenticated'/'will-scan' ride a swapped cx).
    identity = _binary_identity(resolved)

    # 4. Version gate — BEFORE auth-recovery, so a below-min cx can't sneak through via
    #    `cx auth login`. A below-min build lacks `cx mcp bridge` / `cx auth login`.
    state = _version_state(identity)
    if state == "below":
        min_ver = ".".join(str(n) for n in _load_min_version())
        _upgrade_instruction = (
            _bootstrap_copilot_cli_instruction("upgrade") if _COPILOT_CLI_MODE else
            "Invoke {0} (Phase 1b — Upgrade). To self-upgrade now, run "
            "the plugin's bundled bootstrap by its resolved absolute path:\n    {1}{2}".format(
                _setup_invocation(), _bootstrap_command_str("upgrade"), _cx_binary_pin_note(effective_tier)
            )
        )
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is older than the required v{0} and cannot run the scanner "
                "or the remediation MCP. This operation is BLOCKED until cx is upgraded.".format(min_ver)
            ),
            context=(
                "cx is below the minimum supported version (v{0}). All agent actions are blocked "
                "fail-closed — including `cx auth login`, which this old build may not support — until "
                "cx is upgraded. {1}".format(min_ver, _upgrade_instruction)
            ),
            reason_code="below_min",
            tool_name=tool,
            version_state="below",
        )
    if state == "unrunnable":
        _reinstall_instruction = (
            _bootstrap_copilot_cli_instruction("install") if _COPILOT_CLI_MODE else
            "Invoke {0}. To reinstall now, run the plugin's bundled bootstrap "
            "by its resolved absolute path:\n    ".format(_setup_invocation()) + _bootstrap_command_str("install")
            + _cx_binary_pin_note(effective_tier)
        )
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is on PATH but `cx version` did not run or did not report a "
                "usable version. Scanning cannot be confirmed, so this operation is BLOCKED."
            ),
            context=(
                "`cx version` failed or returned no parseable version (corrupt install, wrong binary, "
                "or a hung process). All agent actions are blocked fail-closed. "
                + _reinstall_instruction
            ),
            reason_code="unrunnable",
            tool_name=tool,
            version_state="unrunnable",
        )
    if state == "incapable":
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is installed but MISSING the security-scanner subcommands "
                "(cx mcp bridge / cx hooks claude-*). This build cannot run the gate, and re-running "
                "install/upgrade will only re-fetch the same incapable build — so this operation is "
                "BLOCKED and cannot be unblocked from here."
            ),
            context=(
                "cx ran `cx version` but the `cx mcp bridge` / `cx hooks claude-*` capability probes "
                "failed — this build predates the agent-security hooks (capability_missing), and a "
                "numeric version match is NOT sufficient. This is a TERMINAL state: it needs a "
                "capability-complete cx build, which may not be publicly available yet. Do NOT try to "
                "work around the gate — do NOT hand-place a cx binary, edit PATH, run setx, or clear "
                "the gate's caches; that only hides the problem without restoring scanning. Tell the "
                "developer a capable cx build is required, and stop. (If the developer has an internal "
                "capable build, they can set CX_BINARY to its absolute path.) All agent actions remain "
                "blocked fail-closed."
                + (
                    "\nNote: CX_BINARY is ALREADY set — and is pinned to THIS incapable binary. "
                    "Setting CX_BINARY again to the same path changes nothing; the developer needs "
                    "a DIFFERENT, capable build and must repoint CX_BINARY at THAT build's absolute "
                    "path (or unset CX_BINARY if a capable build has been placed in the canonical "
                    "store instead)."
                    if effective_tier == "binary" else ""
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
        # Fresh-login window: the credential was just written but `cx auth validate` is still returning
        # invalid — a transient backend-propagation lag, NOT a real auth failure. The critical guidance
        # is DON'T re-run `cx auth login`: it revokes the token and reissues a new one, resetting the
        # wait (the loop we observed). Tell the agent to wait and retry the SAME operation instead.
        if _credential_is_fresh():
            _deny(
                reason=(
                    "You just authenticated, but Checkmarx has not finished accepting the new token yet "
                    "(this can take up to ~1–2 minutes on some backends). Do NOT re-run `cx auth login` — "
                    "each login REVOKES the current token and RESTARTS the wait. Wait ~30–60s and retry "
                    "this SAME operation."
                ),
                context=(
                    "The cx credential file was written moments ago (a fresh `cx auth login`/`configure`), "
                    "but `cx auth validate` still reports not-authenticated — a transient post-login "
                    "window while the backend finalizes the freshly-issued token, NOT a bad credential. "
                    "RE-RUNNING `cx auth login` makes it WORSE: it revokes the token server-side and "
                    "issues a new one, resetting this wait — that is the loop to avoid. Wait ~30–60s, "
                    "then retry the ORIGINAL operation. You may confirm readiness once with:\n    "
                    + _cx_recovery_command_str("auth validate")
                    + "\nAll agent actions remain blocked fail-closed until validate succeeds."
                ),
                reason_code="auth_pending_fresh_login",
                tool_name=tool,
                version_state=state,
            )
        _deny(
            reason=(
                "The Checkmarx CLI (cx) could not authenticate to Checkmarx One. If you JUST signed in, "
                "the backend may have been slow — retry the operation once. Otherwise run {0} "
                "to (re)authenticate, then retry."
            ).format(_setup_invocation()),
            context=(
                "cx auth validate did not succeed within the gate's timeout — cx is either not "
                "authenticated (credentials missing or expired) OR the backend was slow/unreachable, so "
                "a valid session that simply timed out looks the same here. Retry once; if it persists, "
                "invoke the checkmarx-cli-setup skill "
                "(%s) for the guided flow. ASK THE DEVELOPER WHICH METHOD FIRST — do not "
                "assume OAuth and do not ask for a URL/tenant before this choice is made. There are two "
                "ways to authenticate, and they differ in who runs them:\n" % _setup_invocation()
                + "- API key (ask this first / simplest): the DEVELOPER runs this in their own terminal "
                "(it is a plaintext secret — do not type an API key yourself):\n    "
                + _cx_recovery_command_str("configure set --prop-name cx_apikey --prop-value <key>")
                + "\n" + _oauth_recovery_bullet(_load_admin_config())

                + "\n  It blocks until the developer finishes (~5 min) — run it with a long timeout or "
                "in the background.\n"
                "Only `cx auth …` / `cx configure …` recovery commands run until authentication "
                "succeeds."
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
    #     CLOSED with the same visible /checkmarx-cli-setup message. UNKNOWN (probe error/timeout) defers to
    #     the real stage-2 scanner — no worse than before — so a flaky probe can't over-block a
    #     genuinely-authenticated user. (Carve-outs in steps 1/2/5 already returned, so the bootstrap,
    #     read-only commands, and `cx auth`/`cx configure` recovery commands never reach this probe.)
    scanner = _scanner_state(identity)
    if scanner == _SCANNER_UNLICENSED:
        # Authenticated, but the cx account has NO AI-scanning license (Checkmarx One Assist / AI
        # Protection / Developer Assist). cx then runs the scanner in SILENT pass-through — it will
        # NOT scan — so allowing the write would be a fail-OPEN (unscanned code reaches disk). Fail
        # CLOSED by default; an operator who KNOWINGLY accepts running without scanning can opt out
        # with CX_ALLOW_UNLICENSED=1 (each such run is surfaced as an unscanned-run warning).
        if os.environ.get("CX_ALLOW_UNLICENSED") == "1":
            _log("unlicensed_override", tool_name=tool)
            _allow_with_warning(
                context=(
                    "WARNING: cx is authenticated but has NO AI-scanning license, so its scanner runs "
                    "in pass-through and this operation ran UNSCANNED. Allowed only because "
                    "CX_ALLOW_UNLICENSED=1. Acquire a Checkmarx AI-scanning license (Checkmarx One "
                    "Assist / AI Protection / Developer Assist) and unset CX_ALLOW_UNLICENSED to "
                    "restore scanning."
                ),
                reason_code="unlicensed_override",
                tool_name=tool,
            )
        _deny(
            reason=(
                "The Checkmarx CLI is authenticated but has NO AI-scanning license, so its security "
                "SCANNER runs in pass-through (allow everything, NO scan). To avoid writing unscanned "
                "code, this operation is BLOCKED."
            ),
            context=(
                "`cx hooks check-auth` reports the scanner is authenticated but UNLICENSED — cx holds "
                "no Checkmarx One Assist / AI Protection / Developer Assist entitlement, so the native "
                "scanner would silently allow everything UNSCANNED. Acquire the AI-scanning license for "
                "this account/tenant (contact your Checkmarx administrator). If you understand and "
                "accept that code will be written WITHOUT scanning, set CX_ALLOW_UNLICENSED=1 to allow "
                "these operations (each is logged as an unscanned run). All agent actions remain blocked "
                "fail-closed until one of those is done."
            ),
            reason_code="scanner_unlicensed",
            tool_name=tool,
            version_state=state,
        )
    if scanner == _SCANNER_PASSTHROUGH:
        _deny(
            reason=(
                "The Checkmarx CLI authenticated, but its security SCANNER could not — it is running "
                "in pass-through (allow everything, NO scan) because it cannot establish an "
                "authenticated session from the current credential. This operation is BLOCKED."
            ),
            context=(
                "`cx auth validate` passed, but `cx hooks check-auth` reports the scanner is not "
                "authenticated — the native scanner could not authenticate with the current "
                "stored credential (stale/expired, or the backend was unreachable) and would silently "
                "allow everything UNSCANNED. Re-authenticate via the checkmarx-cli-setup skill ({0}). "
                .format(_setup_invocation()) +
                "ASK THE DEVELOPER WHICH METHOD FIRST — do not assume OAuth and do not ask for a "
                "URL/tenant before this choice is made.\n"
                "- API key (ask this first / simplest): the DEVELOPER runs this in their own terminal "
                "(do not type an API key yourself):\n    "
                + _cx_recovery_command_str("configure set --prop-name cx_apikey --prop-value <key>")
                + "\n" + _oauth_recovery_bullet(_load_admin_config())

                + "\nOnly `cx auth …` / `cx configure …` commands run until the scanner is authenticated."
            ),
            reason_code="scanner_passthrough",
            tool_name=tool,
            version_state=state,
        )

    # cx is installed, recent enough, authenticated, and the scanner WILL actually scan.
    _log("gate_decision", decision="pass", reason_code="ok", tool_name=tool, version_state=state)


def _fail_closed_on_crash():
    """Last-resort deny printed if the gate itself crashes. A fail-CLOSED guard: an unexpected
    error inside cx_check() must still BLOCK via a decided deny (exit 0 + permissionDecision:
    "deny" JSON) — see the exit-code contract note on _deny(). main() exits 0 after calling this
    so the JSON is actually read instead of being discarded as a generic hook error.
    Uses the correct JSON shape per client: flat for Copilot CLI, nested for Claude Code.
    NOTE: reads sys.argv directly (not _COPILOT_CLI_MODE/_CODEX_MODE) because a crash inside
    _is_bootstrap_command() or any pre-mode-set code path means those flags may still be False
    even for a Copilot CLI / Codex invocation — sys.argv is always reliable."""
    try:
        is_copilot = _COPILOT_CLI_MODE or "--copilot-cli" in sys.argv
        if is_copilot:
            print(json.dumps({
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "The Checkmarx security gate hit an internal error and could not evaluate "
                    "this action, so it is BLOCKED fail-closed. Re-run /checkmarx-cli-setup, or set "
                    "CX_ALLOW_UNSCANNED=1 to bypass scanning (audited)."
                ),
            }))
        else:
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
                        "blocked until it is resolved. Re-run /checkmarx-cli-setup, or set CX_ALLOW_UNSCANNED=1 "
                        "to bypass scanning (audited)."
                    ),
                }
            }))
    except Exception:
        pass


def main():
    # _deny()/_allow_with_warning() raise SystemExit with the decision JSON already printed.
    # ANY other exception is an internal gate failure → fail CLOSED (deny).
    # Claude Code: exit 2 (non-zero = deny; exit 1 = uncaught error = fail-open).
    # Codex CLI / Copilot CLI: exit 0 (non-zero is treated as a hook ERROR — fail-open — not a
    # denial; see the exit-code contract note on _deny()).
    try:
        cx_check()
    except SystemExit:
        raise
    except BaseException:
        _fail_closed_on_crash()
        is_copilot = _COPILOT_CLI_MODE or "--copilot-cli" in sys.argv
        is_codex = _CODEX_MODE or "--codex" in sys.argv
        sys.exit(0 if (is_copilot or is_codex) else 2)


if __name__ == "__main__":
    main()
