"""Shared helper: enforces that the cx CLI is installed, recent enough, and authenticated
before gated file writes (to types Checkmarx can scan) and Checkmarx MCP calls. Fail-closed: if cx
is missing, unrunnable, or below the minimum version, those operations are BLOCKED — even offline.
Shell commands are never blocked by this gate. The only escape from the block is running the plugin's
own bundled bootstrap.

This gate runs for Cursor preToolUse (Write/StrReplace/Edit/MultiEdit/EditNotebook) and
beforeMCPExecution (see hooks/hooks.json); it governs whether the security TOOLING ITSELF is usable,
not whether a specific ASCA/SCA finding should block a write. That distinction lives in stage 2
(hooks/cx_run.sh -> `cx hooks cursor-before-file-write`), which emits structured deny JSON with
agent_message when a finding is detected; the agent must follow cx-hook-deny.mdc."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# This file's OWN directory must be importable for the sibling helper modules below. Python already
# puts a script's directory on sys.path when it is run as `python …/cx_check.py` (how the hooks invoke
# it), but NOT when it is loaded by absolute path via importlib — which is how the test suite and any
# embedding tool load it. Inserting it explicitly makes the sibling imports work in both cases.
_HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
if _HOOKS_DIR not in sys.path:
    sys.path.insert(0, _HOOKS_DIR)

# Structured logging is OPTIONAL and must NEVER break the gate: a missing/broken cx_log, or any
# error inside it, is swallowed and the gate proceeds exactly as before.
try:
    import cx_log
except Exception:
    cx_log = None

# hooks/cx_shell.py owns EVERY shell-specific concern (unwrapping PowerShell/cmd/bash wrappers,
# variable expansion, chaining/redirect checks, and rendering commands per shell) so this gate and
# hooks/_cx_bootstrap_match.sh cannot drift apart on what a command means. Unlike cx_log, it is NOT
# optional — the carve-outs below cannot be evaluated without it — so a failed import is recorded and
# turned into a fail-CLOSED deny in main() rather than an uncaught ImportError, which would exit 1
# and risk being treated as non-blocking (fail OPEN).
try:
    import cx_shell
    _CX_SHELL_IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - only on a broken/partial install
    cx_shell = None
    _CX_SHELL_IMPORT_ERROR = "{0}: {1}".format(type(exc).__name__, exc)


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
_MIN_VERSION_FALLBACK = (2, 3, 63)

# The cx executable the GATE invokes for its own probes, resolved by ABSOLUTE path where possible so
# the gate works the instant cx is installed — even before it is on PATH. A freshly-installed cx in
# the canonical store is invisible to this frozen-PATH session (setx/shell-profile only affect
# FUTURE sessions), so relying on PATH alone would keep the gate blocked until a restart. Resolution
# precedence: CX_BINARY (explicit pin) -> the canonical per-OS store the bootstrap installs to -> PATH.
# The stage-2 scanner runs through hooks/cx_run.sh, which uses the SAME precedence, so whatever the
# gate validates (version/capability/auth) is exactly what scans — no PATH dependency, no fail-open.
# (The remediation MCP resolves cx the SAME way, via hooks/cx_run.sh, so it is not a bare-PATH
# consumer either; it activates after one /reload-plugins, no scan is bypassed.) CX_BINARY must be valid.
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


def _canonical_cx_path():
    """Absolute path where the bootstrap installs cx — whether or not the file exists yet.
    Used for carve-out path pinning when matching deny-message commands before the gate has
    resolved cx (LOCALAPPDATA unset in the hook env, PATH not refreshed, etc.)."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local")
        return os.path.normpath(os.path.join(base, "Checkmarx", "cx", "cx.exe"))
    return os.path.normpath(os.path.join(os.path.expanduser("~"), ".checkmarx", "bin", "cx"))


def _is_trusted_cx_exe_path(raw_path):
    """True when `raw_path` names a real cx binary the auth/setup carve-outs may invoke.

    Matches pinned candidates (canonical store, CX_BINARY, gate resolution) OR — when the path is
    absolute and names an existing `cx` / `cx.exe` on disk — the literal path from a deny message /
    PowerShell `& \"…\\cx.exe\" auth …` line. That second case is what stops cx_check from denying
    OAuth recovery when env-based canonical resolution drifts from the path the agent actually runs."""
    if not raw_path or not isinstance(raw_path, str) or raw_path.strip() == "cx":
        return False
    for expected in _resolved_cx_candidates():
        if _paths_equal(raw_path, expected):
            return True
    try:
        norm = os.path.normpath(raw_path)
        if os.path.basename(norm).lower() not in ("cx", "cx.exe"):
            return False
        candidates = [norm, raw_path]
        if os.name == "nt":
            candidates.extend([norm.replace("\\", "/"), raw_path.replace("\\", "/")])
        for candidate in candidates:
            if not candidate:
                continue
            try:
                if os.path.isfile(candidate):
                    if os.path.isabs(os.path.normpath(candidate)):
                        return True
                    if os.name == "nt" and len(candidate) >= 2 and candidate[1] == ":":
                        return True
            except (OSError, ValueError, TypeError):
                continue
    except (OSError, ValueError, TypeError):
        return False
    return False


def _resolved_cx_candidates():
    """Absolute paths treated as 'our' cx for auth/setup carve-out path pinning (deduped)."""
    seen = set()
    out = []

    def add(p):
        if not p or not isinstance(p, str):
            return
        n = _normalize_path(p)
        if n and n not in seen:
            seen.add(n)
            out.append(p)

    exe, err = _cx_binary()
    if err is None and exe != "cx":
        add(exe)
    add(_canonical_cx())
    add(_canonical_cx_path())
    resolved, _tier = _cx_exe_with_tier()
    if os.path.isabs(resolved):
        add(resolved)
    elif resolved == "cx":
        add(shutil.which("cx"))
    add(_cx_exe())
    return out


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


def _cx_recovery_exe():
    """cx path embedded in deny/recovery commands. Prefer the resolved binary; when cx is not yet on
    PATH / in the canonical store, fall back to the per-OS canonical STORE PATH anyway so every
    platform's recovery line (`~/.checkmarx/bin/cx` on Unix, `%LOCALAPPDATA%\\…\\cx.exe` on Windows)
    is both rendered AND accepted by the carve-out matchers — not a bare `cx` that fails on a
    first-install session."""
    exe = _cx_exe()
    if exe and exe != "cx" and os.path.isabs(exe):
        return exe
    return _canonical_cx_path()


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


def _is_number(value):
    """True for a real int/float — NOT bool (True == 1 in Python)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _read_capped(path, max_bytes, encoding="utf-8-sig"):
    """The file's text, or None if unreadable, undecodable, or larger than max_bytes."""
    try:
        with open(path, "r", encoding=encoding) as f:
            raw = f.read(max_bytes + 1)
    except (OSError, UnicodeDecodeError):
        return None
    return None if len(raw) > max_bytes else raw


def _plugin_path(*parts):
    """Absolute path to a file bundled in this plugin, relative to THIS file (…/hooks)."""
    return os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", *parts))


def _agent_log_dir():
    """Per-user directory for the gate's caches and bypass audit (and, later, structured
    logs). Default ~/.checkmarx/agent-logs/cursor/ — a user-owned 0700 dir, so these
    predictable filenames can't be pre-planted by another local user the way world-writable
    OS-temp files could. CX_LOG_DIR overrides the location. Falls back to the OS temp dir
    only if the per-user dir can't be created, so caching/auditing degrade gracefully and
    this never raises into the gate."""
    override = os.environ.get("CX_LOG_DIR")
    target = override or os.path.join(
        os.path.expanduser("~"), ".checkmarx", "agent-logs", "cursor"
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


# Per-user state lives under _AGENT_LOG_DIR (default ~/.checkmarx/agent-logs/cursor, 0700),
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

# Every cx subcommand that is TRUSTED BOOTSTRAP/SETUP work and must therefore ALWAYS reach an allow,
# even while the gate is otherwise blocking every action:
#   auth …            login / logout / validate / register — the OAuth and token-validation surface
#   configure …       set/show, including `configure set --prop-name cx_apikey` (API-key path)
#   hooks check-auth  the scanner's own session/licence validation probe
# These are the commands that FIX the very conditions the gate blocks on, so gating them is a
# deadlock, not a control: without this carve-out `cx auth login` is denied because cx is not
# authenticated. `version` / `utils env` are trusted too but live in the separate
# _SETUP_DIAGNOSTIC_RE group below, because those are pure convenience (they only remove setup noise)
# and so stay subject to the CX_GATE_ALL_COMMANDS opt-out, while these do not.
_AUTH_RECOVERY_SUBCOMMANDS = r"(?:auth|configure|hooks\s+check-auth)\b"

# `cx ignore-vulnerability ...` — a bounded, self-referential bookkeeping command against cx's own
# ignore file (see hooks/cx_run.sh's carve-out call for the reliability problem this solves: without
# it, EVERY ignore-vulnerability call depends on a blocking call into the native
# `cx hooks cursor-before-shell` scanner, which is unreliable for this command in practice).
# Stage 1 (cx_check.sh) and Stage 2 (cx_run.sh) both fast-allow via --match-ignore-vulnerability;
# the command still requires a working cx at runtime but skips the slow native scanner and the full
# auth/version gate latency on the hook path.
_IGNORE_VULN_SUBCOMMAND = r"ignore-vulnerability\b"

# A bare `bash "<bootstrap>" <install|upgrade>` invocation — the ONLY command allowed to run
# while the gate is blocking, because it's how the missing/outdated cx gets fixed. The mode is
# REQUIRED (a bare `bash "<bootstrap>"` is not a sanctioned action); the path is validated
# separately (must resolve to the plugin's own bootstrap); the regex pins the shape so no extra
# arguments or a `-c` payload can ride along.
# `'` is accepted alongside `"` because PowerShell's literal quoting form is single quotes, and an
# agent driving PowerShell writes `bash 'C:\…\cx-bootstrap.sh' install` just as naturally.
_BOOTSTRAP_RE = re.compile(
    r"""^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*(?:bash|sh)\s+(?:"(?P<path>[^"]+)"|'(?P<spath>[^']+)'|(?P<upath>\S+))\s+(?:install|upgrade)\s*$""")

# Read-only shell programs that cannot write code to disk or execute another program — safe to run
# WITHOUT the cx readiness/auth gate, so a plain `ls`/`cat` works during setup instead of being blocked
# with "cx not installed". Matched ONLY as a BARE command (via _bare_bash_command: no chaining /
# substitution / unsafe redirect) whose FIRST token equals one of these. Programs with a write or exec
# form are deliberately EXCLUDED — find (-exec/-delete), sed (-i), awk (system), sort (-o), tee, env /
# command / type / xargs (run others), git (push/commit/config …) — so this can never smuggle a write
# or a command. Disable with CX_GATE_ALL_COMMANDS=1.
#
# Covers all four supported shells, because the SAME setup step is spelled differently in each and
# gating one spelling while allowing another is arbitrary friction: `which cx` (bash) is `where cx`
# (cmd) is `Get-Command cx` (PowerShell); `ls`/`cat` are `dir`/`type` in cmd and
# `Get-ChildItem`/`Get-Content` in PowerShell. Matching is CASE-INSENSITIVE (see
# _is_readonly_command) since PowerShell cmdlet names and cmd builtins are. PowerShell cmdlets that
# can write (Set-*, New-*, Out-File, Add-Content, Tee-Object) or execute (Invoke-*, Start-*) are
# excluded on the same principle as their POSIX counterparts.
_READONLY_COMMANDS = frozenset(name.lower() for name in {
    # POSIX / Git Bash
    "ls", "pwd", "cat", "head", "tail", "echo", "whoami", "id", "date", "hostname", "uname",
    "wc", "which", "where", "stat", "file", "basename", "dirname", "realpath", "readlink", "tree",
    "df", "du", "ps", "grep", "rg", "cut", "uniq", "cmp", "cksum", "md5sum", "sha256sum",
    # cmd.exe builtins / Windows utilities
    "dir", "ver", "systeminfo",
    # PowerShell read-only cmdlets
    "Get-Command", "Get-ChildItem", "Get-Content", "Get-Location", "Get-Date", "Get-Host",
    "Get-ComputerInfo", "Test-Path", "Split-Path", "Resolve-Path", "Join-Path", "Write-Output",
    "Write-Host", "Select-String", "Measure-Object", "Get-FileHash",
})


# --- Scannable files: what the three Checkmarx engines can actually analyse ------------------------
# The readiness chain is only worth ENFORCING for a file one of the engines would look at.
# The set lives in config/cx-scannable-files; THIS is its only reader — see that file's header.
_SCANNABLE_FILES_MAX_BYTES = 65536
_SCANNABLE_KINDS = ("ext", "suffix", "base", "txtprefix")
_FILE_TOOL_PATH_KEYS = ("file_path", "notebook_path")
_FILE_WRITE_TOOLS = frozenset({"Write", "StrReplace", "Edit", "MultiEdit", "EditNotebook"})


def _scannable_files_path():
    return _plugin_path("config", "cx-scannable-files")


def _load_scannable_files(path=None):
    """config/cx-scannable-files parsed to {kind: frozenset(lowercased values)}, or None on failure."""
    try:
        if path is None:
            path = _scannable_files_path()
        raw = _read_capped(path, _SCANNABLE_FILES_MAX_BYTES)
        if raw is None:
            return None
        parsed = {kind: set() for kind in _SCANNABLE_KINDS}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            kind, _sep, value = line.partition(":")
            kind = kind.strip().lower()
            value = value.strip().lower()
            if value and kind in parsed:
                parsed[kind].add(value)
        if not any(parsed.values()):
            return None
        return {kind: frozenset(values) for kind, values in parsed.items()}
    except Exception:
        return None


def _effective_basename(base):
    """The basename that will ACTUALLY be created, or '' when it cannot be determined."""
    if "::" in base:
        return ""
    return base.rstrip(" .")


def _is_scannable_file(hook_input):
    """True when this call targets a file one of the Checkmarx engines can analyse.

    FAIL CLOSED on every uncertainty. Force-gate everything with CX_GATE_ALL_FILES=1."""
    if os.environ.get("CX_GATE_ALL_FILES") == "1":
        return True
    if hook_input.get("tool_name") not in _FILE_WRITE_TOOLS:
        return True
    tool_input = hook_input.get("tool_input")
    if not isinstance(tool_input, dict):
        return True
    path = None
    for key in _FILE_TOOL_PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            path = value
            break
    if path is None:
        return True
    table = _load_scannable_files()
    if table is None:
        return True
    base = _effective_basename(os.path.basename(path.replace("\\", "/").rstrip("/")).lower())
    if not base:
        return True
    if base in table["base"]:
        return True
    _root, ext = os.path.splitext(base)
    if ext and ext in table["ext"]:
        return True
    if any(base.endswith(suffix) for suffix in table["suffix"]):
        return True
    if ext == ".txt" and any(base.startswith(prefix) for prefix in table["txtprefix"]):
        return True
    return False


# Git-Bash/MSYS-style POSIX rendering of a Windows drive path: `/c/Users/...` for `C:\Users\...`.
# This is exactly what `pwd`/`$(dirname "$0")` return inside the Git-Bash `bash`/`sh` the agent's
# Shell tool and this plugin's own scripts run under — so a bootstrap/auth-recovery command the
# agent builds from a bash-resolved path is very likely to look like this, NOT like Python's own
# `os.path.abspath` rendering.
_GITBASH_DRIVE_COLON_RE = re.compile(r"^/([A-Za-z]):/(.*)$")
_GITBASH_DRIVE_RE = re.compile(r"^/([A-Za-z])(/.*)?$")


def _normalize_path(p):
    """Normalize for cross-format comparison: absolute, real-cased on Windows, forward
    slashes. Lets a path the agent typed (possibly with the Windows `\\` cx_check.py's
    __file__ produced) compare equal to the resolved bootstrap path.

    On Windows, ALSO rewrites a leading Git-Bash-style drive prefix (`/c/...`) to the native
    drive form (`C:/...`) before handing off to `os.path`. Without this, `os.path.abspath` has no
    concept of `/c/...` as a drive reference — it treats the leading `/` as "root of the current
    drive" and `c` as an ordinary directory NAME, so `/c/AST/Repos/x.sh` resolves to the bogus
    `C:\\c\\AST\\Repos\\x.sh` instead of `C:\\AST\\Repos\\x.sh`. That silently broke every
    path-equality carve-out (bootstrap, auth-recovery, setup-diagnostic) whenever the agent's
    Git-Bash shell supplied a POSIX-style path for the very file this gate resolves via Python's
    native (backslash) path — a real, observed cause of the bootstrap command being denied as
    "not recognized" even though it was byte-for-byte the documented recovery command."""
    if os.name == "nt" and isinstance(p, str):
        posix = p.replace("\\", "/")
        m = _GITBASH_DRIVE_COLON_RE.match(posix)
        if m:
            p = m.group(1).upper() + ":/" + m.group(2)
        else:
            m = _GITBASH_DRIVE_RE.match(p)
            if m:
                drive = m.group(1).upper()
                rest = (m.group(2) or "/").replace("/", "\\")
                p = drive + ":" + rest
    try:
        p = os.path.abspath(os.path.normpath(p))
    except (OSError, ValueError):
        return None
    if os.name == "nt":
        p = p.casefold()
    return p.replace("\\", "/")


def _paths_equal(a, b):
    """True when two path strings refer to the same filesystem location. Uses normalized string
    equality first, then os.path.samefile when both paths exist (handles symlinks, short vs long
    paths on Windows)."""
    na = _normalize_path(a)
    nb = _normalize_path(b)
    if na is None or nb is None:
        return False
    if na == nb:
        return True
    try:
        return os.path.samefile(a, b)
    except (OSError, ValueError):
        return False


def _plugin_root_from_script_dir():
    """Plugin root derived from where THIS hook script lives — mirrors hooks/cx_run.sh's SCRIPT_DIR
    (dirname of the launcher) + `cd ..`, which is what deny messages and the stage-2 scanner embed."""
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def _plugin_root_candidates():
    """Every plugin root that may host the bundled bootstrap for THIS install.

    The hook launcher always runs from __file__'s tree (same as cx_run.sh's SCRIPT_DIR). Cursor may
    ALSO inject CURSOR_PLUGIN_ROOT/CX_PLUGIN_ROOT — sometimes pointing at a different copy (e.g. the
    agent copied the deny-message path from `.cursor/plugins/local/…` while hooks still run from a
  dev checkout). Path-equality carve-outs must consider every candidate so the documented recovery
    command is never denied as "unrecognized" when the target file exists."""
    roots = []
    seen = set()
    for root in (_plugin_root_from_script_dir(),):
        norm = os.path.normpath(root)
        key = _normalize_path(norm)
        if key and key not in seen:
            seen.add(key)
            roots.append(norm)
    for var in ("CURSOR_PLUGIN_ROOT", "CX_PLUGIN_ROOT"):
        root = os.environ.get(var)
        if not root:
            continue
        norm = os.path.normpath(root)
        key = _normalize_path(norm)
        if key and key not in seen:
            seen.add(key)
            roots.append(norm)
    return roots


def _plugin_root_from_script():
    """Primary plugin root for deny-message paths — always __file__-relative (cx_run.sh parity)."""
    return _plugin_root_from_script_dir()


def _bootstrap_script_candidates():
    """Absolute paths to scripts/cx-bootstrap.sh under every known plugin root for this hook."""
    return [
        os.path.normpath(os.path.join(root, "scripts", "cx-bootstrap.sh"))
        for root in _plugin_root_candidates()
    ]


def _bootstrap_script_path():
    """Resolved absolute path to scripts/cx-bootstrap.sh beside this hook (__file__ tree)."""
    return os.path.normpath(
        os.path.join(_plugin_root_from_script_dir(), "scripts", "cx-bootstrap.sh")
    )


def _is_existing_bootstrap_script_path(raw_path):
    """True when `raw_path` names a real `…/scripts/cx-bootstrap.sh` on disk.

    Last-resort matcher for deny-message copy-paste: the agent runs the exact path the gate printed
    even when that path targets a different plugin install copy than this hook's __file__ tree."""
    if not raw_path:
        return False
    try:
        norm = os.path.normpath(raw_path)
        if os.path.basename(norm).lower() != "cx-bootstrap.sh":
            return False
        if os.path.basename(os.path.dirname(norm)).lower() != "scripts":
            return False
        return os.path.isfile(norm)
    except (OSError, ValueError, TypeError):
        return False


def _bootstrap_path_matches(raw_path):
    """True when `raw_path` is THIS plugin's bundled bootstrap (any install copy) or a real one on disk."""
    if not raw_path:
        return False
    candidate = _normalize_path(raw_path)
    for expected in _bootstrap_script_candidates():
        expected_norm = _normalize_path(expected)
        if candidate is not None and expected_norm is not None and candidate == expected_norm:
            return True
        if _paths_equal(raw_path, expected):
            return True
    return _is_existing_bootstrap_script_path(raw_path)


def _bootstrap_command_str(mode):
    """The exact command the agent should run to escape the block — embedded in deny
    messages so the agent doesn't need ${CURSOR_PLUGIN_ROOT} (which is empty in its shell).
    Forward slashes so Git-Bash and the shell-stage bootstrap matcher both accept the path."""
    return 'bash "{0}" {1}'.format(_bootstrap_script_path().replace("\\", "/"), mode)


def _cx_bash_token():
    """The gate's resolved cx as a single POSIX-shell-safe token. On a first-install session cx sits
    in the canonical store but NOT on the frozen PATH, so a bare `cx` would exit 127 — emit the
    resolved ABSOLUTE path instead (forward slashes so Git-Bash doesn't treat backslashes as escapes;
    double-quoted so a path with spaces survives). Falls back to bare 'cx' when only PATH resolution
    is available (later sessions / manual install), so the guidance degrades cleanly.

    POSIX-only by design: this is the token form used where the surrounding text is already a bash
    command (e.g. the bundled scripts). Anything the AGENT is told to run goes through
    _cx_recovery_command_block(), which renders PowerShell / cmd / bash forms instead — a quoted path
    alone is a string EXPRESSION in PowerShell, not a command."""
    exe = _cx_exe()
    if os.path.isabs(exe):
        return '"{0}"'.format(exe.replace("\\", "/"))
    return "cx"


def _detected_shell():
    """The shell the agent is driving, as detected for THIS invocation (cx_check() records it in
    _GATE_CTX from the incoming command, which is the only first-hand evidence available)."""
    return _GATE_CTX.get("shell") or cx_shell.detect_shell()


def _cx_recovery_command_str(args, suppress_stdout=False):
    """A ready-to-run `cx auth …` / `cx configure …` recovery command for the DETECTED shell, using
    the gate's resolved cx (absolute path when cx isn't yet on PATH). Mirrors _bootstrap_command_str,
    which likewise embeds a resolved absolute path so the agent never needs ${CURSOR_PLUGIN_ROOT} /
    cx on PATH. Use _cx_recovery_command_block() in deny text so the other shells are shown too."""
    return cx_shell.render_invocation(_detected_shell(), _cx_recovery_exe(), args,
                                      suppress_stdout=suppress_stdout)


def _cx_recovery_command_block(args, suppress_stdout=False):
    """The same recovery command, rendered for EVERY shell the developer could be in and prefixed
    with a newline so it drops straight into deny/context prose.

    Why not one string: the three shells genuinely disagree. PowerShell needs the `&` call operator
    before a quoted path (without it the path is echoed, not executed), bash needs forward slashes
    (a backslash is an escape), cmd needs backslashes, and stdout suppression is `1>/dev/null` vs
    `1>$null` vs `1>NUL`. The detected shell is listed first; every listed form is accepted by the
    gate's carve-outs (see _is_auth_recovery_command), so the agent cannot pick a line that then gets
    blocked. On macOS/Linux there is only one relevant form, so this collapses to a single line."""
    return "\n" + cx_shell.variants_block(
        _cx_recovery_exe(), args, suppress_stdout=suppress_stdout, detected=_detected_shell())


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


# --- Admin onboarding config (config/cx-onboarding.properties) -------------------------------------
# Official Checkmarx One doc that lists the regional environment base URLs and how to find your
# tenant. Surfaced in the OAuth recovery guidance so a developer can look up their region instead of
# guessing. The concrete region examples are ALSO embedded inline below, so the guidance is useful
# even without opening the page.
_CX_ENV_URLS_DOC = "https://docs.checkmarx.com/en/34965-68530-logging-in-to-checkmarx-one.html"

# STRICT validation for admin-supplied values. These get embedded into the `cx auth login …` command
# the AGENT then runs, so the charset must exclude every shell-active and flag-smuggling character:
#   - tenant: must START alphanumeric (bans a leading '-' → no `--proxy …`/`--insecure` flag
#     smuggling), then only letters/digits/._- , max 64. No whitespace/quote/$/backtick by construction.
#   - base-auth-uri: https:// + host (+ optional :port) ONLY — no path/query/userinfo/space, so it
#     cannot carry a second token or a redirect.
# Anything failing these is IGNORED (fall back to the <url>/<tenant> placeholders); a bad value is
# never emitted and never blocks — this is a convenience, not a gate control (fail SOFT, not closed).
_ADMIN_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
_ADMIN_URL_RE = re.compile(r"^https://[A-Za-z0-9][A-Za-z0-9.\-]{0,127}(?::[0-9]{2,5})?$")
_ADMIN_CONFIG_MAX_BYTES = 8192
_ADMIN_CONFIG_VALIDATORS = {
    "cx_base_auth_uri": _ADMIN_URL_RE,
    "cx_tenant": _ADMIN_TENANT_RE,
}


def _admin_config_path():
    """Absolute path to the bundled admin onboarding config, relative to THIS file (…/hooks) —
    mirrors _bootstrap_script_path()/_load_min_version(); never uses ${CURSOR_PLUGIN_ROOT} (which is
    empty in the agent shell). Works on every OS via os.path.join."""
    return os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config",
                     "cx-onboarding.properties")
    )


def _load_admin_config(path=None):
    """Read config/cx-onboarding.properties and return ONLY the known, VALIDATED keys as a dict
    (possibly empty). FAIL SOFT: a missing/garbled/oversized/undecodable file, an invalid value, or
    any unexpected error yields {} (no pre-fill). This must NEVER raise — an escaped exception would
    trip _fail_closed_on_crash and brick every tool call — and NEVER block. `path` is a test hook."""
    try:
        if path is None:
            path = _admin_config_path()
        try:
            # utf-8-sig (not plain utf-8): an admin editing this file with Windows Notepad can prepend
            # a UTF-8 BOM, which would otherwise corrupt the first key name (cx_base_auth_uri →
            # ﻿cx_base_auth_uri → silently dropped). utf-8-sig strips a leading BOM and is a no-op
            # when there isn't one.
            with open(path, "r", encoding="utf-8-sig") as f:
                raw = f.read(_ADMIN_CONFIG_MAX_BYTES + 1)
        except (OSError, UnicodeDecodeError):
            return {}
        if len(raw) > _ADMIN_CONFIG_MAX_BYTES:
            return {}  # implausibly large for two values — refuse rather than parse
        result = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _sep, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            validator = _ADMIN_CONFIG_VALIDATORS.get(key)
            if validator is None:
                continue  # unknown key — silently dropped
            if value and validator.match(value):
                result[key] = value
            else:
                _log("admin_config", result="invalid", key=key)
        return result
    except Exception:
        return {}


_OAUTH_BULLET_LEAD = (
    "- Browser sign-in (OAuth) — only if the developer picks this: you may run it yourself "
    "(it opens the developer's browser with MFA; no secret passes through you; it resolves cx "
    "by absolute path so it works before cx is on PATH). "
)


def _oauth_recovery_bullet(cfg, history=None):
    """The 'Browser sign-in (OAuth)' bullet for an auth-recovery deny context."""
    base = cfg.get("cx_base_auth_uri")
    tenant = cfg.get("cx_tenant")
    if base and tenant:
        cmd = _cx_recovery_command_block(
            "auth login --base-auth-uri {0} --tenant {1}".format(base, tenant),
            suppress_stdout=True)
        return _OAUTH_BULLET_LEAD + (
            "The --base-auth-uri and --tenant "
            "below were PRECONFIGURED BY YOUR ADMINISTRATOR (the plugin's "
            "config/cx-onboarding.properties) — use them AS-IS and do NOT ask the developer for a URL "
            "or tenant:" + cmd
        )
    if history is None:
        history = _confirmed_login_pairs()
    if history:
        pairs = "".join(
            "\n    [{0}] {1} @ {2}\n        {3}".format(
                i + 1, t, b,
                _cx_recovery_command_block(
                    "auth login --base-auth-uri {0} --tenant {1}".format(b, t),
                    suppress_stdout=True))
            for i, (b, t) in enumerate(history))
        _log("login_history", action="offered", count=len(history))
        return _OAUTH_BULLET_LEAD + (
            "The environment(s) below were used in an EARLIER `cx auth login` "
            "from this machine and are offered as a shortcut, NOT as verified history — the plugin "
            "infers success from the credential file changing, which a login the developer abandoned "
            "can also produce. Treat each as a suggestion to confirm, never as fact. Most recent "
            "first. Only AFTER OAuth is "
            "chosen, present them with the AskUserQuestion tool — one option per environment, most "
            "recent first; the tool's built-in \"Other\" lets the developer type a different URL + "
            "tenant instead — and do NOT run any login until the developer explicitly picks one "
            "(they may want a different tenant this time). If they pick \"Other\", ask for the "
            "URL/tenant per the cx-cli-setup skill's oauth.md Question 2 (free-text form) — NEVER "
            "guess or default values that are not listed. Ready-to-run command for each:" + pairs
        )
    cmd = _cx_recovery_command_block(
        "auth login --base-auth-uri <url> --tenant <tenant>", suppress_stdout=True)
    return _OAUTH_BULLET_LEAD + (
        "Only AFTER OAuth is chosen, ask for the "
        "URL/tenant — NEVER guess or default the --base-auth-uri or --tenant values (e.g. do not try "
        "'iam.checkmarx.net' or a tenant of 'checkmarx') — ask the developer, per the cx-cli-setup "
        "skill's oauth.md Question 2. Regional URL examples: US https://ast.checkmarx.net, "
        "US2 https://us.ast.checkmarx.net, EU https://eu.ast.checkmarx.net, "
        "ANZ https://anz.ast.checkmarx.net, India https://ind.ast.checkmarx.net, or their on-prem "
        "URL. Full region list + how to find your tenant: " + _CX_ENV_URLS_DOC
        + cmd
    )


# --- OAuth login history (previously used base-URL/tenant pairs) -----------------------------------
_LOGIN_HISTORY_FILE = _state_path("cx_login_history.json")
_LOGIN_HISTORY_MAX = 5
_LOGIN_HISTORY_OFFER_MAX = 3
_LOGIN_HISTORY_MAX_BYTES = 16384
_LOGIN_PENDING_TTL = 3600

_AUTH_LOGIN_RE = re.compile(r"\bauth\s+login\b")
_LOGIN_FLAG_RE = re.compile(
    r'--(base-auth-uri|tenant)(?:=|\s+)(?:"([^"\s]+)"|\'([^\'\s]+)\'|([^\s"\']+))')
_CX_CONFIGURE_SET_RE = re.compile(r"\bconfigure\s+set\b")


def _parse_login_flags(command):
    if not command or not _AUTH_LOGIN_RE.search(command):
        return None
    found = {}
    for m in _LOGIN_FLAG_RE.finditer(command):
        found[m.group(1)] = next(g for g in m.groups()[1:] if g is not None)
    base = found.get("base-auth-uri")
    tenant = found.get("tenant")
    if base is None or tenant is None:
        return None
    if not (_ADMIN_URL_RE.match(base) and _ADMIN_TENANT_RE.match(tenant)):
        return None
    return base, tenant


def _valid_login_entry(entry):
    if not isinstance(entry, dict):
        return None
    url, tenant = entry.get("base_auth_uri"), entry.get("tenant")
    status, last_used, cred = entry.get("status"), entry.get("last_used"), entry.get("cred_before")
    if isinstance(url, str):
        url = url.strip()
    if isinstance(tenant, str):
        tenant = tenant.strip()
    if not (isinstance(url, str) and _ADMIN_URL_RE.fullmatch(url)):
        return None
    if not (isinstance(tenant, str) and _ADMIN_TENANT_RE.fullmatch(tenant)):
        return None
    if status not in ("pending", "confirmed") or not _is_number(last_used):
        return None
    if cred is not None and not _is_number(cred):
        return None
    return {"base_auth_uri": url, "tenant": tenant, "status": status,
            "last_used": last_used, "cred_before": cred}


def _load_login_history(path=None):
    try:
        if path is None:
            path = _LOGIN_HISTORY_FILE
        if not path:
            return []
        raw = _read_capped(path, _LOGIN_HISTORY_MAX_BYTES, encoding="utf-8")
        if raw is None:
            return []
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return []
        version = data.get("version") if isinstance(data, dict) else None
        if version != 1 or isinstance(version, bool):
            return []
        entries = data.get("entries")
        if not isinstance(entries, list):
            return []
        result = [e for e in (_valid_login_entry(entry) for entry in entries) if e is not None]
        if len(result) < len(entries):
            _log("login_history", action="invalid", count=min(len(entries) - len(result), 255))
        result.sort(key=lambda e: e["last_used"], reverse=True)
        return result[:_LOGIN_HISTORY_MAX]
    except Exception:
        return []


def _save_login_history(entries, path=None):
    try:
        if path is None:
            path = _LOGIN_HISTORY_FILE
        if not path:
            return
        entries = entries[:_LOGIN_HISTORY_MAX]
        directory = os.path.dirname(path) or "."
        fd, tmp = tempfile.mkstemp(prefix=".cx_login_history-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json.dumps({"version": 1, "entries": entries}))
            _chmod_600(tmp)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    except Exception:
        pass


def _record_login_attempt(command, path=None):
    try:
        if command and _CX_CONFIGURE_SET_RE.search(command):
            _drop_pending_logins(path)
            return
        parsed = _parse_login_flags(command)
        if parsed is None:
            return
        base, tenant = parsed
        key = (base.lower(), tenant.lower())
        status = "pending"
        entries = []
        for entry in _load_login_history(path):
            if (entry["base_auth_uri"].lower(), entry["tenant"].lower()) == key:
                if entry["status"] == "confirmed":
                    status = "confirmed"
                continue
            entries.append(entry)
        entries.insert(0, {"base_auth_uri": base, "tenant": tenant, "status": status,
                           "last_used": time.time(), "cred_before": _credential_mtime()})
        _save_login_history(entries, path)
        _log("login_history", action="recorded")
    except Exception:
        pass


def _drop_pending_logins(path=None):
    try:
        entries = _load_login_history(path)
        kept = [e for e in entries if e["status"] != "pending"]
        if len(kept) != len(entries):
            _save_login_history(kept, path)
            _log("login_history", action="pruned", count=len(entries) - len(kept))
    except Exception:
        pass


def _promote_pending_login(path=None):
    try:
        if path is None:
            path = _LOGIN_HISTORY_FILE
        if not path or not os.path.exists(path):
            return
        entries = _load_login_history(path)
        if not any(e["status"] == "pending" for e in entries):
            return
        cred = _credential_mtime()
        now = time.time()
        kept = []
        promoted = False
        for entry in entries:
            if entry["status"] != "pending":
                kept.append(entry)
            elif not promoted and cred is not None and cred != entry.get("cred_before"):
                kept.append(dict(entry, status="confirmed", last_used=now))
                promoted = True
            elif not promoted and (now - entry["last_used"]) <= _LOGIN_PENDING_TTL:
                kept.append(entry)
        if promoted or len(kept) != len(entries):
            _save_login_history(kept, path)
            _log("login_history", action="promoted" if promoted else "pruned")
    except Exception:
        pass


def _confirmed_login_pairs(path=None):
    try:
        confirmed = [(e["base_auth_uri"], e["tenant"])
                     for e in _load_login_history(path) if e["status"] == "confirmed"]
        return confirmed[:_LOGIN_HISTORY_OFFER_MAX]
    except Exception:
        return []


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
# `cx mcp bridge` / `cx hooks cursor-*`). The real gate is whether those subcommands exist,
# so probe them with --help (local, no network). All must exit 0 to count as capable.
# Probe EVERY cx subcommand the hooks wiring actually invokes (MCP bridge + Cursor hook
# subcommands), not just two — otherwise a partial build passes the gate then a missing
# scanner exits non-blocking and the action goes UNSCANNED.
_CURSOR_CAPABILITY_PROBES = (
    ("mcp", "bridge", "--help"),
    ("hooks", "cursor-before-file-write", "--help"),
    ("hooks", "cursor-stop", "--help"),
)

# Per-invocation context set at the top of cx_check(). This gate is Cursor-only and only ever
# runs for the preToolUse hook, so "agent" is always "cursor" and there is no longer a
# post-hook/blocking-hook distinction to track (that only mattered when this gate also ran for
# postToolUse/afterFileEdit, which the plugin no longer wires).
_GATE_CTX = {"agent": "cursor"}


# Cursor's native beforeShellExecution hook carries "command" at the TOP LEVEL (not inside
# tool_input). Some Cursor / CLI builds also OMIT hook_event_name and send only {command, cwd,
# sandbox} per the public hooks spec — treating hook_event_name as mandatory silently broke every
# carve-out (bootstrap, auth login, cx version) on those builds. beforeMCPExecution is NOT a shell
# event even though it may carry a top-level "command" (MCP server spawn string).
_BEFORE_SHELL_EVENT = "beforeShellExecution"
_BEFORE_MCP_EVENT = "beforeMCPExecution"
# Kept for comments/tests that refer to the pair; shell parsing must use _is_before_shell_payload().
_NATIVE_SHELL_EVENTS = (_BEFORE_SHELL_EVENT, _BEFORE_MCP_EVENT)


def _is_before_shell_payload(hook_input):
    """True when hook_input is a shell-command gate payload (beforeShellExecution or preToolUse
    Shell), in any spelling Cursor IDE or Cursor CLI may emit."""
    if not isinstance(hook_input, dict):
        return False
    if hook_input.get("tool_name") == "Shell":
        return True
    if hook_input.get("hook_event_name") == _BEFORE_SHELL_EVENT:
        return True
    if hook_input.get("hook_event_name") == _BEFORE_MCP_EVENT:
        return False
    # preToolUse non-Shell tools must not be treated as shell even if a stray top-level command exists.
    if hook_input.get("tool_name") and hook_input.get("tool_name") != "Shell":
        return False
    if isinstance(hook_input.get("tool_input"), dict) and hook_input.get("tool_name"):
        return False
    command = hook_input.get("command")
    if isinstance(command, str) and command.strip():
        # Minimal beforeShellExecution shape from Cursor docs: command + cwd|sandbox, no hook_event_name.
        if "cwd" in hook_input or "sandbox" in hook_input:
            return True
    return False


def _effective_tool(hook_input, agent):
    tool = hook_input.get("tool_name")
    if tool:
        return tool
    if _is_before_shell_payload(hook_input):
        return "Shell"
    return ""


def _shell_command(hook_input, agent):
    """Shell command string for either shape Cursor sends: native beforeShellExecution (top-level
    command, with or without hook_event_name), or preToolUse Shell-tool (tool_input.command)."""
    if hook_input.get("tool_name") == "Shell":
        tool_input = hook_input.get("tool_input")
        command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
        if isinstance(command, str) and command.strip():
            return command
    if _is_before_shell_payload(hook_input):
        command = hook_input.get("command", "")
        if isinstance(command, str) and command.strip():
            return command
    return ""


def _capabilities_present(agent=None):
    """True iff every required cx subcommand responds to --help with exit 0. Any non-zero
    exit, missing subcommand, timeout, or spawn error → False (fail-closed). Each probe is
    `--help` only — purely local, no network — so a tight 3s timeout is ample; keeping it
    tight bounds the gate's worst-case latency under the hooks.json hook timeout."""
    exe = _cx_exe()
    for probe in _CURSOR_CAPABILITY_PROBES:
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
    subcommands (`cx mcp bridge` / `cx hooks cursor-*`) is 'incapable' — the real gate, since
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


_PROBE_LOCK_TIMEOUT = 8.0   # seconds a cache-miss will wait for another invocation's probe
_PROBE_LOCK_POLL = 0.2


def _lock_path(cache_file):
    if not cache_file:
        return None
    return os.path.normpath(cache_file + ".lock")


def _acquire_probe_lock(lock_file, timeout=_PROBE_LOCK_TIMEOUT, poll=_PROBE_LOCK_POLL):
    """Best-effort mutual exclusion around a cache-miss so a BATCH of concurrent gate invocations
    (several Write/Edit calls Cursor fires at once, each hitting this hook independently) do not
    all spawn the SAME expensive `cx version` / `cx auth validate` / `cx hooks check-auth`
    subprocess simultaneously. Under load that stampede is exactly what turns one ~1-3s probe into
    several competing for CPU/network, any one of which can then blow ITS OWN hooks.json timeout —
    a hook-CHAIN failure (cx_check.sh exiting non-2), not a real policy decision on the file's
    content. Uses an atomic O_CREAT|O_EXCL lock file as the mutex, restricted to 0600 immediately
    after creation (before any other process could plausibly open it). A lock older than `timeout`
    is presumed to belong to a holder that crashed/was killed and is stolen — checked with isfile()
    first, and the unlink's own OSError is still swallowed for the race where a concurrent release
    wins first — rather than honored, so a stuck lock file can never wedge the gate. Returns an fd
    to pass to _release_probe_lock, or None if the lock could not be acquired in time — the caller
    then probes anyway (this is purely a stampede optimization; it must never itself become a
    source of blocking or fail-open)."""
    if not lock_file:
        return None
    lock_file = os.path.normpath(lock_file)
    deadline = time.time() + timeout
    while True:
        try:
            fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            fd = None
        except OSError:
            return None
        if fd is not None:
            _chmod_600(lock_file)
            return fd
        try:
            if (time.time() - os.path.getmtime(lock_file)) > timeout and os.path.isfile(lock_file):
                try:
                    os.unlink(lock_file)  # stale — previous holder crashed/was killed
                except OSError:
                    pass
                continue
        except OSError:
            pass
        if time.time() >= deadline:
            return None
        time.sleep(poll)


def _release_probe_lock(lock_file, lock_fd):
    if lock_fd is None:
        return
    try:
        os.close(lock_fd)
    except OSError:
        pass
    if not lock_file:
        return
    lock_file = os.path.normpath(lock_file)
    if os.path.isfile(lock_file):
        try:
            os.unlink(lock_file)
        except OSError:
            pass


def _cached_probe(cache_file, ttl, key, probe, should_cache):
    """Memoize probe() to `cache_file` for `ttl` seconds, keyed on the dict `key` (the resolved-binary
    identity plus any extra invalidators — min version, credential mtime). A cached value is reused
    ONLY while every `key` field still matches and its timestamp is within `ttl`; and ONLY results for
    which should_cache(result) is True are ever written — so a failing/pass-through probe can never be
    masked (the fail-open a stale positive would cause). A falsy `cache_file` (no private state dir)
    disables caching — re-probe every call. Never raises: any I/O or decode error falls through to a
    live probe (fail-safe). This is the single home for the gate's version/auth/scanner caching.

    A cache MISS is additionally serialized via _acquire_probe_lock (see its docstring): without
    this, a batch of concurrent invocations landing on a cold/expired cache all spawn the same
    subprocess at once, and the resulting contention is a common cause of an otherwise-healthy
    invocation timing out. The lock is best-effort only — an unavailable lock just means this one
    call probes live, exactly as before this fix existed."""

    def _load():
        if not cache_file:
            return None
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
        return None

    hit = _load()
    if hit is not None:
        return hit

    lock_file = _lock_path(cache_file)
    lock_fd = _acquire_probe_lock(lock_file)
    try:
        # Re-check: another invocation may have populated the cache while this one waited for the
        # lock (or the lock was unavailable and we're racing it anyway) — the double-check is what
        # actually avoids the redundant spawn, not merely holding the lock.
        hit = _load()
        if hit is not None:
            return hit
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
    finally:
        _release_probe_lock(lock_file, lock_fd)


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
# `cx hooks cursor-*` authenticates ONLY by extracting a Checkmarx API key, and when it cannot it
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
    """Fallback for a cx that predates `cx hooks check-auth`: run a benign hook probe and inspect stderr.
    A hook only INSPECTS proposed/post content — benign payloads yield no finding. Returns
    _SCANNER_PASSTHROUGH when unauthenticated, _SCANNER_SCAN when it ran, _SCANNER_UNKNOWN on error."""
    probe_path = _state_path("cx_scanner_probe.txt") or os.path.join(
        tempfile.gettempdir(), "cx_scanner_probe.txt")
    payload = json.dumps({
        "conversation_id": "cx-probe",
        "hook_event_name": "postToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": probe_path},
        "cwd": os.getcwd(),
    }).encode("utf-8")
    route = ["hooks", "cursor-after-file-edit", "--debug"]
    try:
        result = subprocess.run(
            [_cx_exe(), *route],
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


def _deny(reason: str, context: str, *, reason_code=None, tool_name=None, version_state=None) -> None:
    _log("gate_decision", decision="deny", reason_code=reason_code, tool_name=tool_name,
         version_state=version_state, exit_code=2)
    agent_msg = _deny_agent_message(context or reason)
    print(json.dumps({
        "permission": "deny",
        "user_message": reason,
        "agent_message": agent_msg,
        # Mirrors agent_message verbatim. Cursor's preToolUse response surfaces additional_context
        # to the agent; agent_message alone was NOT reliably reaching the agent's context, which is
        # why the MANDATORY recovery instructions (the bootstrap command, auth guidance, …) were
        # silently dropped and the agent never actually saw them. Keep both in sync — never let
        # this drift from agent_message.
        "additional_context": agent_msg,
    }))
    sys.exit(2)


_DENY_AGENT_PREFIX = (
    "CHECKMARX_HOOK_DENY — MANDATORY agent_message "
    "(follow exactly; cx-hook-deny rule applies):\n\n"
    "Do not bypass the scan by writing the same content through another tool or shell command.\n\n"
)


def _deny_agent_message(context: str) -> str:
    if not context:
        return _DENY_AGENT_PREFIX
    if context.startswith(_DENY_AGENT_PREFIX):
        return context
    return _DENY_AGENT_PREFIX + context


def _allow(*, reason_code="ok", tool_name=None, version_state=None, context="") -> None:
    """Emit explicit allow JSON on stdout. Required for failClosed hooks: empty stdout is
    treated as a hook failure and misattributes stage-2 scanner denies to stage-1."""
    _log("gate_decision", decision="allow", reason_code=reason_code, tool_name=tool_name,
         version_state=version_state, exit_code=0)
    if context:
        # additional_context mirrors agent_message verbatim — see _deny()'s comment for why.
        print(json.dumps({"permission": "allow", "agent_message": context, "additional_context": context}))
    else:
        print(json.dumps({"permission": "allow"}))
    sys.exit(0)


def _allow_with_warning(context: str, *, reason_code=None, tool_name=None) -> None:
    _allow(reason_code=reason_code or "allow_with_warning", tool_name=tool_name, context=context)


def _read_hook_input():
    """Parse the Cursor hook JSON sent on stdin (preToolUse and native beforeShellExecution /
    beforeMCPExecution). Returns {} on any problem (no stdin / empty / non-JSON) so the normal
    gate still runs fail-closed.

    Reads RAW BYTES (sys.stdin.buffer), not sys.stdin.read(), and decodes explicitly trying
    utf-8-sig before utf-16: some Windows callers (PowerShell's default redirect encoding is
    UTF-16LE; a UTF-8 BOM is also common from Windows tooling) prepend a byte-order mark or use
    a wide encoding. PYTHONUTF8=1 makes sys.stdin a plain 'utf-8' TextIOWrapper, which does NOT
    strip a leading BOM — a stray U+FEFF before the '{' makes json.loads raise, _read_hook_input
    silently returns {}, and EVERY carve-out below (auth-recovery, bootstrap, read-only, …) then
    fails to match on an hook_input that looks empty. The gate still runs (fail-closed is
    preserved) but falls through to the generic cx-state deny — which denied `cx auth login`
    itself with a generic "not authenticated" message that had nothing to do with the actual
    command, a real deadlock observed in production. 'utf-8-sig' decodes plain UTF-8 identically
    to 'utf-8' when no BOM is present, so this never changes behavior for the common case."""
    try:
        if sys.stdin.isatty():
            return {}
        raw = sys.stdin.buffer.read()
    except (OSError, ValueError, AttributeError):
        return {}
    if not raw or not raw.strip():
        return {}
    text = None
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            text = raw.decode(encoding)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    if text is None or not text.strip():
        return {}
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


# Shell-syntax handling (wrapper unwrapping, variable expansion, chaining/redirect checks, leading
# token parsing) lives ENTIRELY in hooks/cx_shell.py — one implementation shared by this gate and, via
# the --match-trusted-setup CLI below, by hooks/_cx_bootstrap_match.sh. The thin wrappers here keep the
# original names (and their behaviour) so the gate's own logic and its tests read unchanged.
def _has_unsafe_redirect(command):
    """True if the command contains a redirect to anything OTHER than a null device. A redirect to a
    real file could exfiltrate a command's stdout (e.g. the live token `cx auth login` prints) to an
    attacker-chosen path. The sanctioned `1>/dev/null` / `1>$null` / `1>NUL` suppression stays
    allowed; any residual `>`/`<` after stripping the exact null-device redirects is unsafe."""
    return cx_shell.has_unsafe_redirect(command)


def _unwrap_shell_wrappers(command):
    """Reduce a raw agent command to a bare one: peel the bash/sh -c, cmd /c and PowerShell -Command
    wrappers Cursor adds for shell interpretation, strip the leading `&` call operator PowerShell
    requires to invoke a quoted/absolute path, and expand `%VAR%` / `$env:VAR` / `${VAR}` / `$VAR` /
    `~` so a symbolically-written cx path still compares equal to the resolved absolute path.

    Expansion cannot loosen the gate: the expanded string is what the chaining/redirect checks below
    then scan, so a variable whose value smuggles a metacharacter (`$env:Path` contains `;` on
    Windows) is rejected exactly as a literal one is, and an UNKNOWN variable stays literal and fails
    the trusted-path comparison."""
    return cx_shell.normalize(command)[0]


def _bare_bash_command(hook_input):
    """The shell command string IFF it is a single BARE command safe to consider for an allow carve-out:
    a Shell tool call, with NO shell chaining/substitution (cx_shell.CHAINING_TOKENS) and
    NO unsafe redirect (_has_unsafe_redirect). Returns None otherwise."""
    command = _shell_command(hook_input, _GATE_CTX.get("agent"))
    if not command:
        return None
    command = _unwrap_shell_wrappers(command)
    if cx_shell.has_chaining(command):
        return None
    if _has_unsafe_redirect(command):
        return None
    return command


def _matches_bare_or_resolved_cx_subcommand(command, subcommand_pattern):
    """True iff `command` is `cx <subcommand_pattern>` (bare, for a session where cx is on PATH) OR
    `"<resolved cx>" <subcommand_pattern>` (the absolute-path form deny messages emit before cx is on
    PATH). `subcommand_pattern` is a regex fragment matched right after the executable token (e.g.
    r"(?:auth|configure)\\b"). The absolute form is pinned to a path in _resolved_cx_candidates()
    (canonical store, CX_BINARY, _cx_exe) — never an attacker-chosen path. Shared by every narrow "let cx's own CLI commands through the gate"
    carve-out (auth/configure recovery, setup diagnostics) so they can't drift apart on this matching.

    The leading-token comparison goes through `_normalize_path` (not a raw string/regex match) so a
    Git-Bash-style POSIX path (`/c/Users/.../cx.exe`, what `bash`'s own path resolution naturally
    produces) still matches the SAME file as Python's native `C:\\Users\\...\\cx.exe` rendering of
    `_cx_exe()` — without it, the agent's own bash-resolved cx path silently failed to match and this
    carve-out never fired, exactly as with the bootstrap path (see _normalize_path).

    Token extraction is cx_shell.leading_token(), so ALL THREE quoting styles a shell may use for the
    path count: `"…"` (bash/cmd/PowerShell), `'…'` (PowerShell's literal form — previously
    unrecognized, which denied every single-quoted `& 'C:\\…\\cx.exe' auth login`), and bare."""
    if re.match(r"^\s*cx(?:\s+--%)?\s+" + subcommand_pattern, command):
        return True
    leading, rest = cx_shell.leading_token(command)
    if leading is None or leading == "cx":
        return False
    rest = cx_shell.strip_stop_parsing_flag(rest)
    if not re.match(r"^\s+" + subcommand_pattern, rest):
        return False
    return _is_trusted_cx_exe_path(leading)


def _is_auth_recovery_command(hook_input, absolute_path_only=False):
    """True for a credential-recovery / session-validation command (`cx auth …`, `cx configure …`,
    `cx hooks check-auth` — see _AUTH_RECOVERY_SUBCOMMANDS) that passes the shared bare-command guard.
    These must run even when unauthenticated so the auth gate never blocks the command that FIXES
    auth. Accepts the BARE form (`cx auth …`, for later sessions / manual install where cx is on PATH)
    AND the resolved ABSOLUTE-path form the deny messages emit (`"<cx>" auth …`) so cx resolves on a
    first-install session before it is on PATH — in any of the shells' spellings, since
    _bare_bash_command() normalizes wrappers, the PowerShell call operator, quoting style and
    variable references first.

    When absolute_path_only=True (early gate, before cx_absent), only the quoted/absolute-path form is
    accepted and the pinned binary must exist on disk."""
    command = _bare_bash_command(hook_input)
    if command is None:
        return False
    if not _matches_bare_or_resolved_cx_subcommand(command, _AUTH_RECOVERY_SUBCOMMANDS):
        return False
    if not absolute_path_only:
        return True
    leading, _rest = cx_shell.leading_token(command)
    if leading is None or leading == "cx":
        return False
    return _is_trusted_cx_exe_path(leading)


def _bare_ignore_vulnerability_command(hook_input):
    """Like _bare_bash_command(), but the chaining/redirect safety check runs on the command's
    quote-stripped SKELETON (cx_shell.command_skeleton, via has_chaining_outside_quotes /
    has_unsafe_redirect_outside_quotes) instead of the raw string. A real
    `cx ignore-vulnerability --data "<json>"` / `--optional-flags "k=v;k=v"` command legitimately
    contains `;`/`%`/etc. INSIDE its safely-quoted argument values, which the naive, raw-string
    CHAINING_TOKENS scan every OTHER carve-out uses cannot tell apart from actual shell chaining —
    using the same check here would mean this carve-out could never match a real invocation. Every
    other carve-out keeps calling the plain _bare_bash_command() unchanged; this does not affect
    them."""
    command = _shell_command(hook_input, _GATE_CTX.get("agent"))
    if not command:
        return None
    command = _unwrap_shell_wrappers(command)
    if cx_shell.has_chaining_outside_quotes(command):
        return None
    if cx_shell.has_unsafe_redirect_outside_quotes(command):
        return None
    return command


def _is_ignore_vulnerability_command(hook_input):
    """True for a `cx ignore-vulnerability ...` Shell command (bare, for a session where cx is on
    PATH, or the resolved absolute-path form) that passes the quote-aware bare-command guard above.
    See _IGNORE_VULN_RE's comment for why this is a Stage-2 (hooks/cx_run.sh) reliability carve-out
    only, and is intentionally not called from cx_check() itself."""
    command = _bare_ignore_vulnerability_command(hook_input)
    if command is None:
        return False
    return _matches_bare_or_resolved_cx_subcommand(command, _IGNORE_VULN_SUBCOMMAND)


# Prep commands that create `.checkmarx/` or write a finding JSON there before `ignore-vulnerability`
# runs with @file syntax. Stage-2 reliability carve-out only (same rationale as ignore-vulnerability).
_CHECKMARX_PREP_CMDLETS = ("new-item", "set-content", "mkdir", "md")


def _strip_safe_out_null_suffix(command):
    """Remove a trailing `| Out-Null` PowerShell stdout suppression — safe for prep carve-outs."""
    if not isinstance(command, str):
        return command
    return re.sub(r"\s*\|\s*Out-Null\s*;?\s*$", "", command, flags=re.IGNORECASE).strip()


def _bare_checkmarx_ignore_prep_command(hook_input):
    """Like _bare_ignore_vulnerability_command(), but for `.checkmarx` directory/file prep only.

    Allows `New-Item … .checkmarx … | Out-Null` and `Set-Content … .checkmarx/…` — prerequisites
    for the @file ignore-vulnerability flow. Rejects anything that does not reference `.checkmarx` or
    whose primary cmdlet is not a directory-create / file-write."""
    command = _shell_command(hook_input, _GATE_CTX.get("agent"))
    if not command:
        return None
    command = _unwrap_shell_wrappers(command)
    if not re.search(r"\.checkmarx", command, re.IGNORECASE):
        return None
    work = _strip_safe_out_null_suffix(command)
    if cx_shell.has_chaining_outside_quotes(work):
        return None
    if cx_shell.has_unsafe_redirect_outside_quotes(work):
        return None
    tokens = work.split()
    if not tokens:
        return None
    if tokens[0].lower() not in _CHECKMARX_PREP_CMDLETS:
        return None
    return command


def _is_checkmarx_ignore_prep_command(hook_input):
    """True for a bare `.checkmarx` prep command (New-Item / Set-Content / mkdir) — see above."""
    return _bare_checkmarx_ignore_prep_command(hook_input) is not None


# `cx version` / `cx utils env` are read-only diagnostics with NO side effects — they can't write
# code, run a scan, or change credentials — so cx-cli-setup can use them to detect current state
# (installed? capable? configured?) without tripping the fail-closed gate. Without this carve-out
# Phase 1a's `cx version` verification step and Phase 4's `cx utils env` check are themselves blocked
# by the very gate they exist to probe, forcing every setup session through a confusing deny instead
# of the plain "command not found" / real version the skill is written to expect.
_SETUP_DIAGNOSTIC_RE = r"(?:version|utils\s+env)\s*$"


def _is_setup_diagnostic_command(hook_input, tool):
    """True for a bare `cx version` / `cx utils env` Shell command (or its resolved-absolute-path
    form) — see _SETUP_DIAGNOSTIC_RE. Shell tool only; opt out with CX_GATE_ALL_COMMANDS=1 like the
    read-only carve-out, since (unlike auth recovery) this one isn't needed to escape a deadlock —
    it only removes setup noise."""
    if tool not in ("Shell",):
        return False
    if os.environ.get("CX_GATE_ALL_COMMANDS") == "1":
        return False
    command = _bare_bash_command(hook_input)
    if command is None:
        return False
    return _matches_bare_or_resolved_cx_subcommand(command, _SETUP_DIAGNOSTIC_RE)


def _is_bootstrap_command(hook_input):
    """True only for a bare `bash "<bootstrap>" <install|upgrade>` Shell command where <bootstrap>
    resolves to THIS plugin's own scripts/cx-bootstrap.sh — the single escape hatch from the
    fail-closed block. Independent defenses: Shell-only, no shell chaining, a REQUIRED install/
    upgrade mode (shape), and a path that must equal the bundled bootstrap. The literal
    ${CURSOR_PLUGIN_ROOT}/${CX_PLUGIN_ROOT} placeholders (which the agent's shell does NOT expand)
    are honored only after expanding them from the gate's own environment and proving they resolve
    to the bundled bootstrap — never blessed blindly."""
    command = _bare_bash_command(hook_input)
    if command is None:
        return False
    m = _BOOTSTRAP_RE.match(command)
    if not m:
        return False
    raw_path = _matched_path(m)
    if raw_path is None:
        return False
    if raw_path == "${CX_PLUGIN_ROOT}/scripts/cx-bootstrap.sh":
        root = os.environ.get("CX_PLUGIN_ROOT") or _plugin_root_from_script_dir()
        if not root:
            return False
        raw_path = os.path.join(root, "scripts", "cx-bootstrap.sh")
    elif raw_path == "${CURSOR_PLUGIN_ROOT}/scripts/cx-bootstrap.sh":
        root = os.environ.get("CURSOR_PLUGIN_ROOT") or _plugin_root_from_script_dir()
        if not root:
            return False
        raw_path = os.path.join(root, "scripts", "cx-bootstrap.sh")
    return _bootstrap_path_matches(raw_path)


_PLUGIN_SCRIPT_RE = re.compile(
    r"""^\s*(?:bash|sh)\s+(?:"(?P<path>[^"]+)"|'(?P<spath>[^']+)'|(?P<upath>\S+))(?:\s+.*)?$""")


def _matched_path(match):
    """The script path from a `bash`/`sh` invocation regex, whichever of the three quoting
    alternatives (`"…"`, `'…'`, bare) actually matched. One helper for both _BOOTSTRAP_RE and
    _PLUGIN_SCRIPT_RE so the two cannot disagree about which spellings are accepted — an agent
    driving PowerShell quotes with `'`, one driving bash with `"`, and either may omit quotes when
    the path has no spaces."""
    for group in ("path", "spath", "upath"):
        value = match.groupdict().get(group)
        if value:
            return value.strip()
    return None


def _expand_plugin_root_placeholder(raw_path):
    """Expand a literal ${CX_PLUGIN_ROOT}/${CURSOR_PLUGIN_ROOT} prefix (which the agent's OWN shell
    does NOT expand — those variables are only injected into the hook's own execution) from the
    gate's own environment, mirroring _is_bootstrap_command. Returns raw_path unchanged if it does
    not start with either placeholder; returns None if the placeholder can't be resolved."""
    for var in ("CX_PLUGIN_ROOT", "CURSOR_PLUGIN_ROOT"):
        prefix = "${%s}" % var
        if raw_path.startswith(prefix):
            root = os.environ.get(var) or _plugin_root_from_script_dir()
            if not root:
                return None
            return os.path.join(root, raw_path[len(prefix):].lstrip("/\\"))
    return raw_path


def _is_plugin_script_command(hook_input):
    """True for a bare `bash`/`sh` invocation of ANY script physically located inside THIS plugin's
    own directory tree (/plugins/cursor-devassist/**) — broader than the narrow cx-bootstrap.sh
    install/upgrade shape _is_bootstrap_command matches (which stays in place as the most-tested
    carve-out for that one script). The plugin's bundled scripts (scripts/*.sh, and this hooks/
    directory's own *.sh) are first-party, SHIPPED content — not agent- or user-authored — so an
    attacker able to alter them has already achieved local code execution the gate cannot prevent
    anyway; gating THEIR execution buys no real security and only breaks legitimate cx-cli-setup
    workflows (e.g. running scripts/cx-asset-resolver.sh or scripts/cx-path-probe.sh standalone, per
    references/manual-install.md). Still requires a BARE command (no chaining/unsafe redirect, via
    _bare_bash_command) and a path that resolves INSIDE the plugin root — a script anywhere else on
    disk is NOT covered."""
    command = _bare_bash_command(hook_input)
    if command is None:
        return False
    m = _PLUGIN_SCRIPT_RE.match(command)
    if not m:
        return False
    matched = _matched_path(m)
    if matched is None:
        return False
    raw_path = _expand_plugin_root_placeholder(matched)
    if not raw_path:
        return False
    candidate = _normalize_path(raw_path)
    if candidate is None:
        return False
    for root in _plugin_root_candidates():
        root_norm = _normalize_path(root)
        if root_norm is None:
            continue
        if candidate == root_norm or candidate.startswith(root_norm + "/"):
            return True
        # Same directory via realpath/symlink (e.g. .cursor/plugins/local → elsewhere).
        try:
            candidate_real = os.path.normpath(os.path.realpath(raw_path))
            root_real = os.path.normpath(os.path.realpath(root))
            c_norm = _normalize_path(candidate_real)
            r_norm = _normalize_path(root_real)
            if c_norm is not None and r_norm is not None and (
                c_norm == r_norm or c_norm.startswith(r_norm + "/")
            ):
                return True
        except (OSError, ValueError):
            continue
    return False


def _is_readonly_command(hook_input, tool):
    """True for a BARE shell command whose first token is a known read-only program (_READONLY_COMMANDS)
    — safe to run without the cx gate. Shell tool only; opt out with CX_GATE_ALL_COMMANDS=1. The
    comparison is case-insensitive and honors quoting, because PowerShell cmdlet names and cmd
    builtins are case-insensitive and an agent may write `'Get-Command' cx`."""
    if tool not in ("Shell",):
        return False
    if os.environ.get("CX_GATE_ALL_COMMANDS") == "1":
        return False
    command = _bare_bash_command(hook_input)
    if not command:
        return False
    leading, _rest = cx_shell.leading_token(command)
    return bool(leading) and leading.lower() in _READONLY_COMMANDS


def cx_check():
    hook_input = _read_hook_input()
    tool = _effective_tool(hook_input, _GATE_CTX["agent"])

    # Record which shell the agent is driving, inferred from the command it proposed (a
    # `powershell -Command …` / `cmd /c …` / `bash -c …` wrapper is first-hand evidence). Every
    # command this gate later embeds in a deny is then rendered for THAT shell first — a quoted
    # absolute path with no `&` is a string expression in PowerShell, not a command, so a bash-only
    # rendering silently does nothing there. See _cx_recovery_command_block.
    _GATE_CTX["shell"] = cx_shell.detect_shell(
        _shell_command(hook_input, _GATE_CTX["agent"]) or None)

    # 0. Auth recovery MUST precede everything else — including the unauthenticated gate below.
    # cx_run.sh often allows the same OAuth line via its native scanner; cx_check must never deny it.
    if _is_auth_recovery_command(hook_input):
        _allow(reason_code="auth_recovery", tool_name=tool)

    # 1. The bootstrap is the ONLY way out of the block — must be checked first.
    if _is_bootstrap_command(hook_input):
        _allow(reason_code="bootstrap", tool_name=tool)

    # 1.5 Any OTHER script physically located inside this plugin's own directory tree is likewise
    #     first-party trusted content — broader than the narrow bootstrap shape above, covering the
    #     setup skill's other bundled helper scripts too (see _is_plugin_script_command).
    if _is_plugin_script_command(hook_input):
        _allow(reason_code="plugin_script", tool_name=tool)

    # 1.8 Auth recovery — duplicate guard (step 0 already returned for auth/configure); kept so
    #     refactors cannot accidentally move the auth gate above this carve-out again.
    if _is_auth_recovery_command(hook_input):
        _allow(reason_code="auth_recovery", tool_name=tool)

    # 2. Read-only Bash commands (ls, cat, grep, …) can't write code to disk or run another program,
    #     so there is nothing to scan — allow them WITHOUT requiring cx to be installed/authed. Removes
    #     the friction of gating a plain `ls` during setup. Allowlisted + shape-guarded so it can't be
    #     used to smuggle a write/exec (`ls; rm …`, `cat $(…)`, `> file` are all rejected).
    if _is_readonly_command(hook_input, tool):
        _allow(reason_code="read_only", tool_name=tool)

    # 2.5 `cx version` / `cx utils env` — read-only cx diagnostics with no side effects, used by the
    #     cx-cli-setup skill to detect current state (installed? capable? configured?) BEFORE the gate
    #     itself can pass. Let them through so the skill sees cx's own real output (a version string,
    #     or the shell's own "command not found") instead of the gate's fail-closed deny.
    if _is_setup_diagnostic_command(hook_input, tool):
        _allow(reason_code="setup_diagnostic", tool_name=tool)

    # 2b. Files no Checkmarx engine can scan are not worth gating — restore with CX_GATE_ALL_FILES=1.
    if not _is_scannable_file(hook_input):
        _allow(reason_code="unscannable_file", tool_name=tool)

    # 2.6 CX_BINARY override: validate before trusting it. A set-but-invalid value fails CLOSED
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
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is not installed. Security scanning cannot run, so this "
                "operation is BLOCKED. Install it, then retry."
            ),
            context=(
                "cx CLI is not installed on this machine (not found via CX_BINARY, the canonical "
                "store, or PATH). Scannable file writes and Checkmarx MCP calls are blocked "
                "fail-closed until it is installed and authenticated. To self-install now, run the "
                "plugin's bundled bootstrap by its resolved absolute path (its directory is empty in "
                "${CURSOR_PLUGIN_ROOT} in your shell, so use this literal command):\n    "
                + _bootstrap_command_str("install")
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
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is older than the required v{0} and cannot run the scanner "
                "or the remediation MCP. This operation is BLOCKED until cx is upgraded.".format(min_ver)
            ),
            context=(
                "cx is below the minimum supported version (v{0}). All agent actions are blocked "
                "fail-closed — including `cx auth login`, which this old build may not support — until "
                "cx is upgraded. To self-upgrade now, run "
                "the plugin's bundled bootstrap by its resolved absolute path:\n    {1}{2}".format(
                    min_ver, _bootstrap_command_str("upgrade"), _cx_binary_pin_note(effective_tier)
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
                "or a hung process). All agent actions are blocked fail-closed. "
                "To reinstall now, run the plugin's bundled bootstrap by its resolved absolute path:\n    "
                + _bootstrap_command_str("install")
                + _cx_binary_pin_note(effective_tier)
            ),
            reason_code="unrunnable",
            tool_name=tool,
            version_state="unrunnable",
        )
    if state == "incapable":
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is installed but MISSING the security-scanner subcommands "
                "(cx mcp bridge / cx hooks cursor-*). This build cannot run the gate, and re-running "
                "install/upgrade will only re-fetch the same incapable build — so this operation is "
                "BLOCKED and cannot be unblocked from here."
            ),
            context=(
                "cx ran `cx version` but the `cx mcp bridge` / `cx hooks cursor-*` capability probes "
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
                    "then retry the ORIGINAL operation. You may confirm readiness once with:"
                    + _cx_recovery_command_block("auth validate")
                    + "\nAll agent actions remain blocked fail-closed until validate succeeds."
                ),
                reason_code="auth_pending_fresh_login",
                tool_name=tool,
                version_state=state,
            )
        _deny(
            reason=(
                "The Checkmarx CLI (cx) could not authenticate to Checkmarx One. If you JUST signed in, "
                "the backend may have been slow — retry the operation once. Otherwise (re)authenticate, "
                "then retry."
            ),
            context=(
                "cx auth validate did not succeed within the gate's timeout — cx is either not "
                "authenticated (credentials missing or expired) OR the backend was slow/unreachable, so "
                "a valid session that simply timed out looks the same here. Retry once; if it persists, "
                "authenticate cx. ASK THE DEVELOPER WHICH METHOD FIRST — do not "
                "assume OAuth and do not ask for a URL/tenant before this choice is made. There are two "
                "ways to authenticate, and they differ in who runs them:\n"
                "- API key (ask this first / simplest): the DEVELOPER runs this in their own terminal "
                "(it is a plaintext secret — do not type an API key yourself):"
                + _cx_recovery_command_block("configure set --prop-name cx_apikey --prop-value <key>")
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

    # Auth verified — promote a recorded `cx auth login` pair when credentials changed.
    _promote_pending_login()

    # 6b. Scanner readiness. `cx auth validate` (step 6) and the native scanner authenticate
    #     DIFFERENTLY: validate accepts an OAuth refresh token, but `cx hooks cursor-*` only
    #     extracts an API key and otherwise runs in SILENT PASS-THROUGH (allow everything, NO scan).
    #     A validate-OK-but-scanner-pass-through state is therefore a silent fail-OPEN — exactly the
    #     gap an OAuth `cx auth login` opens. Treat it as NOT authenticated for scanning and fail
    #     CLOSED with the same visible deny message. UNKNOWN (probe error/timeout) defers to
    #     the real stage-2 scanner — no worse than before — so a flaky probe can't over-block a
    #     genuinely-authenticated user. (Carve-outs in steps 1/1.8/2 already returned, so the bootstrap,
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
                "allow everything UNSCANNED. Re-authenticate cx. "
                "ASK THE DEVELOPER WHICH METHOD FIRST — do not assume OAuth and do not ask for a "
                "URL/tenant before this choice is made.\n"
                "- API key (ask this first / simplest): the DEVELOPER runs this in their own terminal "
                "(do not type an API key yourself):"
                + _cx_recovery_command_block("configure set --prop-name cx_apikey --prop-value <key>")
                + "\n" + _oauth_recovery_bullet(_load_admin_config())
                + "\nOnly `cx auth …` / `cx configure …` commands run until the scanner is authenticated."
            ),
            reason_code="scanner_passthrough",
            tool_name=tool,
            version_state=state,
        )

    # cx is installed, recent enough, authenticated, and the scanner WILL actually scan.
    _allow(reason_code="ok", tool_name=tool, version_state=state)


def _fail_closed_on_crash(detail=None):
    """Last-resort deny printed if the gate itself crashes. A fail-CLOSED guard: an unexpected
    error inside cx_check() must BLOCK (exit 2) — preToolUse is always a blocking gate. `detail`
    names the specific failure when it is known (e.g. a missing hooks/cx_shell.py), so a broken
    install is diagnosable instead of a generic "internal error".

    Logged with its own reason_code ("gate_crash", distinct from every content-based reason_code
    _deny() uses elsewhere in this file) so this HOOK-CHAIN failure is never confused, in the
    cx-devassist.jsonl audit log or in the message shown to the agent, with a real policy decision
    about the file's content — before this, a crash here denied silently with NO log record at
    all, so "the gate crashed" and "the gate never ran" were indistinguishable after the fact."""
    _log("gate_decision", decision="deny", reason_code="gate_crash", exit_code=2)
    try:
        reason = (
            "The Checkmarx security gate hit an internal error BEFORE it could evaluate this "
            "action's content, so it is BLOCKED fail-closed. This is a hook-chain execution "
            "failure, NOT a decision about your file's content — no scan of the content ran."
        )
        context = (
            (detail + " " if detail else "")
            + "An unexpected error occurred inside cx_check.py — a hook-chain failure, not a "
            "content-based policy denial (no scan of the proposed content ran or could have run). "
            "All agent actions remain blocked until it is resolved. Re-run the plugin's bundled "
            "bootstrap to restore the gate:\n    "
            + _bootstrap_command_str("install")
        )
        agent_msg = _deny_agent_message(context)
        print(json.dumps({
            "permission": "deny",
            "user_message": reason,
            "agent_message": agent_msg,
            "additional_context": agent_msg,
        }))
    except Exception:
        pass


def is_trusted_setup_command(hook_input):
    """True when `hook_input` is one of the TRUSTED BOOTSTRAP/SETUP commands that must ALWAYS reach an
    allow decision, whatever state cx is in and whichever shell the agent is driving:

      - the plugin's own bundled scripts, including `bash "<…>/cx-bootstrap.sh" install|upgrade`
        (component download + install) and the other first-party helpers it ships;
      - `cx auth …` (login / logout / validate / register — OAuth and token validation),
        `cx configure …` (API-key setup), and `cx hooks check-auth` (scanner session validation);
      - `cx version` / `cx utils env` — the pre-scan initialization probes.

    These are the operations that ESTABLISH the conditions the gate enforces, so blocking them is a
    deadlock rather than a control: an unauthenticated gate that denies `cx auth login` can never
    become authenticated. Each still has to be a BARE command (no chaining, no substitution, no
    redirect to a real file) and, when it names cx or a script by path, that path must resolve to the
    canonical store / a CX_BINARY pin / inside this plugin — so the carve-out cannot be used to run
    something else.

    This is the SINGLE authoritative definition, shared with the shell stages: hooks/cx_check.sh and
    hooks/cx_run.sh reach it through hooks/_cx_bootstrap_match.sh, which shells out to the
    `--match-trusted-setup` CLI below instead of re-implementing the matching in sh. That is what
    keeps stage-1 and stage-2 from ever disagreeing about the same command (one allowing, the other
    denying → blocked, because every hook in a matcher must allow)."""
    return bool(
        _is_bootstrap_command(hook_input)
        or _is_plugin_script_command(hook_input)
        or _is_auth_recovery_command(hook_input)
        or _is_setup_diagnostic_command(hook_input, _effective_tool(hook_input, "cursor"))
    )


_MATCH_EXIT_TRUSTED = 0      # it IS a trusted bootstrap/setup command -> caller allows
_MATCH_EXIT_NOT_TRUSTED = 1  # it is NOT -> caller falls through to its own gate/deny
_MATCH_EXIT_UNAVAILABLE = 3  # this matcher could not decide -> caller uses its own fallback


def _match_auth_recovery_cli():
    """`python cx_check.py --match-auth-recovery` — fast auth/configure carve-out for cx_check.sh."""
    try:
        hook_input = _read_hook_input()
        if not hook_input:
            sys.exit(_MATCH_EXIT_NOT_TRUSTED)
        _GATE_CTX["shell"] = cx_shell.detect_shell(
            _shell_command(hook_input, _GATE_CTX["agent"]) or None)
        sys.exit(_MATCH_EXIT_TRUSTED if _is_auth_recovery_command(hook_input)
                 else _MATCH_EXIT_NOT_TRUSTED)
    except SystemExit:
        raise
    except BaseException:
        sys.exit(_MATCH_EXIT_UNAVAILABLE)


def _match_ignore_vulnerability_cli():
    """`python cx_check.py --match-ignore-vulnerability` — fast carve-out probe for
    hooks/cx_run.sh and hooks/cx_check.sh (via hooks/_cx_bootstrap_match.sh), used to decide whether
    Stage 2 can skip its blocking native `cx hooks cursor-before-shell` scanner for this command,
    and whether Stage 1 can fast-allow without running the full auth/version gate (see
    _is_ignore_vulnerability_command)."""
    try:
        hook_input = _read_hook_input()
        if not hook_input:
            sys.exit(_MATCH_EXIT_NOT_TRUSTED)
        _GATE_CTX["shell"] = cx_shell.detect_shell(
            _shell_command(hook_input, _GATE_CTX["agent"]) or None)
        sys.exit(_MATCH_EXIT_TRUSTED if _is_ignore_vulnerability_command(hook_input)
                 else _MATCH_EXIT_NOT_TRUSTED)
    except SystemExit:
        raise
    except BaseException:
        sys.exit(_MATCH_EXIT_UNAVAILABLE)


def _match_checkmarx_ignore_prep_cli():
    """`python cx_check.py --match-checkmarx-prep` — fast carve-out for `.checkmarx` prep commands."""
    try:
        hook_input = _read_hook_input()
        if not hook_input:
            sys.exit(_MATCH_EXIT_NOT_TRUSTED)
        _GATE_CTX["shell"] = cx_shell.detect_shell(
            _shell_command(hook_input, _GATE_CTX["agent"]) or None)
        sys.exit(_MATCH_EXIT_TRUSTED if _is_checkmarx_ignore_prep_command(hook_input)
                 else _MATCH_EXIT_NOT_TRUSTED)
    except SystemExit:
        raise
    except BaseException:
        sys.exit(_MATCH_EXIT_UNAVAILABLE)


def _match_trusted_setup_cli():
    """`python cx_check.py --match-trusted-setup` — read Cursor hook JSON on stdin and exit
    _MATCH_EXIT_TRUSTED / _MATCH_EXIT_NOT_TRUSTED. Prints nothing.

    The three exit codes are distinct on purpose: an internal error must NOT be mistaken for "not
    trusted" (that would deny the bootstrap on a machine where this file is broken), so it reports
    _MATCH_EXIT_UNAVAILABLE and the sh caller falls back to its own POSIX matcher."""
    try:
        hook_input = _read_hook_input()
        if not hook_input:
            sys.exit(_MATCH_EXIT_NOT_TRUSTED)
        _GATE_CTX["shell"] = cx_shell.detect_shell(
            _shell_command(hook_input, _GATE_CTX["agent"]) or None)
        sys.exit(_MATCH_EXIT_TRUSTED if is_trusted_setup_command(hook_input)
                 else _MATCH_EXIT_NOT_TRUSTED)
    except SystemExit:
        raise
    except BaseException:
        sys.exit(_MATCH_EXIT_UNAVAILABLE)


_OBSERVABLE_LOGIN_RE = re.compile(
    r'^\s*&?\s*"?(?:[^"\s]*[/\\])?cx(?:\.exe)?"?\s+(?:auth|configure)\b', re.IGNORECASE
)


def _is_observable_login_command(hook_input):
    """True for a bare shell `<any cx path> auth|configure …` worth recording."""
    command = _bare_bash_command(hook_input)
    if not command:
        return False
    return _OBSERVABLE_LOGIN_RE.match(command) is not None


def cx_record_login():
    """OBSERVER-ONLY mode: notes URL/tenant of `cx auth login` for later auth-recovery offers."""
    hook_input = _read_hook_input()
    if _is_observable_login_command(hook_input):
        _record_login_attempt(_bare_bash_command(hook_input))


def main():
    # OBSERVER mode: record-login must NEVER block a tool call.
    if len(sys.argv) > 1 and sys.argv[1] == "record-login":
        try:
            cx_record_login()
        except BaseException:
            pass
        sys.exit(0)

    # cx_shell is required (it owns all shell parsing) — a failed import means the carve-outs cannot
    # be evaluated at all, which must BLOCK, not silently pass. Handled here rather than at import
    # time so it becomes a well-formed deny (exit 2) instead of an uncaught ImportError (exit 1,
    # which risks being treated as non-blocking = fail OPEN).
    if cx_shell is None:
        _fail_closed_on_crash(
            detail="hooks/cx_shell.py could not be imported ({0}), so the gate cannot parse the "
                   "proposed command.".format(_CX_SHELL_IMPORT_ERROR))
        sys.exit(2)
    if "--match-auth-recovery" in sys.argv[1:]:
        _match_auth_recovery_cli()
    if "--match-trusted-setup" in sys.argv[1:]:
        _match_trusted_setup_cli()
    if "--match-ignore-vulnerability" in sys.argv[1:]:
        _match_ignore_vulnerability_cli()
    if "--match-checkmarx-prep" in sys.argv[1:]:
        _match_checkmarx_ignore_prep_cli()
    # _deny()/_allow_with_warning() raise SystemExit with the real allow(0)/deny(2) code — let it
    # propagate. ANY other exception is an internal gate failure → fail CLOSED (deny, exit 2),
    # never an uncaught traceback (exit 1, which is treated as non-blocking = fail OPEN).
    try:
        cx_check()
    except SystemExit:
        raise
    except BaseException:
        _fail_closed_on_crash()
        sys.exit(2)


if __name__ == "__main__":
    main()
