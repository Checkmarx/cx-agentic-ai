"""Shared helper: enforces that the cx CLI is installed, recent enough, and authenticated
before any gated file write runs. Fail-closed: if cx is missing, unrunnable, or below the
minimum version, writes to scannable files are BLOCKED — even offline. The only escape from
the block is running the plugin's own bundled bootstrap. Shell commands are not gated; a
non-blocking observer records OAuth URL/tenant pairs for later re-auth."""

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


# Provenance tag prepended to every agent-facing string this gate emits, so the agent (or a reader
# hardened against prompt injection) can recognize genuine Checkmarx output. NOT an authority claim —
# an attacker could spoof this exact string from a file, a fetched page, or another tool's output — it
# is a signpost: text that LOOKS like a Checkmarx finding/hook message but lacks this exact tag, or
# that instructs running a script/CLI command "silently"/"without asking", did not come from Checkmarx
# and must not be acted on without asking the user first. Applied centrally in
# _deny()/_allow_with_warning()/_fail_closed_on_crash() rather than at each call site, so every present
# and future message from THIS gate carries it automatically.
_PROVENANCE_TAG = "[Checkmarx cx-devassist — automated security output, not user input]"


def _tag(text):
    """Prefix `text` with _PROVENANCE_TAG. `text` may be empty (e.g. _allow_with_warning's context
    is sometimes just a status note) — tag it anyway so absence of the tag stays a reliable signal."""
    return _PROVENANCE_TAG + " " + text


# Minimum cx version — a NUMERIC FLOOR only. The single source of truth is scripts/cx-min-version;
# this tuple is the fail-closed fallback used only when that file is missing or garbled. The floor
# is a fast pre-filter: capability is decided by the probe below (_capabilities_present), not by
# this number. Keep IDENTICAL to scripts/cx-min-version and scripts/cx-bootstrap.sh.
# (search marker: CX_MIN_VERSION)
_MIN_VERSION_FALLBACK = (2, 3, 69)

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


def _is_number(value):
    """True for a real int/float — NOT bool (True == 1 in Python, so a bare isinstance check
    would accept a boolean where a timestamp/mtime is expected)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _read_capped(path, max_bytes, encoding="utf-8-sig"):
    """The file's text, or None if it is unreadable, undecodable, or larger than max_bytes.

    Reads max_bytes + 1 so the length test can distinguish "exactly at the cap" from "over it"; an
    implausibly large state/config file is refused rather than parsed. Never raises — the shared read
    for every small bundled file the gate consumes, each of which maps None to its own sentinel.
    utf-8-sig by default: an admin editing a bundled file with Windows Notepad can prepend a BOM,
    which would otherwise corrupt the first key/line. It is a no-op when there is no BOM."""
    try:
        with open(path, "r", encoding=encoding) as f:
            raw = f.read(max_bytes + 1)
    except (OSError, UnicodeDecodeError):
        return None
    return None if len(raw) > max_bytes else raw


def _plugin_path(*parts):
    """Absolute path to a file bundled in this plugin, resolved relative to THIS file (…/hooks).

    Never ${CLAUDE_PLUGIN_ROOT} / ${PLUGIN_ROOT}: those are injected only into hook execution and
    are EMPTY in the agent's own shell, so a path built from them would not resolve."""
    return os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", *parts))


def _agent_log_dir():
    """Per-user directory for the gate's caches and bypass audit (and, later, structured
    logs). Default ~/.checkmarx/agent-logs/copilot-cli/ — a user-owned 0700 dir, so these
    predictable filenames can't be pre-planted by another local user the way world-writable
    OS-temp files could. CX_LOG_DIR overrides the location. Falls back to the OS temp dir
    only if the per-user dir can't be created, so caching/auditing degrade gracefully and
    this never raises into the gate.

    The "copilot-cli" leaf is NOT optional and must match cx_log.py's _assistant() default and
    cx-bootstrap.sh's _COPILOT_VERSION_CACHE. Omitting it (as this file did) drops every state file
    — cx_auth_cache, cx_version_cache, cx_scanner_cache, cx_login_history.json — into the SHARED
    ~/.checkmarx/agent-logs/ root, where they collide with the Claude and Cursor plugins' identically
    named files and, worse, sit outside the path the bootstrap clears after an install/upgrade, so a
    stale version cache survives and the gate keeps reporting the pre-upgrade version.
    Sibling plugins pin their own leaf the same way ("claude", "cursor")."""
    override = os.environ.get("CX_LOG_DIR")
    target = override or os.path.join(
        os.path.expanduser("~"), ".checkmarx", "agent-logs", "copilot-cli"
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


# Per-user state lives under _AGENT_LOG_DIR (default ~/.checkmarx/agent-logs/copilot-cli, 0700),
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

# --- Scannable files: what the Checkmarx engines can actually analyse -----------------------------
# The readiness chain (cx present → recent → capable → authenticated → licensed → really scanning) is
# only worth ENFORCING for a file one of the engines would look at. ASCA, KICS and SCA each self-skip
# an unsupported path. The secret engine does not: it scans every file the hook sees. A README.md write is therefore gated.
#
# The set lives in config/cx-scannable-files so an administrator can adjust coverage without editing
# code. THIS is its only reader — see that file's header for why a second, POSIX-shell implementation
# was written for the shell deny branches and then deleted.
# The shipped config/cx-scannable-files is ~4.5 KB, of which ~88% is explanatory header prose. At the
# 8192 inherited from the two-value cx-onboarding.properties, one more comparable comment block would
# tip it over, _load_scannable_files would return None, and the gate would silently start blocking
# EVERY file write with "everything is blocked" as the only symptom. 64 KB keeps the original intent
# (refuse an implausibly large file rather than parse it) with real headroom for documentation.
_SCANNABLE_FILES_MAX_BYTES = 65536

# The line kinds config/cx-scannable-files may declare. Each mirrors how the corresponding Go filter
# compares, so the plugin gates exactly what the engines scan:
#   ext         → filepath.Ext(...)      (ASCA asca.go:26, SCA oss-realtime.go:208)
#   suffix      → strings.HasSuffix(...) (KICS kics.go:33 — why `.auto.tfvars` matches but a plain
#                                         `.tfvars` is NOT scanned, and so must NOT be gated)
#   base        → exact basename         (KICS `Dockerfile`, SCA's manifest filename set)
#   txtprefix   → a *.txt manifest       (SCA oss-realtime.go:238-244)
#   swiftprefix → a *.swift manifest     (SCA oss-realtime.go:252-255)
#
# The two *prefix kinds exist because SCA treats a GENERIC extension as a manifest only when the
# basename also starts with a known prefix: `requirements.txt` is one but `changelog.txt` is not,
# `Package@swift-5.9.swift` is one but `App.swift` is not. Extension alone would over-gate every
# .txt and .swift file in the repo. Keyed by extension so adding the next one is a single entry —
# _SCANNABLE_KINDS is derived from it rather than repeated, which is what let `swiftprefix:` ship
# in the config and be silently dropped by the parser.
_PREFIX_KINDS_BY_EXT = {".txt": "txtprefix", ".swift": "swiftprefix"}
_SCANNABLE_KINDS = ("ext", "suffix", "base") + tuple(_PREFIX_KINDS_BY_EXT.values())

# The tool_input key holding the target path, in priority order. Copilot CLI create/edit typically
# carry file_path; `path` is accepted as a fallback. Notebook-style payloads carry notebook_path.
_FILE_TOOL_PATH_KEYS = ("file_path", "notebook_path", "path")

# The tools whose payloads the file-type rule may narrow. Anything NOT listed here is gated
# unconditionally — see _is_scannable_file. Copilot CLI uses lowercase create/edit; Claude-style
# names are kept so the same gate module still classifies those payloads in tests.
# Kept in step with the file matchers in hooks/hooks-copilot-cli.json; a new file tool added there
# but not here is gated (fail closed), which is the safe direction.
_FILE_WRITE_TOOLS = frozenset({"create", "edit", "Write", "Edit", "MultiEdit", "NotebookEdit"})


def _scannable_files_path():
    """Absolute path to the bundled scannable-file list, relative to THIS file (…/hooks)."""
    return _plugin_path("config", "cx-scannable-files")


def _load_scannable_files(path=None):
    """config/cx-scannable-files parsed to {kind: frozenset(lowercased values)}, or None when it is
    missing, oversized, undecodable, or parses to nothing. Unknown line kinds are silently dropped
    and this NEVER raises — an escaped exception would trip _fail_closed_on_crash and brick every
    tool call.

    Unlike _load_admin_config, a load failure is NOT benign: returning None makes _is_scannable_file
    gate EVERY file (fail CLOSED). An empty parse is treated as a failure for the same reason — a
    truncated or garbled file must not read as "nothing is scannable", which would silently disable
    the gate everywhere. `path` is a test hook."""
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
    """The basename that will ACTUALLY be created, or `""` when it cannot be determined.

    Windows silently discards trailing spaces and dots from a filename, and `name::$DATA` addresses
    the default data stream of `name` — so `payload.py `, `payload.py.` and `payload.py::$DATA` all
    create `payload.py`. Classifying the raw string would let a scannable file be laundered through
    the unscannable carve-out: the gate sees extension `.py ` (no match → allow), and cx's own ASCA
    filter sees the same, so real Python source reaches disk unscanned with an `allow` audit record.

    Applied on EVERY OS, not just Windows: the payload can name a path on a Windows share or be
    replayed cross-platform, and stripping a trailing space/dot can only ever make the gate MORE
    conservative. A stream suffix yields `""` — everything after `::` is not part of the filename, so
    the target is genuinely unknown and the caller must gate. `""` rather than a distinct sentinel
    because "stripped to nothing" and "cannot tell" lead to the same verdict at the only call site."""
    if "::" in base:
        return ""
    return base.rstrip(" .")


def _is_scannable_file(hook_input):
    """True when this call targets a file one of the Checkmarx engines can analyse — i.e. when the
    readiness chain is worth enforcing. Reads config/cx-scannable-files via _load_scannable_files.

    FAIL CLOSED on every uncertainty, so this can only ever narrow the gate for files that are
    PROVABLY unscannable:
      - a tool that is not a known FILE-WRITE tool (shell, MCP, glob, and any assistant whose tool
        names this gate does not know) → True
      - a missing / empty / non-string path → True
      - an unloadable or empty config → True
    Only a positively identified non-scannable path on a known file-write tool returns False.
    Force-gate everything with CX_GATE_ALL_FILES=1.

    The tool-name check is not redundant with the path lookup: an MCP remediation call can
    legitimately carry a `file_path` argument, and keying only off the PRESENCE of that key let
    such a call skip the entire readiness chain — cx is required for the MCP to work at all, so it
    must always be gated.

    Comparison is case-insensitive. ASCA and KICS lowercase before matching; SCA's basename lookup is
    case-SENSITIVE in Go, so `Package.json` is gated here but would not be scanned there — over-gating
    by a hair, which is the fail-closed direction."""
    if os.environ.get("CX_GATE_ALL_FILES") == "1":
        return True
    if _tool_name(hook_input) not in _FILE_WRITE_TOOLS:
        return True
    tool_input = _tool_input(hook_input)
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
    # Normalize separators before taking the basename: the gate may run under Git-Bash (POSIX
    # semantics) while the agent types a native Windows path, where os.path.basename would not split
    # on backslashes. `""` from _effective_basename means "cannot determine the real target" (an NTFS
    # stream suffix, or a name that strips to nothing) — both gate.
    base = _effective_basename(os.path.basename(path.replace("\\", "/").rstrip("/").lower()))
    if not base:
        return True
    if base in table["base"]:
        return True
    _root, ext = os.path.splitext(base)
    if ext and ext in table["ext"]:
        return True
    if any(base.endswith(suffix) for suffix in table["suffix"]):
        return True
    prefix_kind = _PREFIX_KINDS_BY_EXT.get(ext)
    if prefix_kind and any(base.startswith(prefix) for prefix in table[prefix_kind]):
        return True
    # Secrets scan every remaining file. ASCA, KICS and SCA would skip it; secrets would not — so such a
    # file is only worth gating while the secrets scanner is switched on. (Default: on.) Inside VS Code a
    # valid IDE state file is the source of the switch, as it is for ast-cli's native scan.
    if _COPILOT_CLI_MODE and _in_vscode(hook_input):
        ide = _load_ide_config()
        if ide is not None:
            return ide.get("cx_secret_scanner_enabled", "").strip().lower() not in _FALSE_VALUES
    return _load_scanner_switches()["cx_secret_scanner_enabled"]


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
    messages so the agent doesn't need ${CLAUDE_PLUGIN_ROOT} (which is empty in its shell).
    Uses `sh` with forward slashes so it works on Windows (bash fails with backslash paths
    when invoked from the Copilot CLI powershell tool or WSL-less Git Bash contexts)."""
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
    ("hooks", "copilot-cli-pre-file-write", "--help"),
    ("hooks", "copilot-cli-stop", "--help"),
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


def _valid_base_uri(value):
    """THE canonical base-auth-uri, or None if the value is not one. Every boundary that accepts a
    base URI — a parsed `cx auth login` flag, a stored history entry, the admin properties file —
    goes through here, so "what counts as canonical" is defined ONCE.

    Canonicalization is SURROUNDING WHITESPACE AND TRAILING SLASHES ONLY. `https://host/` and
    `https://host` are the same environment and ast-cli accepts both, but _ADMIN_URL_RE's charset
    has no '/' — so the slashed spelling could never validate, and a developer who typed it had
    EVERY login silently dropped while `cx auth login` itself succeeded.

    A path-bearing URL is REJECTED rather than truncated — an on-prem reverse-proxy prefix is
    meaningful. fullmatch, not match: Python's `$` ALSO matches immediately before a trailing
    newline, so a value carrying a newline would be rendered as TWO shell lines."""
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip("/")
    return value if _ADMIN_URL_RE.fullmatch(value) else None


def _valid_tenant(value):
    """The canonical tenant, or None. Peer of _valid_base_uri — see it for why whitespace is
    stripped before validating and why this is fullmatch rather than match."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if _ADMIN_TENANT_RE.fullmatch(value) else None


# key -> canonicalize-and-validate. This table is the ONLY declaration of a key's handling, so a key
# added here cannot end up validated but un-canonicalized.
_ADMIN_CONFIG_VALIDATORS = {
    "cx_base_auth_uri": _valid_base_uri,
    "cx_tenant": _valid_tenant,
}


def _admin_config_path():
    """Absolute path to the bundled admin onboarding config, relative to THIS file (…/hooks)."""
    return _plugin_path("config", "cx-onboarding.properties")


def _parse_admin_file(path):
    """The known, VALIDATED keys of ONE properties file as a dict (possibly empty). Fail soft: a
    missing/garbled/oversized/undecodable file, an invalid value or any error yields what was parsed so
    far / {}. NEVER raises."""
    try:
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                raw = f.read(_ADMIN_CONFIG_MAX_BYTES + 1)
        except (OSError, UnicodeDecodeError):
            return {}
        if len(raw) > _ADMIN_CONFIG_MAX_BYTES:
            return {}
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
                continue
            canonical = validator(value)
            if canonical:
                result[key] = canonical
            else:
                _log("admin_config", result="invalid", key=key)
        return result
    except Exception:
        return {}


def _load_admin_config(path=None):
    """The URL / tenant pre-fill: ONLY the known, VALIDATED keys, as a dict (possibly empty).

    Precedence per key: the user's ~/.checkmarx/cx-onboarding.properties (when the developer or admin
    set a valid value there) over the bundled config/cx-onboarding.properties. The same strict
    validators apply to both files, so a value from either is shell-inert before it is ever embedded in
    the `cx auth login` command. FAIL SOFT: any problem yields fewer keys (the plugin then asks the
    developer), never an exception — an escaped exception would trip _fail_closed_on_crash and brick
    every tool call — and never a block. `path` is a test hook that reads that single file only."""
    try:
        if path is not None:
            return _parse_admin_file(path)
        merged = _parse_admin_file(_admin_config_path())
        merged.update(_parse_admin_file(_user_config_path()))
        return merged
    except Exception:
        return {}


# --- User copy of the onboarding config (~/.checkmarx/cx-onboarding.properties) ---------------------
# Copilot CLI has no plugin-install hook, so the bundled config is copied to the user's ~/.checkmarx
# the first time any hook runs after install. The copy is NEVER overwritten (the developer's edits
# survive plugin updates). Scanner on/off switches are read from it; they can only NARROW what the
# plugin does and never cause a deny. URL/tenant pre-fill stays bundle-only (see the file header).
# Never seeded inside VS Code (_should_seed_user_config): VS Code uses cx-onboarding-ide.properties.
_USER_CONFIG_NAME = "cx-onboarding.properties"
_SCANNER_SWITCH_KEYS = (
    "cx_asca_scanner_enabled",
    "cx_sca_scanner_enabled",
    "cx_kics_scanner_enabled",
    "cx_secret_scanner_enabled",
)
_FALSE_VALUES = frozenset({"false", "0", "no", "off", "disabled"})


def _user_config_path():
    return os.path.join(os.path.expanduser("~"), ".checkmarx", _USER_CONFIG_NAME)


def _property_key(line):
    """The key of a `key=value` line, treating a `#`-commented line as the SAME key (so a developer who
    commented a setting out deliberately is not nagged with it again). None for blanks/plain comments."""
    line = line.strip().lstrip("#").strip()
    key, sep, _value = line.partition("=")
    key = key.strip()
    return key if sep and key and " " not in key else None


def _merge_new_properties(src, dest):
    """Append to the user's copy every ACTIVE key the bundled file defines that the user's file does not
    mention at all (active or commented), each with the comment block above it. Existing lines are never
    modified, reordered or removed, so a plugin update brings new settings without touching the
    developer's choices. Admin-only keys are not copied: they are commented examples in the bundle, and
    only active bundle lines count. Written via temp-file + os.replace so a crash cannot truncate the
    user's file, and two racing hooks compute identical content instead of appending twice.
    Returns True when something was added. Never raises."""
    try:
        with open(src, "r", encoding="utf-8-sig", newline="") as f:
            bundled = f.read(_ADMIN_CONFIG_MAX_BYTES + 1).splitlines()
        with open(dest, "r", encoding="utf-8", newline="") as f:
            current = f.read(_ADMIN_CONFIG_MAX_BYTES + 1)
        if len(current) > _ADMIN_CONFIG_MAX_BYTES:
            return False
        present = {_property_key(line) for line in current.splitlines()}
        eol = "\r\n" if "\r\n" in current else "\n"
        additions = []
        for i, line in enumerate(bundled):
            key = _property_key(line)
            if not key or line.strip().startswith("#") or key in present:
                continue
            start = i
            while start > 0 and bundled[start - 1].strip().startswith("#"):
                start -= 1
            additions.append(bundled[start:i + 1])
            present.add(key)
        if not additions:
            return False
        out = current if (not current or current.endswith(("\n", "\r"))) else current + eol
        out += eol + "# --- added by a plugin update ---" + eol
        for block in additions:
            out += eol.join(block) + eol
        tmp = dest + ".tmp-{0}".format(os.getpid())
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(out)
        os.replace(tmp, dest)
        _log("admin_config", result="merged_user_copy")
        return True
    except Exception:
        return False


def _seed_user_config(src=None, dest=None):
    """Keep ~/.checkmarx/cx-onboarding.properties in step with the bundle. Missing -> copy it.
    Present -> leave every existing line alone and only ADD settings a plugin update introduced
    (_merge_new_properties). Best-effort: never raises, never blocks. `src`/`dest` are test hooks.
    Returns True only when the file was freshly copied."""
    try:
        src = src or _admin_config_path()
        dest = dest or _user_config_path()
        if not os.path.isfile(src):
            return False
        if os.path.exists(dest):
            _merge_new_properties(src, dest)
            return False
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(src, "rb") as fin, open(dest, "xb") as fout:   # "x": never clobber a racing writer
            fout.write(fin.read())
        _log("admin_config", result="seeded_user_copy")
        return True
    except Exception:
        return False


def _load_scanner_switches(path=None):
    """{switch_key: bool} for the four scanner switches. Every scanner defaults to ENABLED; only an
    explicit false/0/no/off/disabled turns one off, so a typo or unreadable file can never silently
    disable scanning. Reads the user copy, falling back to the bundled file. NEVER raises."""
    result = {key: True for key in _SCANNER_SWITCH_KEYS}
    try:
        raw = None
        for candidate in ([path] if path else [_user_config_path(), _admin_config_path()]):
            raw = _read_capped(candidate, _ADMIN_CONFIG_MAX_BYTES)
            if raw is not None:
                break
        if raw is None:
            return result
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _sep, value = line.partition("=")
            key = key.strip()
            if key in result and value.strip().lower() in _FALSE_VALUES:
                result[key] = False
    except Exception:
        pass
    return result


# --- VS Code IDE state file (~/.checkmarx/cx-onboarding-ide.properties) ----------------------------
# Written ONLY by the Checkmarx VS Code extension, from its "Checkmarx Self-Healing" setting. GitHub
# Copilot in VS Code loads this same plugin and runs these same hooks, so the file is how the user's
# VS Code choice reaches them. Read only when the host is VS Code (_in_vscode) — the terminal Copilot
# CLI never reads it, so the CLI stays exactly as it was. "Missing file = ON": an absent, unreadable,
# oversized or unknown-schema file, a missing key or any value outside _FALSE_VALUES all mean enabled.
_IDE_CONFIG_NAME = "cx-onboarding-ide.properties"
_IDE_CONFIG_MAX_BYTES = 8192
_IDE_SCHEMA_VERSION = "1"


def _ide_config_path():
    return os.path.join(os.path.expanduser("~"), ".checkmarx", _IDE_CONFIG_NAME)


def _load_ide_config(path=None):
    """{key: value} from the IDE state file (last occurrence wins, `#` lines skipped, BOM stripped),
    or None when it is not VALID: missing, unreadable, undecodable, over 8 KB, or carrying a
    cx_schema_version other than 1. `path` is a test hook. NEVER raises."""
    try:
        path = path or _ide_config_path()
        # The cap is in BYTES (as the shell reader's `wc -c` measures it); _read_capped counts chars.
        if os.path.getsize(path) > _IDE_CONFIG_MAX_BYTES:
            return None
        raw = _read_capped(path, _IDE_CONFIG_MAX_BYTES)
        if raw is None:
            return None
        values = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _sep, value = line.partition("=")
            values[key.strip()] = value.strip()
        if values.get("cx_schema_version", _IDE_SCHEMA_VERSION) != _IDE_SCHEMA_VERSION:
            return None
        return values
    except Exception:
        return None


def _ide_self_healing_disabled():
    """True only when the IDE state file is valid AND cx_self_healing_enabled is explicitly false."""
    ide = _load_ide_config()
    return ide is not None and ide.get("cx_self_healing_enabled", "").strip().lower() in _FALSE_VALUES


# The shared opening of every _oauth_recovery_bullet branch — one copy, so a wording change cannot
# silently miss a branch (there are three of them now).
_OAUTH_BULLET_LEAD = (
    "- Browser sign-in (OAuth) -- only if the developer picks this: you may run it yourself "
    "(it opens the developer's browser with MFA; no secret passes through you; it resolves cx "
    "by absolute path so it works before cx is on PATH). "
)


def _oauth_recovery_bullet(cfg, history=None):
    """The 'Browser sign-in (OAuth)' bullet for an auth-recovery deny context, in precedence order:

      1. the admin config supplied a VALIDATED base-auth-uri AND tenant → embed the real values and
         tell the agent to use them as-is (skip the URL/tenant question);
      2. else the login history holds previously used (URL, tenant) pairs → list them as CHOICES the
         developer must pick from (never auto-used);
      3. else the ask-the-developer / never-guess guidance, with the regional-URLs doc link.

    Every embedded value is pre-validated to a shell-inert charset, so each resulting
    `"<cx>" auth login …` command still passes _is_auth_recovery_command's bare-command guard.
    `history=None` (the production call) loads the confirmed pairs LAZILY — only once the admin branch
    has not short-circuited. Tests inject explicit lists (including `[]` so a developer machine with
    real history cannot flake the placeholder-branch assertion)."""
    base = cfg.get("cx_base_auth_uri")
    tenant = cfg.get("cx_tenant")
    if base and tenant:
        cmd = _cx_recovery_command_str(
            "auth login --base-auth-uri {0} --tenant {1}".format(base, tenant))
        return _OAUTH_BULLET_LEAD + (
            "The --base-auth-uri and --tenant "
            "below were PRECONFIGURED (cx-onboarding.properties: the plugin's bundled "
            "copy or the developer's ~/.checkmarx copy) -- use them AS-IS and do NOT ask the developer for a URL "
            "or tenant:\n    " + cmd
        )
    if history is None:
        history = _confirmed_login_pairs()
    if history:
        pairs = "".join(
            "\n    [{0}] {1} @ {2}\n        {3}".format(
                i + 1, t, b,
                _cx_recovery_command_str(
                    "auth login --base-auth-uri {0} --tenant {1}".format(b, t)))
            for i, (b, t) in enumerate(history))
        _log("login_history", action="offered", count=len(history))
        return _OAUTH_BULLET_LEAD + (
            "The environment(s) below were used in an EARLIER `cx auth login` "
            "from this machine and are offered as a shortcut, NOT as verified history -- the plugin "
            "infers success from the credential file changing, which a login the developer abandoned "
            "can also produce. Treat each as a suggestion to confirm, never as fact. Most recent "
            "first. Only AFTER OAuth is "
            "chosen, present them as numbered choices -- one option per environment, most "
            "recent first; an \"Other\" option lets the developer type a different URL + "
            "tenant instead -- and do NOT run any login until the developer explicitly picks one "
            "(they may want a different tenant this time). If they pick \"Other\", ask for the "
            "URL/tenant per the cx-cli-setup skill's oauth.md Question 2 (free-text form) -- NEVER "
            "guess or default values that are not listed. Ready-to-run command for each:" + pairs
        )
    cmd = _cx_recovery_command_str("auth login --base-auth-uri <url> --tenant <tenant>")
    return _OAUTH_BULLET_LEAD + (
        "Only AFTER OAuth is chosen, ask for the "
        "URL/tenant -- NEVER guess or default the --base-auth-uri or --tenant values (e.g. do not try "
        "'iam.checkmarx.net' or a tenant of 'checkmarx') -- ask the developer, per the cx-cli-setup "
        "skill's oauth.md Question 2. Regional URL examples: US https://ast.checkmarx.net, "
        "US2 https://us.ast.checkmarx.net, EU https://eu.ast.checkmarx.net, "
        "ANZ https://anz.ast.checkmarx.net, India https://ind.ast.checkmarx.net, or their on-prem "
        "URL. Full region list + how to find your tenant: " + _CX_ENV_URLS_DOC
        + "\n    " + cmd
    )


# --- OAuth login history (previously used base-URL/tenant pairs) -----------------------------------
# The cx CLI deliberately never persists --base-auth-uri/--tenant for an agent-issued flag login, so
# every fresh OAuth login used to re-ask the developer for both. The gate (and the shell observer)
# remember the pairs: RECORD as `pending` when a `cx auth login` is observed, PROMOTE to `confirmed`
# once auth validates AND the stored credential has CHANGED since the attempt, and OFFER only
# confirmed pairs in the auth-recovery deny — as choices, never silently auto-used. Admin pre-fill
# (cx-onboarding.properties) keeps absolute precedence. Convenience, not a gate control: any
# read/write error degrades to "no history" and never blocks or raises.
_LOGIN_HISTORY_FILE = _state_path("cx_login_history.json")
_LOGIN_HISTORY_MAX = 5
_LOGIN_HISTORY_OFFER_MAX = 3
_LOGIN_HISTORY_MAX_BYTES = 16384
_LOGIN_PENDING_TTL = 3600

_AUTH_LOGIN_RE = re.compile(r"\bauth\s+login\b")
_LOGIN_FLAG_RE = re.compile(
    r'--(base-auth-uri|base-uri|tenant)(?:=|\s+)(?:"([^"\s]+)"|\'([^\'\s]+)\'|([^\s"\']+))')


def _parse_login_flags(command):
    """(base_auth_uri, tenant) from a `cx auth login …` command, or None. Both flags must be present
    AND pass the strict admin-config validators — a half-parsed or invalid pair is never recorded.
    A repeated flag takes the LAST occurrence, mirroring the CLI's own last-flag-wins semantics."""
    if not command or not _AUTH_LOGIN_RE.search(command):
        return None
    found = {}
    for m in _LOGIN_FLAG_RE.finditer(command):
        key = "base-auth-uri" if m.group(1) in ("base-auth-uri", "base-uri") else m.group(1)
        found[key] = next(g for g in m.groups()[1:] if g is not None)
    base = _valid_base_uri(found.get("base-auth-uri"))
    tenant = _valid_tenant(found.get("tenant"))
    if base is None or tenant is None:
        return None
    return base, tenant


def _valid_login_entry(entry):
    """The normalized history entry dict, or None if ANY field fails re-validation."""
    if not isinstance(entry, dict):
        return None
    url = _valid_base_uri(entry.get("base_auth_uri"))
    tenant = _valid_tenant(entry.get("tenant"))
    status, last_used, cred = entry.get("status"), entry.get("last_used"), entry.get("cred_before")
    if url is None or tenant is None:
        return None
    if status not in ("pending", "confirmed") or not _is_number(last_used):
        return None
    if cred is not None and not _is_number(cred):
        return None
    return {"base_auth_uri": url, "tenant": tenant, "status": status,
            "last_used": last_used, "cred_before": cred}


def _load_login_history(path=None):
    """The validated entry list from cx_login_history.json (possibly empty), NEWEST FIRST and capped
    at _LOGIN_HISTORY_MAX. FAIL SOFT: missing/oversized/corrupt file yields [] and never raises."""
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
    """Best-effort ATOMIC write (temp file in the same dir + os.replace). Never raises."""
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


_CX_CONFIGURE_SET_RE = re.compile(r"\bconfigure\s+set\b")


def _record_login_attempt(command, path=None):
    """Note an admitted recovery command in the login history. A parseable `cx auth login …`
    upserts its (URL, tenant) pair as PENDING; `cx configure set …` drops all pendings.
    Never raises."""
    try:
        if command and _CX_CONFIGURE_SET_RE.search(command):
            _drop_pending_logins(path)
            return
        if not (command and _AUTH_LOGIN_RE.search(command)):
            return
        parsed = _parse_login_flags(command)
        if parsed is None:
            _log("login_history", action="skipped")
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
    """Remove all PENDING entries (confirmed ones stay). Never raises."""
    try:
        entries = _load_login_history(path)
        kept = [e for e in entries if e["status"] != "pending"]
        if len(kept) != len(entries):
            _save_login_history(kept, path)
            _log("login_history", action="pruned", count=len(entries) - len(kept))
    except Exception:
        pass


def _promote_pending_login(path=None):
    """Called once auth validates: promote the newest PENDING attempt whose credential-mtime
    snapshot DIFFERS from the current one. Never raises."""
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
    """The offerable (base_auth_uri, tenant) pairs: CONFIRMED entries only, most recent first."""
    try:
        confirmed = [(e["base_auth_uri"], e["tenant"])
                     for e in _load_login_history(path) if e["status"] == "confirmed"]
        return confirmed[:_LOGIN_HISTORY_OFFER_MAX]
    except Exception:
        return []


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


def _deny(reason: str, context: str, *, reason_code=None, tool_name=None, version_state=None) -> None:
    # Exit-code + output contract differs by client:
    #   Claude Code:  exit 0 + hookSpecificOutput JSON wrapper — Claude Code PARSES
    #                 hookSpecificOutput.permissionDecision:"deny" and surfaces the reason.
    #   Copilot CLI:  exit 0 + FLAT JSON (no hookSpecificOutput wrapper) — Copilot CLI reads
    #                 permissionDecision / permissionDecisionReason at the TOP LEVEL of the
    #                 JSON object (per https://docs.github.com/en/copilot/reference/hooks-reference).
    #                 Using exit 1 also blocks but degrades to a generic "hook errored" with no
    #                 reason shown — the flat-JSON path is strictly better.
    # _COPILOT_CLI_MODE is set once per cx_check() call based on the --copilot-cli flag or
    # Deny exit code differs by client: Claude Code uses exit 2 for deny (exit 1 = error =
    # fail-open, exit 0 = allow). Copilot CLI uses exit 0 for everything — non-zero exits are
    # treated as hook errors (fail-open), not denials.
    _deny_exit = 0 if _COPILOT_CLI_MODE else 2
    _log("gate_decision", decision="deny", reason_code=reason_code, tool_name=tool_name,
         version_state=version_state, exit_code=_deny_exit)
    if _COPILOT_CLI_MODE:
        # Flat JSON — Copilot CLI reads permissionDecision at the top level.
        # permissionDecisionReason is shown directly to the agent.
        output = {
            "permissionDecision": "deny",
            "permissionDecisionReason": _tag(reason + "\n\n" + context),
        }
    else:
        # Claude Code nested wrapper format.
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": _tag(reason),
                "additionalContext": _tag(context),
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
            "permissionDecisionReason": _tag(context),
        }
    else:
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "additionalContext": _tag(context),
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

# How a hook knows it runs inside VS Code rather than the terminal Copilot CLI. First match wins:
#   1. PLUGIN_ROOT, which the host sets to the plugin folder it runs (verified by the AST-186850 PoC).
#      VS Code always runs its own copy under <VS Code user data>/agentPlugins/ (Windows
#      %APPDATA%/Code/agentPlugins, macOS ~/Library/Application Support/Code/agentPlugins, Linux
#      ~/.config/Code/agentPlugins, Insiders likewise) — for a plugin installed by the Copilot CLI and for
#      one installed from VS Code's marketplace. The terminal Copilot CLI (including one started in VS
#      Code's integrated terminal) runs it from ~/.copilot/installed-plugins/.
#   2. Any other PLUGIN_ROOT (a VS Code fork, JetBrains, Visual Studio, ...) is not VS Code.
#   3. Only when PLUGIN_ROOT is not set: GITHUB_COPILOT_INTEGRATION_ID=vscode-chat (VS Code sets it on
#      the Copilot CLI engine it bundles for its Copilot CLI chat sessions), then VS Code-shaped input
#      (snake_case tool_name / tool_input).
#   4. PLUGIN_ROOT under ~/.copilot/installed-plugins/ or not set: the nearest Copilot ancestor process
#      is VS Code's bundled Copilot runtime (<VS Code install>/resources/app/node_modules.asar.unpacked/
#      @github/copilot-sdk-<platform>/...). VS Code's Copilot CLI chat sessions run the plugin from
#      ~/.copilot/installed-plugins/ without GITHUB_COPILOT_INTEGRATION_ID, so rules 1-3 call them the
#      terminal. The terminal Copilot CLI is the `copilot` binary; in VS Code's integrated terminal it
#      is still the nearest Copilot ancestor, so it stays the terminal.
# Deliberately NOT keyed off TERM_PROGRAM / VSCODE_*: the integrated terminal inherits those.
_VSCODE_INTEGRATION_ID = "vscode-chat"
_VSCODE_INPUT_KEYS = ("tool_name", "tool_input", "hook_event_name", "session_id")
_COPILOT_SDK_MARKER = "/node_modules.asar.unpacked/@github/copilot-sdk-"
# VS Code's own install folders (stable and Insiders; Windows user/system, macOS, Linux deb/rpm/snap/AUR).
# A VS Code fork bundling the same SDK lives elsewhere and is not VS Code.
_VSCODE_INSTALL_MARKERS = (
    "/microsoft vs code/", "/microsoft vs code insiders/",
    "/visual studio code.app/", "/visual studio code - insiders.app/",
    "/usr/share/code/", "/usr/share/code-insiders/", "/snap/code/", "/snap/code-insiders/",
    "/opt/visual-studio-code/", "/opt/visual-studio-code-insiders/",
)
_TERMINAL_COPILOT_NAMES = ("copilot", "copilot.exe")
_MAX_ANCESTORS = 12
_PS_TIMEOUT_SEC = 3
# Windows API constants (tlhelp32.h / winnt.h / minwindef.h).
_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
_MAX_PATH = 260
_MAX_LONG_PATH = 32768
# Linux procfs: the only folder _posix_ancestor_exes reads.
_PROC_ROOT = "/proc"


def _copilot_parent_kind(exe_path):
    """"vscode-runtime" for VS Code's bundled Copilot runtime, "copilot-cli" for the terminal `copilot`
    binary, else None (not a Copilot process)."""
    p = (exe_path or "").replace("\\", "/").lower()
    if _COPILOT_SDK_MARKER in p and any(marker in p for marker in _VSCODE_INSTALL_MARKERS):
        return "vscode-runtime"
    if p.rsplit("/", 1)[-1] in _TERMINAL_COPILOT_NAMES:
        return "copilot-cli"
    return None


def _windows_ancestor_exes():
    import ctypes
    from ctypes import wintypes

    class _ProcessEntry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * _MAX_PATH)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.OpenProcess.restype = wintypes.HANDLE
    snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == wintypes.HANDLE(-1).value:
        return []
    parents = {}
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(_ProcessEntry)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            parents[entry.th32ProcessID] = entry.th32ParentProcessID
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    exes = []
    pid, seen = os.getpid(), set()
    while len(seen) < _MAX_ANCESTORS:
        pid = parents.get(pid)
        if not pid or pid in seen:
            break
        seen.add(pid)
        handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            continue
        try:
            buf = ctypes.create_unicode_buffer(_MAX_LONG_PATH)
            size = wintypes.DWORD(len(buf))
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                exes.append(buf.value)
        finally:
            kernel32.CloseHandle(handle)
    return exes


def _proc_entry(pid, name):
    """<_PROC_ROOT>/<pid>/<name>, normalised and checked to stay under _PROC_ROOT."""
    path = os.path.normpath(os.path.join(_PROC_ROOT, str(int(pid)), name))
    if os.path.dirname(os.path.dirname(path)) != _PROC_ROOT:
        raise ValueError("unexpected procfs path: %s" % path)
    return path


def _posix_ancestor_exes():
    exes = []
    pid = os.getppid()
    if os.path.isdir(_PROC_ROOT) and os.path.exists(_proc_entry(os.getpid(), "stat")):
        for _ in range(_MAX_ANCESTORS):
            if pid <= 1:
                break
            try:
                exes.append(os.readlink(_proc_entry(pid, "exe")))
            except OSError:
                pass
            try:
                with open(_proc_entry(pid, "stat"), "r") as f:
                    # Field 4 (ppid) follows the ")" that closes the command name.
                    pid = int(f.read().rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                break
        return exes
    # macOS: one `ps` call for the whole table; `comm` is the executable path there.
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,comm="], capture_output=True, text=True,
                         timeout=_PS_TIMEOUT_SEC).stdout
    table = {}
    for line in out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            table[int(parts[0])] = (int(parts[1]), parts[2])
    for _ in range(_MAX_ANCESTORS):
        if pid <= 1 or pid not in table:
            break
        pid, exe = table[pid]
        exes.append(exe)
    return exes


_copilot_parent = None


def _nearest_copilot_parent():
    """"vscode-runtime", "copilot-cli" or "none": the nearest Copilot ancestor process (rule 4). Cached
    for the process; any failure means "none" (the terminal behaviour). NEVER raises."""
    global _copilot_parent
    if _copilot_parent is None:
        _copilot_parent = "none"
        try:
            exes = _windows_ancestor_exes() if os.name == "nt" else _posix_ancestor_exes()
            for exe in exes:
                kind = _copilot_parent_kind(exe)
                if kind:
                    _copilot_parent = kind
                    break
        except Exception:
            _copilot_parent = "none"
    return _copilot_parent


def _plugin_root_host():
    """"vscode", "cli", "other" (any other host's plugin folder) or None (PLUGIN_ROOT not set) from
    the PLUGIN_ROOT the host injected."""
    root = os.environ.get("PLUGIN_ROOT", "").strip().replace("\\", "/").lower()
    # Terminal marker first: VS Code's folder names encode the source path with dashes
    # (...-copilot-installed-plugins-...), so they never contain it, while a terminal path could
    # contain "agentPlugins" by chance (a user or folder name).
    if "/.copilot/installed-plugins/" in root:
        return "cli"
    # Only VS Code's own user-data folder ("Code", "Code - Insiders") counts: VS Code forks (Cursor,
    # Windsurf, Kiro, Devin, ...) keep their agentPlugins copies under their own folder and are not VS Code.
    if "/code/agentplugins/" in root or "/code - insiders/agentplugins/" in root:
        return "vscode"
    if root:
        # Any other plugin folder (a VS Code fork's agentPlugins, JetBrains, Visual Studio, ...) is not
        # VS Code, and the fallbacks must not override that.
        return "other"
    return None


def _in_vscode(hook_input):
    """True when this Copilot hook runs inside VS Code (see the rules above)."""
    host = _plugin_root_host()
    if host == "vscode":
        return True
    if host == "other":
        return False
    if host is None:
        if os.environ.get("GITHUB_COPILOT_INTEGRATION_ID", "").strip() == _VSCODE_INTEGRATION_ID:
            return True
        if isinstance(hook_input, dict) and any(k in hook_input for k in _VSCODE_INPUT_KEYS):
            return True
    return _nearest_copilot_parent() == "vscode-runtime"


def _log_host_detect(hook_input, tool):
    """Logs the signals _in_vscode decides from (constants only, never the PLUGIN_ROOT path)."""
    integration_id = os.environ.get("GITHUB_COPILOT_INTEGRATION_ID", "").strip()
    _log("host_detect",
         plugin_root_host=_plugin_root_host() or "unset",
         integration_id=integration_id or "unset",
         input_shape="cli" if isinstance(hook_input, dict) and _is_copilot_cli_input(hook_input) else "vscode",
         copilot_parent=_nearest_copilot_parent(),
         in_vscode=_in_vscode(hook_input),
         tool_name=tool)


def _is_vscode_plugin_copy(path=None):
    """True when `path` (default: this file) is inside VS Code's own plugin copy
    (<VS Code user data>/agentPlugins/...). The MCP bridge spawn (`seed-user-config` from cx_run.sh) may not
    get PLUGIN_ROOT in its environment, but it always runs the scripts from the folder its host runs."""
    p = os.path.abspath(path or __file__).replace("\\", "/").lower()
    return "/code/agentplugins/" in p or "/code - insiders/agentplugins/" in p


def _should_seed_user_config():
    """False inside VS Code: there the Checkmarx VS Code extension keeps the user's choices in
    ~/.checkmarx/cx-onboarding-ide.properties, so GitHub Copilot in VS Code never creates or updates
    ~/.checkmarx/cx-onboarding.properties (it still reads one the terminal Copilot CLI created, else the
    bundled config). Stdin is not read yet when this runs, so only the environment and this file's own
    location decide."""
    return not (_in_vscode(None) or _is_vscode_plugin_copy())



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
    ${CLAUDE_PLUGIN_ROOT} placeholder (which the agent's shell does NOT expand) is honored only
    after expanding it from the gate's own environment and proving it resolves to the bundled
    bootstrap — never blessed blindly."""
    command = _bare_bash_command(hook_input)
    if command is None:
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

    # Set the client mode flag — read by _deny() to choose the correct exit code. Moved BEFORE the
    # bootstrap check (was after) so the bootstrap carve-out below can also branch on it correctly,
    # instead of running while the flag still holds its stale module-level default.
    # Priority: explicit --copilot-cli argv flag (passed from hooks-copilot-cli.json) overrides
    # the stdin-format heuristic. The flag is the reliable signal because Copilot CLI may not
    # include a `toolCalls` key in every hook payload, causing _is_copilot_cli_input() to return
    # False and _deny() to fall back to exit 0 — which Copilot CLI ignores (it only blocks on
    # a non-zero exit). The argv flag makes Copilot CLI mode explicit and format-independent.
    global _COPILOT_CLI_MODE
    _COPILOT_CLI_MODE = ("--copilot-cli" in sys.argv[1:]) or _is_copilot_cli_input(hook_input)

    # 0. VS Code "Checkmarx Self-Healing" unticked → the plugin does NOTHING in VS Code: allow at
    #    once, before the bootstrap, CX_BINARY, version, auth and licence checks. Emits no JSON — an
    #    explicit allow would also skip VS Code's own tool-confirmation prompt. A missing/invalid IDE
    #    state file means ON (today's behaviour). The terminal Copilot CLI never reaches this read.
    if _COPILOT_CLI_MODE:
        _log_host_detect(hook_input, tool)
    if _COPILOT_CLI_MODE and _in_vscode(hook_input) and _ide_self_healing_disabled():
        _log("gate_decision", decision="allow", reason_code="self_healing_disabled", tool_name=tool)
        return

    # 1. The bootstrap is the ONLY way out of the block — must be checked first.
    #
    # Emit an EXPLICIT decision JSON here too, matching every other branch in this file (_deny,
    # _allow_with_warning), instead of a bare `return`. A silent exit-0-with-no-stdout used to rely
    # on an unverified assumption that Copilot CLI treats it as an implicit allow; in practice an
    # empty response can be read as a malformed hook run, which Copilot CLI then reports as a hook
    # ERROR — and an errored preToolUse hook denies the call, not fail-open, defeating the one
    # command meant to always get through. Claude Code already tolerates a silent allow (exit 0, no
    # output), so printing an explicit allow JSON for it too is a no-op there — safe for both clients.
    if _is_bootstrap_command(hook_input):
        _log("gate_decision", decision="allow", reason_code="bootstrap", tool_name=tool)
        if _COPILOT_CLI_MODE:
            print(json.dumps({"permissionDecision": "allow"}))
        else:
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                }
            }))
        return

    # 2. Read-only Bash commands (ls, cat, grep, …) can't write code to disk or run another program,
    #     so there is nothing to scan — allow them WITHOUT requiring cx to be installed/authed. Removes
    #     the friction of gating a plain `ls` during setup. Allowlisted + shape-guarded so it can't be
    #     used to smuggle a write/exec (`ls; rm …`, `cat $(…)`, `> file` are all rejected).
    if _is_readonly_command(hook_input, tool):
        _log("gate_decision", decision="allow", reason_code="read_only", tool_name=tool)
        return

    # 2b. Files no Checkmarx engine can scan are not worth gating: ASCA, KICS and SCA each self-skip
    #     an unsupported path, so a README.md / .css / .sql write would have gone through UNSCANNED
    #     even on a healthy cx — blocking it on "cx isn't authenticated" is pure friction. Placed
    #     BEFORE the CX_BINARY check below so such a write is not blocked by a bad CX_BINARY either.
    #     Fails CLOSED on any uncertainty (unknown tool, missing path, unreadable config), so MCP
    #     calls and unrecognised assistants stay gated exactly as before. Restore the previous
    #     behaviour with CX_GATE_ALL_FILES=1.
    if not _is_scannable_file(hook_input):
        _log("gate_decision", decision="allow", reason_code="unscannable_file", tool_name=tool)
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
            "(its directory is empty in ${CLAUDE_PLUGIN_ROOT} in your shell, so use this literal "
            "command):\n    " + _bootstrap_command_str("install")
        )
        _deny(
            reason=(
                "The Checkmarx CLI (cx) is not installed. Security scanning cannot run, so this "
                "operation is BLOCKED. Run /cx-cli-setup to install and authenticate it, then retry."
            ),
            context=(
                "cx CLI is not installed on this machine (not found via CX_BINARY, the canonical "
                "store, or PATH). All agent actions are blocked fail-closed until it is installed and "
                "authenticated. IMMEDIATELY invoke the cx-cli-setup skill (via /cx-cli-setup). "
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
            "Invoke /cx-cli-setup (Phase 1b — Upgrade). To self-upgrade now, run "
            "the plugin's bundled bootstrap by its resolved absolute path:\n    {0}{1}".format(
                _bootstrap_command_str("upgrade"), _cx_binary_pin_note(effective_tier)
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
            "Invoke /cx-cli-setup. To reinstall now, run the plugin's bundled bootstrap "
            "by its resolved absolute path:\n    " + _bootstrap_command_str("install")
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
                "the backend may have been slow — retry the operation once. Otherwise run /cx-cli-setup "
                "to (re)authenticate, then retry."
            ),
            context=(
                "cx auth validate did not succeed within the gate's timeout — cx is either not "
                "authenticated (credentials missing or expired) OR the backend was slow/unreachable, so "
                "a valid session that simply timed out looks the same here. Retry once; if it persists, "
                "invoke the cx-cli-setup skill "
                "(/cx-cli-setup) for the guided flow. ASK THE DEVELOPER WHICH METHOD FIRST — do not "
                "assume OAuth and do not ask for a URL/tenant before this choice is made. There are two "
                "ways to authenticate, and they differ in who runs them:\n"
                "- API key (ask this first / simplest): the DEVELOPER runs this in their own terminal "
                "(it is a plaintext secret — do not type an API key yourself):\n    "
                + _cx_recovery_command_str("configure set --prop-name cx_apikey --prop-value <key>")
                + "\n" + _oauth_recovery_bullet(_load_admin_config())

                + "\n  It blocks until the developer finishes (~5 min) — run it with a long timeout or "
                "in the background.\n"
                "Shell commands are NOT blocked — you may run `cx version`, the bootstrap, tests and "
                "any other command freely; writes to files Checkmarx cannot scan are not blocked "
                "either. Only writes to scannable files wait for authentication "
                "succeeds."
            ),
            reason_code="unauthenticated",
            tool_name=tool,
            version_state=state,
        )

    # Auth verified — if a recorded `cx auth login` changed the stored credential, promote its
    # URL/tenant pair to offerable. Unconditional on purpose: the first gated call after a login can
    # come arbitrarily late (next-day session), so any freshness gate here would silently strand
    # pendings forever. Steady-state cost is one stat (no history file → immediate return).
    _promote_pending_login()

    # 6b. Scanner readiness. `cx auth validate` (step 6) and the native scanner authenticate
    #     DIFFERENTLY: validate accepts an OAuth refresh token, but `cx hooks claude-*` only
    #     extracts an API key and otherwise runs in SILENT PASS-THROUGH (allow everything, NO scan).
    #     A validate-OK-but-scanner-pass-through state is therefore a silent fail-OPEN — exactly the
    #     gap an OAuth `cx auth login` opens. Treat it as NOT authenticated for scanning and fail
    #     CLOSED with the same visible /cx-cli-setup message. UNKNOWN (probe error/timeout) defers to
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
                "allow everything UNSCANNED. Re-authenticate via the cx-cli-setup skill (/cx-cli-setup). "
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
    NOTE: reads sys.argv directly (not _COPILOT_CLI_MODE) because a crash inside
    _is_bootstrap_command() or any pre-mode-set code path means _COPILOT_CLI_MODE may still
    be False even for a Copilot CLI invocation — sys.argv is always reliable."""
    try:
        is_copilot = _COPILOT_CLI_MODE or "--copilot-cli" in sys.argv
        if is_copilot:
            print(json.dumps({
                "permissionDecision": "deny",
                "permissionDecisionReason": _tag(
                    "The Checkmarx security gate hit an internal error and could not evaluate "
                    "this action, so it is BLOCKED fail-closed. Re-run /cx-cli-setup, or set "
                    "CX_ALLOW_UNSCANNED=1 to bypass scanning (audited)."
                ),
            }))
        else:
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": _tag(
                        "The Checkmarx security gate hit an internal error and could not evaluate this "
                        "action, so it is BLOCKED fail-closed."
                    ),
                    "additionalContext": _tag(
                        "An unexpected error occurred inside cx_check.py. All agent actions remain "
                        "blocked until it is resolved. Re-run /cx-cli-setup, or set CX_ALLOW_UNSCANNED=1 "
                        "to bypass scanning (audited)."
                    ),
                }
            }))
    except Exception:
        pass


# The OBSERVER's matcher: any cx-looking executable token followed by `auth`/`configure`.
#
# Deliberately NOT _is_auth_recovery_command. That is a PERMISSION guard: it pins the absolute form to
# the gate's own resolved _cx_exe() so an attacker-chosen path can never be admitted. As an
# OBSERVATION filter that safety property inverts: a false negative is silent data loss. Accepting
# any path that ends in cx / cx.exe is safe here because this drives recording only, never a
# permission decision. Optional leading `&` covers Copilot CLI on Windows (`& "path" auth login`).
_OBSERVABLE_LOGIN_RE = re.compile(
    r'^\s*&?\s*"?(?:[^"\s]*[/\\])?cx(?:\.exe)?"?\s+(?:auth|configure)\b', re.IGNORECASE
)


def _observable_login_command(hook_input):
    """The command string of a bare `cx auth|configure` worth recording, or None.

    Looser than _is_auth_recovery_command (any path ending in cx/cx.exe, optional leading PowerShell
    `&`, optional PowerShell null-sink). Copilot CLI on Windows issues logins via the powershell tool
    with `& "path" auth login 1>$null`; dropping those would make remembered environments a no-op on
    the most common Copilot host."""
    command = _bash_command(hook_input)
    if not command:
        return None
    stripped = _PS_NULL_REDIRECT_RE.sub("", command).rstrip()
    s = stripped.lstrip()
    if s.startswith("& "):
        after = s[2:].lstrip()
        for tok in _SHELL_CHAINING:
            if tok != "&" and tok in after:
                return None
        check = s
    else:
        if any(tok in stripped for tok in _SHELL_CHAINING):
            return None
        if _has_unsafe_redirect(stripped):
            return None
        check = stripped
    if _OBSERVABLE_LOGIN_RE.match(check) is None:
        return None
    return stripped


def _is_observable_login_command(hook_input):
    """True for a bare shell `<any cx path> auth|configure …` worth recording."""
    return _observable_login_command(hook_input) is not None


def cx_record_login():
    """OBSERVER-ONLY mode, invoked as `cx_check.py record-login` by hooks/cx_record_login.sh.
    Notes the URL/tenant of a `cx auth login` so a later logged-out session can offer it instead of
    re-asking the developer from scratch. Cannot block: never calls _deny, and main() forces exit 0."""
    hook_input = _read_hook_input()
    command = _observable_login_command(hook_input)
    if command:
        _record_login_attempt(command)


def main():
    # HOST-ONLY mode for hooks/_cx_ide_host.sh: exit 0 when the nearest Copilot ancestor is VS Code's
    # bundled Copilot runtime (rule 4 above), else 1. The shell cannot read the Windows process tree.
    if len(sys.argv) > 1 and sys.argv[1] == "vscode-runtime-host":
        sys.exit(0 if _nearest_copilot_parent() == "vscode-runtime" else 1)

    if _should_seed_user_config():
        _seed_user_config()   # best-effort first-run copy to ~/.checkmarx; never raises

    # SEED-ONLY mode for hooks/cx_run.sh: the seeding above is the whole job. Lets the MCP bridge spawn
    # (session start — the nearest thing Copilot CLI has to an install event) create the user copy
    # without waiting for the first shell/file-write hook. Prints nothing; never blocks.
    if len(sys.argv) > 1 and sys.argv[1] == "seed-user-config":
        sys.exit(0)

    # OBSERVER mode: record-login must NEVER block a tool call, whatever happens inside it.
    if len(sys.argv) > 1 and sys.argv[1] == "record-login":
        try:
            cx_record_login()
        except BaseException:
            pass
        sys.exit(0)

    # _deny()/_allow_with_warning() raise SystemExit with the decision JSON already printed.
    # ANY other exception is an internal gate failure → fail CLOSED (deny).
    # Claude Code: exit 2 (non-zero = deny; exit 1 = uncaught error = fail-open).
    # Copilot CLI: exit 0 (non-zero is treated as hook error = fail-open, not a denial).
    try:
        cx_check()
    except SystemExit:
        raise
    except BaseException:
        _fail_closed_on_crash()
        is_copilot = _COPILOT_CLI_MODE or "--copilot-cli" in sys.argv
        sys.exit(0 if is_copilot else 2)


if __name__ == "__main__":
    main()
