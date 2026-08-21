"""Cross-shell command handling for cx-devassist-cursor — the SINGLE place that knows how
PowerShell, cmd.exe, bash and sh differ.

Two jobs, both of which used to be duplicated (and drifting) across hooks/cx_check.py and
hooks/_cx_bootstrap_match.sh:

1. PARSING what the agent proposed. Cursor hands a hook whatever string the agent's shell would
   run, and on Windows Cursor's default shell is PowerShell — so the SAME logical command
   (`cx auth login …`) legitimately arrives in many syntactic disguises: a `bash -c '…'` wrapper,
   a `powershell -NoProfile -Command "& \\"<path>\\" …"` wrapper, a `cmd /c "…"` wrapper, a bare
   PowerShell line using the `&` call operator, single- vs double-quoted paths, and paths written
   with `%LOCALAPPDATA%` / `$env:LOCALAPPDATA` / `$LOCALAPPDATA` / `~`. `normalize()` reduces all of
   those to ONE bare command string that the carve-out matchers in cx_check.py can compare against a
   trusted path — so a legitimate auth/bootstrap command is recognized no matter which shell the
   agent is driving. Without this, every non-bash rendering was silently DENIED, including the very
   `cx auth login` the gate's own deny message tells the agent to run.

2. RENDERING the commands the plugin tells the agent to run. A quoted absolute path is a bare string
   expression in PowerShell (it needs the `&` call operator), stdout suppression is `1>/dev/null` in
   bash but `1>$null` in PowerShell and `1>NUL` in cmd, and a JSON `--data` argument needs
   Cursor-specific quoting (see quote_json_data_for_cursor()) on top of the per-shell differences.
   `render_invocation()` / `variants_block()` emit syntax that is valid for the target shell instead
   of a bash-only string the agent then has to fix up by hand.

SECURITY NOTE — normalization NEVER relaxes the gate. It only widens the set of SPELLINGS that can be
recognized; every recognized spelling is still put through the same chaining/redirect checks
(`has_chaining` / `has_unsafe_redirect`) and the same trusted-path equality in cx_check.py. Variable
references are expanded from the gate's OWN environment and the result is re-scanned, so an expansion
that introduces a metacharacter (e.g. `$env:Path`, which contains `;` on Windows) is rejected exactly
as a literal one would be. Unknown variables are left literal, which fails the path comparison — a
safe default. Pure library: no I/O, no subprocesses, never raises on ordinary string input.
"""

import os
import re

# --- Supported shells -----------------------------------------------------------------------------
# BASH and SH are separate identities only so a detected wrapper can be reported faithfully; they
# render and parse IDENTICALLY (see POSIX_SHELLS) because everything this module emits is POSIX.
POWERSHELL = "powershell"
CMD = "cmd"
BASH = "bash"
SH = "sh"

POSIX_SHELLS = (BASH, SH)
SUPPORTED_SHELLS = (POWERSHELL, CMD, BASH, SH)

# Human labels used in the multi-shell blocks embedded in deny messages.
SHELL_LABELS = {
    POWERSHELL: "PowerShell",
    CMD: "cmd.exe",
    BASH: "bash / sh",
    SH: "bash / sh",
}

# Order the variants block lists shells in when no single shell is confidently detected.
_VARIANT_ORDER = (POWERSHELL, BASH, CMD)

# Explicit operator escape hatch: an integrator that KNOWS which shell the agent drives can pin it
# rather than rely on detection. Accepts the canonical names plus the common executable spellings.
SHELL_OVERRIDE_ENV = "CX_AGENT_SHELL"
_SHELL_ALIASES = {
    "powershell": POWERSHELL, "powershell.exe": POWERSHELL, "pwsh": POWERSHELL, "pwsh.exe": POWERSHELL,
    "cmd": CMD, "cmd.exe": CMD, "command.com": CMD,
    "bash": BASH, "bash.exe": BASH, "gitbash": BASH, "git-bash": BASH, "zsh": BASH,
    "sh": SH, "dash": SH, "ash": SH,
}


# --- Wrapper unwrapping ---------------------------------------------------------------------------
# Cursor sends the command exactly as the agent's shell would run it, which means an outer
# interpreter wrapper whenever the command needs shell interpretation (a redirect, a call operator).
# Each pattern captures the inner command AND identifies the shell that wrapper implies — the single
# strongest signal available about which shell the agent is actually driving.
#
# `-c` is accepted alongside `-Command` because PowerShell accepts any unambiguous prefix of a
# parameter name, and `powershell -c "…"` is what several agents emit. `-EncodedCommand` is
# deliberately NOT unwrapped: base64 cannot be scanned for chaining, so decoding it would be a
# bypass. Such a command simply fails to match any carve-out and stays gated (fail closed).
#
# The PowerShell prefix before `-Command`/`-c` is matched with a LAZY `.*?`, not an enumerated list
# of single-token flags — PowerShell's own startup switches are not all bare flags: `-ExecutionPolicy
# Bypass`, `-WindowStyle Hidden`, `-InputFormat Text` each take a SEPARATE value token with no `-`
# prefix of its own. `-ExecutionPolicy Bypass -NoProfile -NonInteractive -Command "…"` is a completely
# ordinary way to invoke PowerShell non-interactively, and an earlier version of this pattern — which
# only accepted a run of `-flag` tokens with no value arguments — failed to unwrap it, leaving the
# ENTIRE wrapped string unrecognized by every carve-out (bootstrap, auth, setup diagnostics all
# denied even though the inner command was exactly the documented recovery command). The lazy prefix
# finds the FIRST `-Command`/`-c` token regardless of what preceded it; anything genuinely
# unwrap-worthy on a real PowerShell command line has -Command as its last switch before the payload.
_UNWRAPPERS = (
    # bash/sh -c '<inner>' — an embedded single quote means the shell string ended early, so the
    # remainder is not reliably attributable to this command: refuse rather than guess.
    (re.compile(r"^(?P<sh>bash|sh)\s+-c\s+'(?P<inner>.*)'$", re.DOTALL), "sq", None),
    (re.compile(r'^(?P<sh>bash|sh)\s+-c\s+"(?P<inner>.*)"$', re.DOTALL), "dq", None),
    (re.compile(
        r'^(?:powershell|pwsh)(?:\.exe)?\b.*?-(?:Command|c)\s+"(?P<inner>.*)"$',
        re.DOTALL | re.IGNORECASE), "dq", POWERSHELL),
    (re.compile(
        r"^(?:powershell|pwsh)(?:\.exe)?\b.*?-(?:Command|c)\s+'(?P<inner>.*)'$",
        re.DOTALL | re.IGNORECASE), "sq", POWERSHELL),
    # cmd's own doubled-quote wrapping: cmd /c ""<path>" auth … 1>NUL". cmd's quoting convention
    # allows <inner> to START with a literal quote, so no embedded-quote rejection applies here; any
    # chaining hidden inside is still caught by has_chaining() AFTER unwrapping. Same lazy-prefix
    # reasoning as PowerShell above: cmd flags like `/A:attributes` can carry a value too.
    (re.compile(r'^cmd(?:\.exe)?\b.*?/c\s+"(?P<inner>.*)"$',
                re.DOTALL | re.IGNORECASE), "raw", CMD),
    (re.compile(r'^cmd(?:\.exe)?\b.*?/c\s+(?P<inner>[^"].*)$',
                re.DOTALL | re.IGNORECASE), "raw", CMD),
)

# A LEADING PowerShell call operator — required syntax to invoke a quoted/absolute path directly, NOT
# shell chaining. Only the leading occurrence is ever stripped; an `&` anywhere else stays subject to
# has_chaining().
_LEADING_CALL_OPERATOR_RE = re.compile(r"^\s*&\s+")

# First token of a command, honoring all three quoting styles a shell may use for a path. Single
# quotes matter for PowerShell (`& 'C:\…\cx.exe' auth validate`), which was previously unrecognized.
_LEADING_TOKEN_RE = re.compile(
    r"""^\s*(?:"(?P<dq>[^"]+)"|'(?P<sq>[^']+)'|(?P<bare>\S+))(?P<rest>.*)$""", re.DOTALL)

# Shell-active characters that disqualify a command from ANY allow carve-out. `^` and `%` are
# cmd.exe's own escape / variable-expansion metacharacters: `^&` hides a literal `&` from cmd's
# parser and `%VAR%` expands before cmd sees the string, so a purely textual scan of a wrapped
# command cannot see through them. This check therefore runs AFTER expand_env_refs(), so a
# well-formed `%LOCALAPPDATA%` is resolved and gone by the time it runs while a leftover `%` (an
# unknown or malformed reference) still fails closed.
CHAINING_TOKENS = (";", "|", "&", "`", "$(", "\n", "^", "%")

# The ONLY redirect safe inside an allow carve-out: suppression to a null device — `/dev/null`
# (bash/sh/Git Bash), `$null` (PowerShell), `NUL` (cmd). The device name must be a COMPLETE token
# (`(?=\s|$|')`, not `\b`) so a real file whose name merely starts with it (`/dev/null.bak`) is not
# mistaken for suppression. Any other redirect could write the command's stdout — which for
# `cx auth login` is the LIVE token — to an attacker-chosen file. (`2>&1` and `&>` contain `&` and
# are already rejected by CHAINING_TOKENS.)
_NULL_REDIRECT_RE = re.compile(
    r"(?:\*|&|\d)?(?:>>?|<)\s*(?:/dev/null|\$null|NUL)(?=\s|$|')", re.IGNORECASE)

NULL_REDIRECTS = {POWERSHELL: "1>$null", CMD: "1>NUL", BASH: "1>/dev/null", SH: "1>/dev/null"}

# Variable references, in the four spellings the supported shells use. Order matters: the PowerShell
# `$env:NAME` / `${env:NAME}` forms must be tried BEFORE the bare POSIX `$NAME`, or `$env:LOCALAPPDATA`
# would match `$NAME` as the variable "env" and leave `:LOCALAPPDATA` behind.
_VAR_PATTERNS = (
    re.compile(r"%(?P<name>[A-Za-z_][A-Za-z0-9_]*)%"),                 # cmd.exe
    re.compile(r"\$\{env:(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}", re.IGNORECASE),   # PowerShell braced
    re.compile(r"\$env:(?P<name>[A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE),       # PowerShell
    re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}"),             # POSIX braced
    re.compile(r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)"),                 # POSIX bare
)

# A leading `~` that a shell would expand to the home directory — only in path position (start of the
# string or immediately after a quote/space) and only when followed by a separator, so a literal `~`
# inside a filename is untouched.
_TILDE_RE = re.compile(r"""(?:(?<=^)|(?<=["'\s]))~(?=[/\\])""")


def _shell_or_default(shell):
    """Coerce an arbitrary shell identifier to one of SUPPORTED_SHELLS (POSIX when unrecognized)."""
    if shell in SUPPORTED_SHELLS:
        return shell
    return _SHELL_ALIASES.get(str(shell or "").strip().lower(), BASH)


def is_posix(shell):
    return _shell_or_default(shell) in POSIX_SHELLS


def unwrap(command):
    """Peel interpreter wrappers off `command` and return (inner_command, wrapper_shell_or_None).

    Bounded to a few rounds so a nested wrapper (`cmd /c "powershell -Command …"`) is still reduced
    while a pathological input cannot loop. The FIRST wrapper recognized is what identifies the
    agent's shell; a `bash -c` / `sh -c` wrapper reports that POSIX shell too. A wrapper whose inner
    string cannot be attributed unambiguously (an embedded quote of the same kind that opened it) is
    left WRAPPED — the carve-out then simply does not match, which fails closed."""
    if not isinstance(command, str):
        return "", None
    wrapper = None
    for _round in range(3):
        for pattern, quoting, implied in _UNWRAPPERS:
            m = pattern.match(command)
            if not m:
                continue
            inner = m.group("inner")
            if quoting == "sq":
                if "'" in inner:
                    return command, wrapper
            elif quoting == "dq":
                if '"' in inner.replace('\\"', ""):
                    return command, wrapper
                inner = inner.replace('\\"', '"')
            if wrapper is None:
                wrapper = implied or _shell_or_default(m.groupdict().get("sh"))
            command = inner
            break
        else:
            break
    return command, wrapper


def strip_call_operator(command):
    """Strip a LEADING PowerShell call operator (`& `). Required to invoke a quoted or absolute path
    directly in PowerShell; it is not chaining, and only the leading occurrence is removed."""
    if not isinstance(command, str):
        return ""
    return _LEADING_CALL_OPERATOR_RE.sub("", command, count=1)


def expand_env_refs(text):
    """Expand `%NAME%`, `$env:NAME`, `${env:NAME}`, `${NAME}`, `$NAME` and a path-position `~` from
    the CURRENT environment, so a path the agent wrote symbolically compares equal to the resolved
    absolute path the gate knows about.

    An UNKNOWN variable is deliberately left literal rather than expanded to an empty string: an
    empty expansion could collapse `%WHATEVER%/Checkmarx/cx/cx.exe` into a path that accidentally
    matches something, whereas leaving it literal guarantees the comparison fails (and, for `%`, that
    the CHAINING_TOKENS scan rejects it outright). HOME/USERPROFILE fall back to the interpreter's own
    notion of `~` because Cursor's hook environment on Windows often has neither set."""
    if not isinstance(text, str) or not text:
        return text or ""

    def resolve(name):
        value = os.environ.get(name)
        if value:
            return value
        if name.upper() in ("HOME", "USERPROFILE"):
            try:
                return os.path.expanduser("~")
            except (OSError, ValueError):
                return None
        return None

    for pattern in _VAR_PATTERNS:
        def _sub(m):
            return resolve(m.group("name")) or m.group(0)
        # A bounded number of passes resolves nesting-free references without ever looping on a
        # value that itself looks like a reference (a `%A%` whose value contains `%A%`).
        for _round in range(2):
            expanded = pattern.sub(_sub, text)
            if expanded == text:
                break
            text = expanded
    try:
        home = os.path.expanduser("~")
    except (OSError, ValueError):
        home = ""
    if home:
        text = _TILDE_RE.sub(home.replace("\\", "\\\\"), text)
    return text


def has_chaining(command):
    """True when `command` contains a shell metacharacter that disqualifies every allow carve-out.
    Call AFTER expand_env_refs() so a resolved `%VAR%` does not read as a stray `%`.

    A LEADING PowerShell `&` call operator is stripped first — it is required syntax to invoke a
    quoted absolute path, NOT shell chaining. Without this, every `& \"C:\\…\\cx.exe\" auth login`
    line was rejected as chained even after normalize() when a caller checked the raw string."""
    if not isinstance(command, str):
        return True
    command = strip_call_operator(command)
    return any(token in command for token in CHAINING_TOKENS)


def has_unsafe_redirect(command):
    """True when `command` redirects to anything OTHER than a null device (see _NULL_REDIRECT_RE)."""
    if not isinstance(command, str):
        return True
    residual = _NULL_REDIRECT_RE.sub(" ", command)
    return ">" in residual or "<" in residual


def command_skeleton(command):
    """`command` with the contents of every quoted argument value blanked out, leaving only the
    characters OUTSIDE quotes. has_chaining()/has_unsafe_redirect() are a naive substring scan with
    no quoting awareness — correct for every command those checks are normally applied to (none of
    them legitimately contain a literal `;`/`%`/`>`/etc. at all), but WRONG for a command like
    `cx ignore-vulnerability --data "<json>"` or `--optional-flags "k=v;k=v"`, whose safely-quoted
    argument VALUES legitimately contain those characters. This is used ONLY by the
    ignore-vulnerability carve-out (see cx_check.py) — every other carve-out keeps calling
    has_chaining()/has_unsafe_redirect() on the raw string on purpose, so this cannot loosen them.

    Recognizes both escaping conventions this plugin's own renderers (and real shells) use for an
    embedded double quote inside a double-quoted value — doubled (`""`, PowerShell/cmd) and
    backslash-escaped (`\\"`, POSIX) — regardless of which shell is actually active, since this
    function does not know. Single-quoted regions are recognized too (no embedded-quote escaping,
    matching plain PowerShell/POSIX single-quote semantics).

    Conservative on purpose: if quoting never closes (an odd number of unescaped quotes), the
    ambiguity itself is suspicious, so the ORIGINAL command is returned unchanged rather than a
    partial skeleton — the caller's chaining/redirect scan then runs on the raw string exactly as it
    would have without this function, which can only reject, never wrongly allow, an unparseable
    command. Worst case for a well-formed command this can't recognize: the carve-out just doesn't
    match and the command falls back to the existing, slower default path — never a security
    regression, only a missed optimization."""
    if not isinstance(command, str):
        return command
    out = []
    i, n = 0, len(command)
    quote = None  # '"' or "'" while inside a quoted region, else None
    while i < n:
        ch = command[i]
        if quote == '"':
            if command[i:i + 2] in ('""', '\\"'):
                i += 2
                continue
            if ch == '"':
                quote = None
            i += 1
            continue
        if quote == "'":
            if ch == "'":
                quote = None
            i += 1
            continue
        if ch == '"' or ch == "'":
            quote = ch
            i += 1
            continue
        out.append(ch)
        i += 1
    if quote is not None:
        return command  # unterminated quote — ambiguous, scan the raw string instead
    return "".join(out)


def has_chaining_outside_quotes(command):
    """has_chaining(), computed on command_skeleton(command) instead of the raw string — see that
    function's docstring for why. Only the ignore-vulnerability carve-out uses this."""
    if not isinstance(command, str):
        return True
    # PowerShell --%: only the prefix is PowerShell-parsed; the suffix is passed through literally.
    return has_chaining(command_skeleton(strip_stop_parsing(command)))


def has_unsafe_redirect_outside_quotes(command):
    """has_unsafe_redirect(), computed on command_skeleton(command) instead of the raw string — see
    that function's docstring for why. Only the ignore-vulnerability carve-out uses this."""
    if not isinstance(command, str):
        return True
    return has_unsafe_redirect(command_skeleton(strip_stop_parsing(command)))


def normalize(command):
    """Reduce a raw agent command to the ONE bare command string the carve-out matchers compare:
    wrappers peeled, leading call operator stripped, variable references expanded.

    Returns (bare_command, wrapper_shell_or_None). Does NOT decide safety — the caller still applies
    has_chaining()/has_unsafe_redirect() and the trusted-path comparison. Keeping normalization and
    the safety checks separate is what lets the SAME normalizer serve both the gate and the renderer
    without either one relaxing the other."""
    inner, wrapper = unwrap(command)
    inner = strip_call_operator(inner)
    inner = expand_env_refs(inner)
    # The call operator can also sit INSIDE a wrapper we just peeled (`cmd /c "& '<path>' …"`), so
    # strip it once more after unwrapping rather than requiring a specific nesting order.
    return strip_call_operator(inner), wrapper


def leading_token(command):
    """Split `command` into (first_token, rest), honoring "double", 'single', and bare quoting.
    Returns (None, '') when there is no token."""
    if not isinstance(command, str):
        return None, ""
    m = _LEADING_TOKEN_RE.match(command)
    if not m:
        return None, ""
    for group in ("dq", "sq", "bare"):
        value = m.group(group)
        if value is not None:
            return value, m.group("rest")
    return None, ""


def detect_shell(command=None):
    """Best guess at the shell the AGENT is driving — used to order the rendered command variants.

    Precedence: an explicit CX_AGENT_SHELL pin -> the wrapper actually observed on `command` (the
    only first-hand evidence available) -> platform default. On Windows the platform default is
    PowerShell because that is Cursor's default shell there; $SHELL is deliberately IGNORED on
    Windows because it describes the Git-Bash `sh` THIS hook runs under, not the agent's shell.
    Detection is a presentation nicety only — every rendered variant is accepted by the gate, so a
    wrong guess costs the agent nothing but reading order."""
    override = _SHELL_ALIASES.get((os.environ.get(SHELL_OVERRIDE_ENV) or "").strip().lower())
    if override:
        return override
    if command:
        _bare, wrapper = unwrap(command)
        if wrapper:
            return wrapper
    if os.name == "nt":
        return POWERSHELL
    shell = os.environ.get("SHELL") or ""
    if shell:
        base = os.path.basename(shell).lower()
        alias = _SHELL_ALIASES.get(base)
        if alias:
            return alias
    return BASH


# --- Path normalization -------------------------------------------------------------------------

_GITBASH_DRIVE_COLON_RE = re.compile(r"^/([A-Za-z]):/(.*)$")
_GITBASH_DRIVE_SLASH_RE = re.compile(r"^/([A-Za-z])(/.*)?$")


def normalize_cx_filesystem_path(path):
    """Normalize a filesystem path for cx CLI arguments on Windows.

    Rewrites MSYS/Git-Bash spellings (`/c:/foo`, `/c/foo`) to a drive-rooted form cx's Go runtime
    can open (`C:/foo` / `c:\\foo` after native_path()). Preserves a leading `@` for @file syntax.
    Non-Windows paths are returned with forward slashes only."""
    if not isinstance(path, str):
        return ""
    path = path.strip()
    if not path:
        return ""
    atfile = path.startswith("@")
    if atfile:
        path = path[1:].lstrip()
    normalized = path.replace("\\", "/")
    m = _GITBASH_DRIVE_COLON_RE.match(normalized)
    if m:
        normalized = m.group(1).upper() + ":/" + m.group(2)
    else:
        m = _GITBASH_DRIVE_SLASH_RE.match(normalized)
        if m:
            drive = m.group(1).upper()
            rest = m.group(2) or "/"
            normalized = drive + ":" + rest
    if atfile:
        return "@" + normalized
    return normalized


# --- Rendering ------------------------------------------------------------------------------------

def native_path(shell, path):
    """`path` in the separator style the target shell's users expect: backslashes for PowerShell and
    cmd on Windows, forward slashes for bash/sh (where a backslash is an escape character, so a
    Windows path must be written with `/` to survive quoting intact)."""
    if not isinstance(path, str):
        return ""
    if is_posix(shell):
        return path.replace("\\", "/")
    if os.name == "nt":
        return path.replace("/", "\\")
    return path


def quote_path(shell, path):
    """`path` quoted so it survives as ONE argument even with spaces in it. Double quotes in every
    shell: PowerShell and cmd do not treat `\\` as an escape inside them, and bash paths are rendered
    with forward slashes by native_path() so there is nothing to escape."""
    return '"{0}"'.format(native_path(shell, path))


def quote_arg(shell, value):
    """An arbitrary VALUE (not a path) quoted for `shell`, using each shell's normal literal-string
    convention. Correct for a well-behaved shell client — NOT for Cursor's own JSON `--data`
    argument, which needs quote_json_data_for_cursor() instead (see there for why).

    POSIX and PowerShell both take single quotes (literal, so embedded `"` needs no escaping;
    PowerShell escapes an embedded `'` by doubling it, POSIX by closing/reopening). cmd.exe has NO
    literal-quote form at all: single quotes are ordinary characters there, so the value must be
    double-quoted with each inner `"` backslash-escaped."""
    value = "" if value is None else str(value)
    shell = _shell_or_default(shell)
    if shell == CMD:
        return '"{0}"'.format(value.replace('"', '\\"'))
    if shell == POWERSHELL:
        return "'{0}'".format(value.replace("'", "''"))
    return "'{0}'".format(value.replace("'", "'\\''"))


def quote_json_data_for_cursor(shell, value):
    """Cursor-specific quoting for a `cx ignore-vulnerability --data <json>` payload.

    Cursor's own command-execution layer can reformat a single-quoted argument into a
    double-quoted one before the real shell ever sees it (observed on Windows). Handing Cursor
    single-quoted JSON per the generic quote_arg() convention lets that reformatting strip/mangle
    the embedded `"` around JSON keys, producing a `'F' looking for beginning of object key
    string`-style parse failure on the cx side. To survive it, always double-quote-wrap the value
    here and pre-escape the embedded `"` the way Cursor's reformatting step expects to find them
    already escaped: doubled (`""`) for cmd/PowerShell, or backslash-escaped (`\\"`) for POSIX
    shells. This is deliberately a separate function from quote_arg() — quote_arg() stays correct
    for any other, non-Cursor-reformatting caller."""
    value = "" if value is None else str(value)
    shell = _shell_or_default(shell)
    if shell in (CMD, POWERSHELL):
        return '"{0}"'.format(value.replace('"', '""'))
    return '"{0}"'.format(value.replace('"', '\\"'))


def null_redirect(shell):
    """The stdout-suppression token for `shell` — `1>/dev/null` / `1>$null` / `1>NUL`. Used on
    `cx auth login`, whose stdout carries a LIVE refresh token that must never be captured."""
    return NULL_REDIRECTS[_shell_or_default(shell)]


def render_invocation(shell, exe, args="", suppress_stdout=False):
    """One executable invocation, valid as written in `shell`.

    The PowerShell case is the reason this function exists: a quoted string in command position is a
    STRING EXPRESSION there, not a command, so `"C:\\…\\cx.exe" auth validate` silently prints the
    path instead of running anything. PowerShell needs the `&` call operator. A bare `cx` (resolved
    from PATH) is a command NAME in every shell and needs neither quoting nor the operator."""
    shell = _shell_or_default(shell)
    bare_name = not (exe and (os.path.isabs(exe) or re.match(r"^[A-Za-z]:[\\/]", exe)))
    if bare_name:
        parts = [exe or "cx"]
    elif shell == POWERSHELL:
        parts = ["&", quote_path(shell, exe)]
    else:
        parts = [quote_path(shell, exe)]
    if args:
        parts.append(args)
    if suppress_stdout:
        parts.append(null_redirect(shell))
    return " ".join(parts)


def strip_stop_parsing(command):
    """Return the PowerShell-parsed prefix of `command` — everything before `--%`.

    After `--%`, PowerShell passes the remainder through to the native executable without
    re-parsing quotes or metacharacters. Carve-out safety checks must run only on the prefix."""
    if not isinstance(command, str):
        return command
    idx = command.find("--%")
    if idx == -1:
        return command
    return command[:idx].rstrip()


def strip_stop_parsing_flag(rest):
    """Remove a leading `--%` token from the remainder after the executable (PowerShell only)."""
    if not isinstance(rest, str):
        return rest
    return re.sub(r"^\s*--%\s+", "", rest, count=1)


def render_with_json_data(shell, exe, command_args, json_value, suppress_stdout=False):
    """One invocation where `json_value` is passed as a single `--data` argument — e.g.
    `cx ignore-vulnerability --scan-type asca --data "<json>"`. `command_args` is everything before
    `--data` (typically `ignore-vulnerability --scan-type asca`).

    On PowerShell, uses `--%` stop-parsing so PowerShell (and Cursor's own single-to-double-quote
    reformatting) leaves the remainder alone — but that remainder still reaches the target exe's
    OWN Windows argv parser (CommandLineToArgvW), which only preserves an embedded `"` when it is
    backslash-escaped inside one outer quoted region. Sending the JSON bare/unquoted after `--%`
    (as this used to do) gets every `"` silently stripped by that parser, corrupting
    `{"FileName":"x.py",...}` into unquoted-key `{FileName:x.py,...}` and producing a `looking for
    beginning of object key string`-style failure on the cx side — verified empirically via
    `ctypes.windll.shell32.CommandLineToArgvW`, and it matches exactly how
    `cursorplugin.IgnoreVulnerabilityCommand` in ast-cli already renders this on Windows. So: wrap
    once in an outer `"..."` and backslash-escape the inner `"`, same as that Go code.

    On cmd/bash, uses quote_json_data_for_cursor() (see that function's docstring) — a different,
    unrelated compensation for Cursor's own single-to-double-quote reformatting on the non-`--%`
    path; leave that one alone."""
    shell = _shell_or_default(shell)
    if shell == POWERSHELL:
        escaped = json_value.replace('"', '\\"')
        data_args = '--% {0} --data "{1}"'.format(command_args.strip(), escaped)
        return render_invocation(shell, exe, data_args, suppress_stdout=suppress_stdout)
    data_args = "{0} --data {1}".format(command_args.strip(), quote_json_data_for_cursor(shell, json_value))
    return render_invocation(shell, exe, data_args, suppress_stdout=suppress_stdout)


def render_ignore_vulnerability_atfile(
        shell, exe, scan_type, data_file, ignored_file_path, optional_flags="",
        suppress_stdout=False):
    """`cx ignore-vulnerability` using @file for `--data` — avoids inline JSON quoting issues.

    `data_file` and `ignored_file_path` are normalized from MSYS `/c:/…` spellings before rendering.
    `--data` is rendered as `@<path>` inside a quoted argument."""
    data_file = normalize_cx_filesystem_path(data_file).lstrip("@")
    ignored_file_path = normalize_cx_filesystem_path(ignored_file_path)
    data_arg = "@{0}".format(native_path(shell, data_file))
    args = "ignore-vulnerability --scan-type {0} --data {1} --ignored-file-path {2}".format(
        scan_type.strip(),
        quote_path(shell, data_arg),
        quote_path(shell, ignored_file_path),
    )
    if optional_flags:
        args = "{0} --optional-flags {1}".format(args, quote_arg(shell, optional_flags))
    return render_invocation(shell, exe, args, suppress_stdout=suppress_stdout)


def render_ignore_vulnerability_block(
        scan_type, data_file, ignored_file_path, optional_flags="", exe=None, detected=None):
    """Multi-shell block for suppressing a finding via @file — embed in deny guidance / skills."""
    exe = exe or "cx"
    shells = _VARIANT_ORDER if os.name == "nt" else (BASH,)
    if detected in shells:
        ordered = [detected] + [s for s in shells if s != detected]
    else:
        ordered = list(shells)
    variants = []
    seen = set()
    for shell in ordered:
        rendered = render_ignore_vulnerability_atfile(
            shell, exe, scan_type, data_file, ignored_file_path, optional_flags)
        if rendered in seen:
            continue
        seen.add(rendered)
        variants.append((shell, rendered))
    if len(variants) == 1:
        return "    " + variants[0][1]
    width = max(len(SHELL_LABELS[s]) for s, _ in variants) + 1
    lines = ["    {0:<{1}} {2}".format(SHELL_LABELS[s] + ":", width, cmd)
             for s, cmd in variants]
    return ("Run the line for YOUR shell (all forms are equivalent and all are allowed by the "
            "gate):\n" + "\n".join(lines))


def render_variants(exe, args="", suppress_stdout=False, shells=None):
    """[(shell, rendered_command)] for each target shell, DEDUPED on the rendered text — a bare `cx`
    on PATH renders identically everywhere, so it collapses to a single entry instead of repeating
    the same line three times."""
    out = []
    seen = set()
    for shell in (shells or _VARIANT_ORDER):
        rendered = render_invocation(shell, exe, args, suppress_stdout)
        if rendered in seen:
            continue
        seen.add(rendered)
        out.append((shell, rendered))
    return out


def variants_block(exe, args="", suppress_stdout=False, indent="    ", detected=None):
    """The command to embed in a deny message / additional_context, formatted for the agent to copy.

    A single indented line when every supported shell spells it identically (a bare `cx …`) or when
    the platform has only one relevant shell (macOS/Linux). Otherwise a labeled block with the
    DETECTED shell first, followed by the alternates — so a correct guess reads as a plain
    instruction while a wrong one still leaves the agent a line that works. Every variant listed is
    accepted by the gate's carve-outs, so switching lines never trades an allow for a deny."""
    detected = _shell_or_default(detected or detect_shell())
    # SH and BASH render identically and share one label, so collapse SH onto BASH for ordering —
    # otherwise an `sh`-detected session would fall through to the default order and list PowerShell
    # first even though its own form is the bash/sh one.
    if detected == SH:
        detected = BASH
    shells = _VARIANT_ORDER if os.name == "nt" else (BASH,)
    if detected in shells:
        ordered = [detected] + [s for s in shells if s != detected]
    else:
        ordered = list(shells)
    variants = render_variants(exe, args, suppress_stdout, ordered)
    if len(variants) == 1:
        return indent + variants[0][1]
    width = max(len(SHELL_LABELS[s]) for s, _ in variants) + 1
    lines = ["{0}{1:<{2}} {3}".format(indent, SHELL_LABELS[s] + ":", width, cmd)
             for s, cmd in variants]
    return ("Run the line for YOUR shell (all forms are equivalent and all are allowed by the "
            "gate):\n" + "\n".join(lines))
