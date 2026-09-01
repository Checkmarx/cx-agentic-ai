"""cx_log — structured, redacted JSONL logging for the checkmarx-devassist gate.

A deep module with a tiny surface: `log_event(event, **fields)`. Two guarantees make it safe to
call from inside the fail-closed gate:

  1. It NEVER raises into the caller — every failure (disabled, unwritable dir, serialization
     error) is swallowed.
  2. It NEVER emits anything but ALLOWLISTED, TYPED fields. Each event declares the exact keys it
     may write and a coercer per key; any other key the caller passes is dropped, and any value
     that does not coerce to a safe type is omitted. No secret, token, source code, prompt, or
     free-form string can reach the log — even if a caller passes one by mistake.

Records are written to `<CX_LOG_DIR or ~/.checkmarx/agent-logs/<assistant>>/checkmarx-devassist.jsonl`,
size-rotated, dir 0700 / file 0600. Set `CX_LOG_DISABLE=1` to turn logging off entirely.
"""

import json
import os
import platform
import re
import time

_LOG_FILE_NAME = "checkmarx-devassist.jsonl"
_MAX_BYTES = 1_000_000  # rotate at ~1 MB
_ROTATE_KEEP = 3        # keep checkmarx-devassist.jsonl.1 .. .3
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")

# Named permission / limit constants — used everywhere below so ASCA does not
# flag bare octal literals as "magic numbers" (they are intentional POSIX constants).
_DIR_MODE  = 0o700   # user-only directory: rwx------
_FILE_MODE = 0o600   # user-only file:      rw-------
_EXIT_CODE_MAX = 255 # POSIX exit-code ceiling used by _as_int coercer
_TOKEN_MAX_LEN = 64  # maximum length of a safe identifier token


# --- coercers: the redaction core. Each maps an arbitrary value to a SAFE value, or None to omit.

def _token(value):
    """A short, safe identifier, or None. Rejects whitespace, quotes, slashes, and anything else
    that could carry an injection or a secret — a free string that is not a clean identifier is
    DROPPED, never logged."""
    if isinstance(value, str) and _SAFE_TOKEN.match(value):
        return value
    return None


def _as_bool(value):
    return value if isinstance(value, bool) else None


def _as_int(value):
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) and 0 <= value <= _EXIT_CODE_MAX else None


def _enum(allowed):
    """Coercer that returns the value only if it is one of `allowed`, else the constant 'other'.
    A caller-supplied value can never leak — it is either a known constant or 'other'."""
    def coerce(value):
        return value if value in allowed else "other"
    return coerce


_VERSION_STATES = _enum({"ok", "dev", "below", "incapable", "unrunnable", "unknown"})

# Per-event ALLOWLIST. Only these keys are ever written, each through its coercer.
_EVENTS = {
    "gate_decision": {
        "decision": _enum({"allow", "deny", "pass"}),
        "reason_code": _token,
        "tool_name": _token,
        "version_state": _VERSION_STATES,
        "exit_code": _as_int,
    },
    # CX_ALLOW_UNLICENSED=1 bypass — distinct from unscanned_override (different env var / policy).
    "unlicensed_override": {
        "tool_name": _token,
    },
    "bootstrap": {
        "mode": _enum({"install", "upgrade", "unknown"}),
        "allowed": _as_bool,
    },
    "admin_config": {
        # Outcome of loading the bundled admin onboarding config
        # (config/cx-onboarding.properties). NEVER carries the offending VALUE (which an admin -- or a
        # tamperer -- controls); only WHICH known key was accepted/rejected and the outcome, so a bad
        # config leaves an audit trail without echoing its payload into the log.
        "result": _enum({"loaded", "invalid", "absent"}),
        "key": _enum({"cx_base_auth_uri", "cx_tenant"}),
    },
    "login_history": {
        # Lifecycle of the remembered base-URL/tenant login pairs (cx_login_history.json):
        # recorded (a `cx auth login` attempt was captured as pending), promoted (auth succeeded →
        # the pair becomes offerable), offered (pairs were embedded into an auth-recovery deny),
        # invalid (a tampered/garbled entry was dropped on read), pruned (a stale or superseded
        # pending attempt was discarded), skipped (an `auth login` went past that could NOT be
        # parsed into a valid URL/tenant pair, so nothing was remembered — the one event that makes
        # a silent drop diagnosable). NEVER carries the URL or tenant value itself — only the
        # action and, for offers, how many pairs were shown.
        "action": _enum({"recorded", "promoted", "offered", "invalid", "pruned", "skipped"}),
        "count": _as_int,
    },
    "capability_probe": {
        "result": _as_bool,
        "version_state": _VERSION_STATES,
    },
    "scan_decision": {
        # The stage-2 native `cx hooks claude-pre-*` scanner's own allow/deny — distinct from
        # "gate_decision" (the stage-1 readiness gate). Never carries the finding/reason text
        # itself, only the outcome, so a real vulnerability's details never reach this log.
        # `reason_code` (not a raw exit code) says WHY: "vulnerability_detected" for a genuine,
        # well-formed deny (the scanner's own JSON carried a permissionDecision:deny), vs
        # "error_during_block" for a deny that fell back to the raw fail-closed exit-2 path without
        # that structured output (an unexpected/error condition, not necessarily a real finding).
        "decision": _enum({"allow", "deny"}),
        "tool_name": _token,
        "reason_code": _enum({"vulnerability_detected", "error_during_block", "no_issues_found"}),
    },
    "mcp_connect": {
        # Every attempt by hooks/cx_run.sh to spawn/respawn `cx mcp bridge` (session start,
        # /restart, reconnect) — success or denial — so a connect failure always has an
        # exact, on-disk reason instead of only Copilot's generic "-32000 / failed to reconnect".
        # No caller-supplied free text: `message` is synthesized below from `reason_code` (an
        # allowlisted enum) plus the already-token-validated version fields, so this event can never
        # carry raw subprocess output or anything else a caller might pass by mistake.
        "result": _enum({"ok", "denied"}),
        "reason_code": _enum({"ok", "dev", "below", "incapable", "unrunnable",
                               "cx_absent", "cx_binary_invalid"}),
        "version_have": _token,
        "version_min": _token,
        # Which resolution tier supplied the checked binary — mirrors cx_check.py's
        # _cx_exe_with_tier(). Drives the CX_BINARY-pin note appended to `message` below: a denial
        # on a CX_BINARY-resolved binary will NOT self-heal from a bootstrap upgrade (the bootstrap
        # only ever writes the canonical store, which a CX_BINARY pin continues to shadow).
        "tier": _enum({"binary", "canonical", "path"}),
    },
}

# Fixed, first-party message templates for "mcp_connect" — never derived from caller input. Formatted
# ONLY with `version_have`/`version_min`, which are themselves already constrained to _SAFE_TOKEN by
# the schema's `_token` coercer above, so the rendered message can never carry an injected/secret
# value even if a caller passed one.
_MCP_CONNECT_MESSAGES = {
    "ok": "cx v{have} is capable and current (>= v{min}) — mcp bridge starting.",
    "dev": "cx reports a 'dev' build and is capable — mcp bridge starting.",
    "below": "cx v{have} is below the required v{min} — mcp bridge blocked; run /checkmarx-cli-setup to upgrade.",
    "incapable": ("cx v{have} is missing the 'mcp bridge' subcommand (capability-incomplete build) — "
                  "mcp bridge blocked; run /checkmarx-cli-setup."),
    "unrunnable": "cx did not report a usable version ('cx version' failed or was unparseable) — mcp bridge blocked.",
    "cx_absent": ("cx CLI could not be resolved via CX_BINARY, the canonical store, or PATH — mcp "
                  "bridge blocked; run /checkmarx-cli-setup to install."),
    "cx_binary_invalid": ("CX_BINARY is set but invalid (not absolute / missing / not executable); "
                          "ignored, falling back to the canonical store or PATH."),
}

# Appended to `message` when a "denied" mcp_connect has tier == "binary" — see the schema comment
# above. Same first-party guarantee as _MCP_CONNECT_MESSAGES: a fixed, hardcoded sentence, never
# derived from caller input.
_CX_BINARY_PIN_NOTE = (
    " Note: CX_BINARY is pinned to this exact binary and takes priority over the canonical store, "
    "so running the bootstrap will NOT fix this — unset CX_BINARY, replace the binary at that "
    "exact path, or repoint CX_BINARY at the canonical store after upgrading."
)


def _disabled():
    # ONLY the documented value disables logging; CX_LOG_DISABLE=0 / =false must NOT silently
    # turn off the audit trail (any other value, including unset, keeps logging on).
    return os.environ.get("CX_LOG_DISABLE") == "1"


def _assistant():
    """This cx_log.py copy is bundled ONLY with codex-devassist (each client plugin — cx-devassist,
    copilot-devassist, cursor-devassist, codex-devassist — ships its own independent copy), so the
    client is fixed, not detected. Hardcoded to 'codex' so logs always land under
    ~/.checkmarx/agent-logs/codex/, matching this plugin's own _agent_log_dir() default and its
    README."""
    return "codex"


def _log_dir():
    override = os.environ.get("CX_LOG_DIR")
    if override:
        return override
    return os.path.join(os.path.expanduser("~"), ".checkmarx", "agent-logs", _assistant())


_PLUGIN_VERSION = None


def _plugin_version():
    global _PLUGIN_VERSION
    if _PLUGIN_VERSION is not None:
        return _PLUGIN_VERSION
    _PLUGIN_VERSION = "unknown"
    # Try plugin.json candidates in priority order:
    #   1. plugin.json at the plugin root (shared, written by both Claude Code and Copilot CLI)
    #   2. .claude-plugin/plugin.json (Claude Code legacy location)
    #   3. .plugin/plugin.json (Copilot CLI location)
    # Reading any one that has a parseable version is sufficient.
    _base = os.path.dirname(os.path.abspath(__file__))
    for rel in (
        os.path.join("..", "plugin.json"),
        os.path.join("..", ".claude-plugin", "plugin.json"),
        os.path.join("..", ".plugin", "plugin.json"),
    ):
        try:
            path = os.path.join(_base, rel)
            with open(path) as f:
                data = json.load(f)
            version = _token(str(data.get("version", "")))
            if version:
                _PLUGIN_VERSION = version
                break
        except Exception:  # swallow — cx_log cannot use logging (would be circular)
            pass
    return _PLUGIN_VERSION


def _os_name():
    return _enum({"windows", "darwin", "linux"})(platform.system().lower())


def _chmod(path, mode):
    if os.name == "nt":
        return
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _open_0600(path, flags):
    """open() opener that creates new files with 0600 (POSIX) so a record is never briefly group/
    world readable between create-with-umask and a later chmod. On Windows the mode bits are
    ignored and the file already sits under the user profile (NTFS ACLs restrict it)."""
    return os.open(path, flags, _FILE_MODE)


def _rotate(path):
    try:
        if not os.path.exists(path) or os.path.getsize(path) < _MAX_BYTES:
            return
        oldest = "{0}.{1}".format(path, _ROTATE_KEEP)
        if os.path.exists(oldest):
            os.remove(oldest)
        for i in range(_ROTATE_KEEP - 1, 0, -1):
            src = "{0}.{1}".format(path, i)
            if os.path.exists(src):
                os.replace(src, "{0}.{1}".format(path, i + 1))
        os.replace(path, "{0}.1".format(path))
    except OSError:
        pass


def log_event(event, **fields):
    """Append one redacted JSONL record for `event`. Unknown events and non-allowlisted fields are
    dropped; values that do not coerce to a safe type are omitted. NEVER raises."""
    try:
        if _disabled():
            return
        schema = _EVENTS.get(event)
        if schema is None:
            return
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "assistant": _assistant(),
            "plugin_version": _plugin_version(),
            "os": _os_name(),
            "event": event,
        }
        for key, coerce in schema.items():
            if key in fields:
                safe = coerce(fields[key])
                if safe is not None:
                    record[key] = safe
        if event == "mcp_connect":
            template = _MCP_CONNECT_MESSAGES.get(record.get("reason_code"))
            if template:
                message = template.format(
                    have=record.get("version_have", "?"), min=record.get("version_min", "?"))
                if record.get("result") == "denied" and record.get("tier") == "binary":
                    message += _CX_BINARY_PIN_NOTE
                record["message"] = message
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
        directory = _log_dir()
        os.makedirs(directory, mode=_DIR_MODE, exist_ok=True)
        _chmod(directory, _DIR_MODE)
        path = os.path.join(directory, _LOG_FILE_NAME)
        _rotate(path)
        with open(path, "a", encoding="utf-8", newline="\n", opener=_open_0600) as f:
            f.write(line + "\n")
        _chmod(path, _FILE_MODE)
    except Exception:
        # Logging must NEVER break the gate.
        return


if __name__ == "__main__":
    # CLI entry point for callers outside Python (cx_run.sh's stage-2 scanner wrapper): a caller
    # process passes `event key=value key=value ...` as argv, never as a shell-interpolated string,
    # so a hostile value can't reach a shell. Same guarantees as log_event: never raises, drops
    # anything not on the per-event allowlist.
    import sys

    try:
        _event = sys.argv[1] if len(sys.argv) > 1 else ""
        _fields = dict(_arg.split("=", 1) for _arg in sys.argv[2:] if "=" in _arg)
        # argv values are always strings; exit_code's coercer (_as_int) requires a real int, so
        # convert here rather than loosen that allowlist gate. A non-numeric value is left as-is
        # and simply dropped by the coercer, same as any other bad exit_code.
        if "exit_code" in _fields:
            try:
                _fields["exit_code"] = int(_fields["exit_code"])
            except ValueError:
                pass
        log_event(_event, **_fields)
    except Exception:
        pass
