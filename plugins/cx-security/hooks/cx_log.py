"""cx_log — structured, redacted JSONL logging for the cx-security gate.

A deep module with a tiny surface: `log_event(event, **fields)`. Two guarantees make it safe to
call from inside the fail-closed gate:

  1. It NEVER raises into the caller — every failure (disabled, unwritable dir, serialization
     error) is swallowed.
  2. It NEVER emits anything but ALLOWLISTED, TYPED fields. Each event declares the exact keys it
     may write and a coercer per key; any other key the caller passes is dropped, and any value
     that does not coerce to a safe type is omitted. No secret, token, source code, prompt, or
     free-form string can reach the log — even if a caller passes one by mistake.

Records are written to `<CX_LOG_DIR or ~/.checkmarx/agent-logs/<assistant>>/cx-security.jsonl`,
size-rotated, dir 0700 / file 0600. Set `CX_LOG_DISABLE=1` to turn logging off entirely.
"""

import json
import os
import platform
import re
import time

_LOG_FILE_NAME = "cx-security.jsonl"
_MAX_BYTES = 1_000_000  # rotate at ~1 MB
_ROTATE_KEEP = 3        # keep cx-security.jsonl.1 .. .3
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")


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
    return value if isinstance(value, int) and 0 <= value <= 255 else None


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
    "unscanned_override": {
        "tool_name": _token,
    },
    "bootstrap": {
        "mode": _enum({"install", "upgrade", "unknown"}),
        "allowed": _as_bool,
    },
    "capability_probe": {
        "result": _as_bool,
        "version_state": _VERSION_STATES,
    },
}


def _disabled():
    # ONLY the documented value disables logging; CX_LOG_DISABLE=0 / =false must NOT silently turn
    # off the audit trail (any other value, including unset, keeps logging on).
    return os.environ.get("CX_LOG_DISABLE") == "1"


def _assistant():
    return _token(os.environ.get("CX_ASSISTANT", "")) or "claude"


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
    try:
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", ".claude-plugin", "plugin.json"
        )
        with open(path) as f:
            data = json.load(f)
        version = _token(str(data.get("version", "")))
        if version:
            _PLUGIN_VERSION = version
    except Exception:
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
    return os.open(path, flags, 0o600)


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
            "ts": int(time.time()),
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
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
        directory = _log_dir()
        os.makedirs(directory, mode=0o700, exist_ok=True)
        _chmod(directory, 0o700)
        path = os.path.join(directory, _LOG_FILE_NAME)
        _rotate(path)
        with open(path, "a", encoding="utf-8", newline="\n", opener=_open_0600) as f:
            f.write(line + "\n")
        _chmod(path, 0o600)
    except Exception:
        # Logging must NEVER break the gate.
        return
