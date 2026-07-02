# Changelog

All notable changes to the **cx-security** plugin are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project follows
[Semantic Versioning](https://semver.org/).

## [1.6.0] — Unreleased

Cross-OS hardening, structured logging, and production packaging. Security-relevant changes close
verified *fail-open* holes — cases where an unscanned change could previously slip through.

### Security

- **Scanner pass-through fail-open closed** — the gate verified auth with `cx auth validate`, but
  the native scanner `cx hooks claude-*` runs in **silent pass-through** — allowing every file write
  / command **UNSCANNED** — whenever it cannot establish an authenticated session from the stored
  credential (e.g. a stale/expired token or an unreachable backend), even though `cx auth validate`
  passed. A command-injection file slipped straight through in that state. The gate now probes the
  scanner's own readiness and, when it would pass-through, **denies fail-closed** with the visible
  `/cx-cli-setup` re-authenticate message — so a credential the scanner can't actually use can no
  longer silently disable scanning. Scanner-readiness is cached, keyed to the cx binary identity
  **and** the credential file mtime, so re-authenticating is picked up immediately. (Upstream
  `cx hooks` should fail *closed* when it cannot authenticate, rather than silent pass-through —
  tracked as a cx-side dependency.)
- **Windows fail-open closed** — hooks now invoke `sh` (always Git Bash) instead of bare `bash`,
  which Windows resolved to the System32 WSL stub (exit 127 → unscanned, action allowed).
- **Linux fail-open closed** — the Python probe now requires Python 3, so a Python 2 interpreter
  can no longer pass a file with a silent `SyntaxError`.
- **Capability gate** — a build that meets the numeric version floor but lacks the required
  subcommands is reported `incapable` and blocked, instead of being trusted on version number alone.
- **`setx` PATH corruption fixed** — Windows install uses the User-scope .NET environment API
  instead of `setx`, which truncated `PATH` at 1024 chars and folded System into User.
- **Shell carve-out tightened** — the POSIX taint list now rejects `<` / `>` (process
  substitution), matching the Python gate so neither path is more permissive than the other.
- **Caches and bypass-audit relocated** to `~/.checkmarx/agent-logs/` (dir `0700`, files `0600`).

### Added

- **Structured, redacted logging** (`hooks/cx_log.py`) — one JSONL record per gate decision under
  `~/.checkmarx/agent-logs/<assistant>/cx-security.jsonl`, with a per-event redaction allowlist
  (only typed, allowlisted fields are written; secrets, source, and free strings are dropped),
  size rotation, and never-raises-into-the-gate behavior. Controlled by
  `CX_LOG_DIR` / `CX_LOG_DISABLE` / `CX_ASSISTANT`.
- **`CX_BINARY`** — point the gate at an absolute `cx` path when it isn't on `PATH`; validated as
  real, recent, capable, and authenticated before it is trusted.
- **Download checksum verification** in `cx-bootstrap.sh` — the downloaded asset is SHA-256 checked
  against the release's published checksums before extraction; `CX_REQUIRE_CHECKSUM=1` makes an
  unverifiable download a hard failure.
- **Extracted, unit-tested helper modules** — `cx-asset-resolver.sh` (OS/arch → asset) and
  `cx-path-probe.sh` (first writable on-PATH dir).
- **LICENSE** and this **CHANGELOG**; a plugin-level **README**.

### Changed

- **`cx-cli-setup` skill** restructured from a 516-line monolith into a lean router plus a
  `references/` set (manual install, Windows PATH activation, OAuth, upgrade, MCP, troubleshooting).
- **MCP** uses the native `cx mcp bridge` subcommand (`.mcp.json` `command: "cx"`).
- **Minimum-version floor documented** — the numeric minimum (`scripts/cx-min-version`) is a floor;
  the runtime capability probe (`cx mcp bridge` / `cx hooks claude-*`) is the authoritative gate.

### Fixed

- **Windows install no longer blocked by a false checksum mismatch** — `compute_sha256` extracted
  the first field of the `sha256sum` line, but GNU coreutils (Git for Windows) prepend a literal
  backslash to that line when the file path contains backslashes (the staging path comes from the
  Windows `%TEMP%`). The digest came back as `\<hash>` and aborted **every** Windows install as a
  bogus mismatch. The backslash escape is now stripped, so verification compares correctly and still
  fails closed on a genuine mismatch. (Confirmed against real Git-Bash `sha256sum`.)
- **OAuth login now runs automatically instead of being handed to the user** — the `unauthenticated`
  and `scanner_passthrough` deny messages told the agent *"all agent actions remain blocked,"* so it
  punted `cx auth login` to the developer with the `!` prefix and the browser never opened on its own.
  The messages (and `references/oauth.md`) now state that the gate's auth-recovery carve-out permits
  `cx auth …` / `cx configure …` through the Bash tool even while blocking, so the agent runs
  `cx auth login` itself and the browser opens automatically. No gate-logic or ast-cli change.

### Notes

- Versions prior to `1.6.0` predate this changelog.
- cx-side finding-level (ASCA/SCA) logging is tracked as an `ast-cli` dependency and is not part of
  this plugin release.
