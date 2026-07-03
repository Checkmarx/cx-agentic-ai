# cx-security

A **fail-closed security gate** for Claude Code, backed by [Checkmarx CxOne](https://checkmarx.com/).

Before Claude writes code, edits a file, runs a shell command, or calls an MCP tool, the plugin asks
the Checkmarx `cx` CLI to scan the proposed action. If a real vulnerability or policy violation is
found — **or if the scanner can't be trusted to run** — the action is **blocked**, not silently
allowed. Found issues are remediated interactively through the bundled Checkmarx MCP server.

---

## How it works

Every gated tool call runs a **two-stage PreToolUse chain**:

1. **The gate** — `sh cx_check.sh` → `cx_check.py` — proves the scanner is trustworthy before anything
   is scanned: cx is **present → recent enough → capable → authenticated**. If any step can't be
   proven, it **denies (exit 2)** and stage 2 never runs.
2. **The scanner** — a native `cx hooks claude-*` subcommand that performs the actual analysis and
   decides whether to allow or block the action.

| Tool event | Gate | Native scanner | What it checks |
|---|---|---|---|
| `Write` / `Edit` | `cx_check` | `cx hooks claude-pre-file-write` | Static analysis (ASCA / SAST) of the proposed file content |
| `Bash` | `cx_check` | `cx hooks claude-pre-tool-use` | Command & dependency policy — open-source / SCA checks on installs and manifest edits |
| MCP tool calls (`mcp__*`) | `cx_check` | `cx hooks claude-pre-tool-use` | Policy check before the MCP call is allowed |
| Session stop | — | `cx hooks claude-stop` | Session-end hook |

The scanning logic itself lives in the `cx` CLI (maintained centrally by Checkmarx); this plugin is a
thin, hardened wrapper that **guarantees cx is ready, installs it when missing, and wires the
remediation MCP** — nothing more.

### Remediation (MCP)

When a finding needs fixing, remediation runs through the **Checkmarx MCP server** (`cx mcp bridge`),
declared in `.mcp.json` and started automatically by Claude Code — no `claude mcp add`, no registration
step. It exposes code- and package-remediation tools (`mcp__Checkmarx__codeRemediation`, …) that the
agent calls directly. A single `cx` sign-in covers both the CLI and the MCP. See
[`skills/cx-cli-setup/references/mcp.md`](skills/cx-cli-setup/references/mcp.md).

---

## Fail-closed by design

The gate is engineered so that **uncertainty blocks.** Only the hook's `exit 2` (or
`permissionDecision: deny`) blocks a tool call; *anything else is treated by Claude Code as
non-blocking*. So every "can't evaluate" path is deliberately routed to `exit 2`, and the gate is
hardened against the cross-OS holes that would otherwise **fail open** (let an unscanned action
through):

- **Windows** — hooks invoke `sh` (which only ever resolves to Git Bash), never bare `bash` (which
  Windows resolves to the System32 WSL stub → exit 127 → unscanned).
- **Linux / macOS** — the launcher requires Python 3, and all shipped scripts are pinned to LF line
  endings, so a stray Python 2 or a `\r` can't slip an action past the scan.
- **Any OS** — an unexpected error inside the gate denies fail-closed instead of crashing through.

If cx is missing, below the minimum version, missing the required subcommands (`incapable`), or
unauthenticated, the gate denies with a clear, actionable message pointing at `/cx-cli-setup`.

---

## Plugin structure

```
plugins/cx-security/
├── .claude-plugin/
│   └── plugin.json              # plugin manifest (name, version, license)
├── .mcp.json                    # declares the Checkmarx MCP server (cx mcp bridge); auto-discovered
├── README.md
├── hooks/
│   ├── hooks.json               # PreToolUse / Stop wiring
│   ├── cx_check.sh              # POSIX launcher — resolves Git Bash + Python 3, then runs the gate
│   ├── cx_check.py              # the fail-closed gate (present → recent → capable → authenticated)
│   └── cx_log.py                # structured, redacted JSONL logging
├── scripts/
│   ├── cx-bootstrap.sh          # download + checksum-verify + install the cx CLI (self-install)
│   ├── cx-asset-resolver.sh     # OS/arch → release asset name
│   ├── cx-path-probe.sh         # first writable on-PATH directory
│   └── cx-min-version           # minimum cx version (numeric floor)
└── skills/
    ├── cx-cli-setup/            # guided cx install + authentication (router + references/)
    └── cx-security-asca/        # ASCA remediation guidance
```

> Tests live at the **repo root** (`tests/`), outside the shipped plugin, so they aren't distributed.

---

## Prerequisites

The plugin installs the `cx` CLI for you, but it **cannot install its own host prerequisites** —
provide these first, or the gate can't run:

| Requirement | Windows | macOS | Linux |
|---|---|---|---|
| **POSIX shell** (`sh`, runs the hook) | **Git for Windows** — required; without it the hook can't launch | built-in | built-in |
| **Python 3** (gate logic) | install from python.org (**not** the Microsoft Store stub) | `xcode-select --install` or `brew install python3` | `apt`/`dnf`/`apk install python3` |
| **`curl` or `wget`** (bootstrap download) | bundled with Git for Windows | built-in `curl` | usually present; minimal images may need it |

If **Python 3** is missing, the gate **fails closed** — it blocks the action with an install hint
(safe). But if the **POSIX shell** (`sh`) is missing — the default on Windows without Git for Windows
— the hook cannot spawn at all and **fails OPEN**: Claude Code treats an un-spawnable hook as a
non-blocking error, so the action proceeds **UNSCANNED**. Claude Code offers no way to fail-close a
missing-shell hook (a hook needs a shell to run, and hook entries cannot be scoped to a single OS), so
**Git for Windows is a hard prerequisite** — install and verify it *before* relying on the gate.
Without it, Claude Code's own Bash tool does not work either, so this is already part of a supported
Windows setup.

Then the **`cx` CLI** itself, which the bundled **`cx-cli-setup`** skill installs (with download
checksum verification), puts on PATH, and authenticates (API key or OAuth). The minimum version is a
numeric floor in `scripts/cx-min-version`; the real capability decision is a runtime probe (the
`cx mcp bridge` and `cx hooks claude-*` subcommands must all respond to `--help`).

---

## Installation

**Local marketplace** (recommended for on-prem / team use):

```bash
claude plugin marketplace add /path/to/cxone-scanners
claude plugin install cx-security@cx-secured-agent
```

Verify:

```bash
claude plugin list      # cx-security@cx-secured-agent  ✔ enabled
```

**Direct plugin-dir** (quick local testing):

```bash
claude --plugin-dir /path/to/cxone-scanners/plugins/cx-security
```

After updating hook scripts, reload them into the session:

```
/reload-plugins
```

On first use the gate will detect that `cx` is missing and walk you through installing and
authenticating it via the **`cx-cli-setup`** skill (`/cx-cli-setup`).

---

## Configuration

All optional — sensible defaults apply.

| Variable | Purpose |
|---|---|
| `CX_BINARY` | Absolute path to `cx` when it isn't on `PATH` (validated: must be a real, recent, capable, authenticated cx). |
| `CX_LOG_DIR` | Override the log directory (default `~/.checkmarx/agent-logs/<assistant>/`). |
| `CX_LOG_DISABLE=1` | Turn structured logging off entirely. |
| `CX_ASSISTANT` | Label the assistant in logs (default `claude`). |
| `CX_REQUIRE_CHECKSUM=1` | Make `cx-bootstrap.sh` refuse to install an asset it can't checksum-verify. |
| `CX_ALLOW_UNSCANNED=1` | Audited emergency bypass — runs the action **unscanned** and records it to the audit log. |

---

## Privacy & logging

The gate writes one redacted JSONL record per decision to
`~/.checkmarx/agent-logs/<assistant>/cx-security.jsonl`. Logging uses a **redaction allowlist**: each
event declares the exact keys it may write and a type coercer per key. Anything else — source code,
secrets, tokens, prompts, free-form strings — is dropped before it can reach disk. The MCP bridge
sends your credential only in the `Authorization` header, never to chat or logs. Logging never raises
into the gate, and `CX_LOG_DISABLE=1` turns it off.

---

## License

MIT (declared in `plugin.json`).
