# cx-devassist-cursor

A **fail-closed security gate** for **Cursor**, backed by
[Checkmarx CxOne](https://checkmarx.com/).

Before Cursor runs a shell command, calls an MCP tool, or writes/edits a file, the plugin asks the
Checkmarx `cx` CLI to scan the proposed action. Shell and MCP calls are blocked fail-closed if a real
vulnerability or policy violation is found — or if the scanner can't be trusted to run. File writes
are scanned silently via Cursor's `afterFileEdit` hook (which cannot block a completed write); if
findings remain when the agent tries to stop, remediation guidance is sent via the stop hook's
`followup_message`. Found issues are remediated interactively through the bundled Checkmarx MCP server
and cx-devassist skills.

Part of [Checkmarx Agentic AI](../../README.md). This plugin is entirely independent of
[`cx-devassist`](../cx-devassist/README.md) (the Claude Code plugin) — no files, hooks, or state
directories are shared between the two.

---

## How it works

Every gated action runs a **two-stage chain**:

1. **The gate** — `sh cx_check.sh` → `cx_check.py` — proves the scanner is trustworthy before anything
   is scanned: cx is **present → recent enough → capable → authenticated**. If any step can't be
   proven, it denies.
2. **The scanner** — a native `cx hooks cursor-*` subcommand that performs the actual analysis and
   decides whether to allow or block the action.

`hooks/hooks.json` wires the following:

| Cursor event | Gate | Scanner | Behavior |
|---|---|---|---|
| `beforeShellExecution` | `cx_check` | `cx hooks cursor-before-shell` | **Deny** if cx missing / not authed, or a real finding |
| `beforeMCPExecution` | `cx_check` | `cx hooks cursor-before-mcp` | **Deny** if cx missing / not authed, or a real finding |
| `afterFileEdit` | `cx_check` | `cx hooks cursor-file-edit-capture` | Scans the documented (`old_string`/`new_string`) diff silently and records findings for the stop hook; fire-and-forget — **cannot block** (the write already landed) |
| `stop` | — | `cx hooks cursor-stop` | Session end; if unresolved findings remain, sends rich remediation guidance via `followup_message` (same text as the former `additional_context`), up to 3 times, then lets the agent stop |

File-write findings cannot be blocked on Cursor; remediation guidance is delivered only when the
agent tries to stop, via `followup_message`. Shell/MCP gates still **deny** fail-closed.

**Scoped scanning:** Cursor's dedicated `afterFileEdit` hook documents a real diff
(`old_string`/`new_string` pairs). Its result is discarded by Cursor (fire-and-forget), but it scans
only the changed region — not the whole file — so pre-existing code elsewhere is not falsely flagged.
A full `Write` falls back to scanning the whole proposed content.

**Stop-hook remediation loop:** if a session had Checkmarx findings that are still present on disk
when the agent tries to stop, the stop hook sends the full remediation prompt (including the
cx-devassist skill to invoke) via `followup_message`, up to 3 times. If findings are fixed earlier,
the loop exits immediately with no follow-up. After 3 attempts, the agent is allowed to stop with a
final summary. A session the user explicitly aborted is respected as-is.

The scanning logic itself lives in the `cx` CLI (maintained centrally by Checkmarx); this plugin is a
thin, hardened wrapper that **guarantees cx is ready, installs it when missing, and wires the
remediation MCP** — nothing more.

### Remediation (MCP)

When a finding needs fixing, remediation runs through the **Checkmarx MCP server** (`cx mcp bridge`),
declared in `mcp.json` and loaded automatically when this plugin is installed under
`~/.cursor/plugins/local/`. It exposes code- and package-remediation tools
(`mcp__Checkmarx__codeRemediation`, …) that the agent calls directly. A single `cx` sign-in covers
both the CLI and the MCP.

---

## Fail-closed by design

The gate is engineered so that **uncertainty blocks** wherever Cursor allows it (shell and MCP calls).
Every "can't evaluate" path on those two gates is deliberately routed to a deny, and the gate is
hardened against cross-OS holes that would otherwise **fail open**:

- **Windows** — hooks invoke `sh` (which only ever resolves to Git Bash), never bare `bash` (which
  Windows resolves to the System32 WSL stub → exit 127 → unscanned).
- **Linux / macOS** — the launcher requires Python 3, and all shipped scripts are pinned to LF line
  endings, so a stray Python 2 or a `\r` can't slip an action past the scan.
- **Any OS** — an unexpected error inside the gate denies fail-closed instead of crashing through.

If cx is missing, below the minimum version, missing the required subcommands (`incapable`), or
unauthenticated, the gate denies with a clear, actionable message that names the exact bootstrap
command to run.

---

## Cross-shell behaviour (PowerShell · cmd.exe · bash · sh)

Cursor's Shell tool runs the workspace's default shell — **PowerShell** on Windows — and the four
supported shells disagree about invoking a quoted path (PowerShell needs the `&` call operator),
path separators, stdout suppression (`1>/dev/null` / `1>$null` / `1>NUL`), and variable references
(`$VAR` / `$env:VAR` / `%VAR%`). `hooks/cx_shell.py` is the single module that owns those differences,
in both directions:

- **Parsing.** Every command the gate evaluates is first normalized: `bash -c` / `sh -c` /
  `powershell -Command` / `powershell -c` / `cmd /c` wrappers are peeled, a leading `&` call operator
  is stripped, `"`/`'`/bare quoting is handled, and `%VAR%` / `$env:VAR` / `${VAR}` / `$VAR` / `~` are
  expanded. So the same logical `cx auth login` is recognized whichever shell wrote it. Normalization
  never relaxes the gate: the **expanded** string is what the chaining and redirect checks scan, so a
  variable whose value smuggles a metacharacter (`$env:Path` contains `;`) is rejected exactly as a
  literal one is, an unknown variable stays literal and fails the trusted-path comparison, and the
  path must still equal the canonical store / a `CX_BINARY` pin / a script inside this plugin.
- **Rendering.** Commands the plugin puts in front of the agent (deny `agent_message` /
  `additional_context`) are emitted **per shell**, detected shell first, so the agent always has a
  line that is valid as written. Every rendered form is accepted by the carve-out below, so switching
  lines never turns an allow into a deny. `skills/cx-cli-setup/references/shells.md` documents the
  same rules for the skills and rules.

**Trusted bootstrap/auth/setup commands always reach an allow.** Both shell stages (`cx_check.sh` and
`cx_run.sh`) consult one shared matcher — `_cx_bootstrap_match.sh`, which delegates to
`cx_check.py --match-trusted-setup` — so stage 1 and stage 2 can never disagree about the same command
(a disagreement blocks the call, since every hook in a Cursor matcher must allow). The trusted set is
the work that *establishes* the conditions the gate enforces, which is why gating it would be a
deadlock rather than a control:

| Trusted operation | Commands |
|---|---|
| Component download + install | `bash "<plugin>/scripts/cx-bootstrap.sh" install\|upgrade`, and the other bundled `scripts/*.sh` |
| Login / OAuth / token validation | `cx auth login\|logout\|validate\|register …` |
| Credential setup | `cx configure …` (including `configure set --prop-name cx_apikey`) |
| Session / licence validation | `cx hooks check-auth` |
| Pre-scan initialization probes | `cx version`, `cx utils env` |

Each still has to be a **bare** command — no chaining (`;`/`&&`/`|`), no substitution (`$(…)`,
backticks), no `^` (cmd's escape), and no redirect to a real file (only suppression to the null device,
so `cx auth login` cannot leak its token). Everything outside this set is gated exactly as before.

---

## Plugin structure

```
plugins/cx-devassist-cursor/
├── .cursor-plugin/
│   └── plugin.json              # Cursor manifest (hooks → hooks/hooks.json, mcp → mcp.json)
├── mcp.json                     # Checkmarx MCP server (${CURSOR_PLUGIN_ROOT})
├── README.md
├── config/
│   └── cx-onboarding.properties # OPTIONAL admin pre-fill of Checkmarx One URL + tenant (onboarding)
├── hooks/
│   ├── hooks.json               # Cursor hook wiring (${CURSOR_PLUGIN_ROOT}/hooks/ paths)
│   ├── hooks.json.template      # Template for install-hooks.sh (sed __CURSOR_PLUGIN_ROOT__ → absolute path)
│   ├── cx_check.sh              # POSIX launcher — resolves Git Bash + Python 3, then runs the gate
│   ├── cx_check.py              # the fail-closed gate (present → recent → capable → authenticated)
│   ├── cx_shell.py              # cross-shell command parsing + rendering (PowerShell/cmd/bash/sh)
│   ├── _cx_bootstrap_match.sh   # trusted-setup matcher for the shell stages (delegates to cx_check.py)
│   ├── cx_run.sh                # resolves cx by absolute path; runs the native scanner + MCP bridge
│   └── cx_log.py                # structured, redacted JSONL logging
├── scripts/
│   ├── cx-bootstrap.sh          # download + checksum-verify + install the cx CLI (self-install)
│   ├── cx-asset-resolver.sh     # OS/arch → release asset name
│   ├── cx-mcp-guard.sh          # version/capability decision for `cx mcp bridge`
│   ├── cx-path-probe.sh         # first writable on-PATH directory
│   ├── cx-min-version           # minimum cx version (numeric floor)
│   └── install-hooks.sh         # writes ~/.cursor/hooks.json with absolute paths
├── skills/
│   ├── cx-cli-setup/            # guided cx install + authentication (router + references/)
│   ├── cx-devassist-asca/       # on-demand SAST (ASCA) scan + remediation for source files
│   └── cx-devassist-sca/        # on-demand SCA (OSS) scan + remediation for dependency manifests
└── examples/
    └── cursor-mcp-bridge.json   # manual MCP config example
```

> Tests live at the **repo root** (`tests/`), outside the shipped plugin, so they aren't distributed.

### On-demand scanning (skills)

Beyond the automatic hook gates, two skills scan on request and remediate via the Checkmarx MCP —
invoked with `/cx-devassist-asca` / `/cx-devassist-sca` in chat, or autonomously by the agent:

| Ask | Skill | Engine |
|---|---|---|
| "scan this file" / "check app.py" (source code) | `cx-devassist-asca` | SAST (ASCA) → `mcp__Checkmarx__codeRemediation` |
| "scan my dependencies" / "check package.json" (manifest/lockfile) | `cx-devassist-sca` | SCA / OSS → `mcp__Checkmarx__packageRemediation` |

A bare "scan this file" routes by the target: source code → ASCA; a dependency manifest/lockfile → SCA.
`cx-cli-setup` (`/cx-cli-setup`) guides installing, upgrading, and authenticating the `cx` CLI itself.

### Admin onboarding pre-fill (optional)

An administrator can pre-seed the Checkmarx One **URL** and **tenant** for browser (OAuth) sign-in by
editing `config/cx-onboarding.properties`. When set (and valid), the values are embedded straight into
the gate's `cx auth login` recovery command. Edit the file in your **forked / internal marketplace
copy** (the reviewed, versioned artifact) — not in an end-user's live install, which is overwritten on
plugin update. Values are strictly validated (https-only host for the URL; a shell-inert charset for
the tenant); an invalid value is ignored and the developer is asked as usual. There is deliberately no
out-of-tree (`~/.checkmarx` / env) override.

---

## Prerequisites

The plugin installs the `cx` CLI for you, but it **cannot install its own host prerequisites** —
provide these first, or the gate can't run:

| Requirement | Windows | macOS | Linux |
|---|---|---|---|
| **POSIX shell** (`sh`, runs the hook) | **Git for Windows** — required; without it the hook can't launch | built-in | built-in |
| **Python 3** (gate logic) | install from python.org (**not** the Microsoft Store stub) | `xcode-select --install` or `brew install python3` | `apt`/`dnf`/`apk install python3` |
| **`curl` or `wget`** (bootstrap download) | bundled with Git for Windows | built-in `curl` | usually present; minimal images may need it |

Then the **`cx` CLI** itself, which the bundled **`cx-bootstrap.sh`** script installs (with download
checksum verification), puts on PATH, and (separately) authenticates (API key or OAuth). The minimum
version is a numeric floor in `scripts/cx-min-version`; the real capability decision is a runtime
probe (the `cx mcp bridge` and `cx hooks cursor-*` subcommands must all respond to `--help`).

---

## Installation

**Local plugin install** (recommended):

```text
~/.cursor/plugins/local/cx-devassist-cursor/
├── .cursor-plugin/plugin.json   ← required for Cursor to load the plugin
├── hooks/hooks.json             ← Cursor hook wiring (relative ./hooks/ paths)
├── mcp.json                     ← Checkmarx MCP
└── ...
```

Copy or symlink this plugin folder there, then run the install script (below) and
**Developer: Reload Window**.

**User-level hooks** (recommended for visibility + belt-and-suspenders):

```bash
bash plugins/cx-devassist-cursor/scripts/install-hooks.sh
# or from the local plugin copy:
CX_PLUGIN_ROOT=~/.cursor/plugins/local/cx-devassist-cursor bash scripts/install-hooks.sh
```

This writes `~/.cursor/hooks.json` (visible in Settings → Hooks) with absolute paths to this plugin.
Plugin-level hooks may still run without this file, but they often do not appear in the Hooks
settings UI without it.

On first use the gate will detect that `cx` is missing and name the exact bootstrap command to run
(`bash scripts/cx-bootstrap.sh install`), then walk you through authenticating it.

Optional: `export CX_ASSISTANT=cursor` (this is already the default for this plugin) so logs land in
`~/.checkmarx/agent-logs/cursor/`.

---

## Configuration

All optional — sensible defaults apply.

| Variable | Purpose |
|---|---|
| `CX_BINARY` | Absolute path to `cx` when it isn't on `PATH` (validated: must be a real, recent, capable, authenticated cx). |
| `CX_LOG_DIR` | Override the log directory (default `~/.checkmarx/agent-logs/cursor/`). |
| `CX_LOG_DISABLE=1` | Turn structured logging off entirely. |
| `CX_ASSISTANT` | Label the assistant in logs (default `cursor`). |
| `CX_REQUIRE_CHECKSUM=1` | Make `cx-bootstrap.sh` refuse to install an asset it can't checksum-verify. |

---

## Privacy & logging

The gate writes one redacted JSONL record per decision to
`~/.checkmarx/agent-logs/cursor/cx-devassist.jsonl` — both the stage-1 readiness gate's own allow/deny
(`gate_decision`) and the stage-2 native scanner's allow/deny (`scan_decision`), so a tool call blocked
because of an actual finding is recorded, not just a blocked-because-cx-isn't-ready decision. Logging
uses a **redaction allowlist**: each event declares the exact keys it may write and a type coercer per
key. Anything else — source code, secrets, tokens, prompts, free-form strings — is dropped before it
can reach disk; `scan_decision` in particular never carries the finding/reason text, only the outcome.
Every record's `ts` is a UTC ISO-8601 timestamp (e.g. `2026-07-09T14:23:01Z`). The MCP bridge sends
your credential only in the `Authorization` header, never to chat or logs. Logging never raises into
the gate, and `CX_LOG_DISABLE=1` turns it off.

---

## License

Apache 2.0 — see [LICENSE](../../LICENSE) at the repo root, which governs this plugin along with the
rest of [Checkmarx Agentic AI](../../README.md).
