# codex-devassist

A **fail-closed security gate** for **OpenAI's Codex CLI**, backed by
[Checkmarx CxOne](https://checkmarx.com/).

Before Codex runs a shell command, applies a patch, or calls an MCP tool, the plugin asks the
Checkmarx `cx` CLI to scan the proposed action. If a real vulnerability or policy violation is
found — **or if the scanner can't be trusted to run** — the action is **blocked**, not silently
allowed. Found issues are remediated interactively through the bundled Checkmarx MCP server.

Part of [Checkmarx Agentic AI](../../README.md). The Claude Code and GitHub Copilot CLI
counterparts live at [plugins/cx-devassist](../cx-devassist/README.md) and
[plugins/copilot-devassist](../copilot-devassist/README.md) — all three plugins share the same
gate design and `cx` CLI, but are packaged and wired independently.

> **Status: depends on an unshipped `cx` CLI capability.** This plugin's native scanner calls
> `cx hooks codex-pre-tool-use` / `codex-pre-file-write` / `codex-stop` — subcommands that do not
> yet exist in any published `cx` (ast-cli) release. Until a capable build ships, the gate
> correctly **fails closed** (blocks every gated action) rather than running unscanned. See
> [External dependency](#external-dependency-cx-cli-capability) below.

---

## How it works

Codex CLI's `PreToolUse` hook contract is confirmed structurally identical to Claude Code's
(nested `hookSpecificOutput.permissionDecision` JSON, or exit code 2, for a deny) — so this
plugin reuses the same two-stage design as `cx-devassist`, adapted only for Codex's tool names.

Every gated tool call runs a **two-stage PreToolUse chain**:

1. **The gate** — `sh cx_check.sh --codex` → `cx_check.py` — proves the scanner is trustworthy
   before anything is scanned: cx is **present → recent enough → capable → authenticated**. If
   any step can't be proven, it **denies (exit 2)** and stage 2 never runs.
2. **The scanner** — a native `cx hooks codex-*` subcommand that performs the actual analysis and
   decides whether to allow or block the action.

`hooks/hooks.json` wires the following:

| Tool event | Gate | Native scanner | What it checks |
|---|---|---|---|
| `apply_patch` (Codex's single file-write/edit tool) | `cx_check` | `cx hooks codex-pre-file-write` | Static analysis (ASCA / SAST) of the proposed file content |
| `Bash` | `cx_check` | `cx hooks codex-pre-tool-use` | Command & dependency policy — open-source / SCA checks on installs and manifest edits |
| MCP calls (`mcp__Checkmarx__*`) | `cx_check` | `cx hooks codex-pre-tool-use` | Policy check before the MCP call is allowed |
| Session stop | — | `cx hooks codex-stop` | Session-end hook |

Codex has one unified file-mutation tool (`apply_patch`), unlike Claude Code's separate
Write/Edit/MultiEdit/NotebookEdit tools — so this plugin gates a single matcher instead of four.

The scanning logic itself lives in the `cx` CLI (maintained centrally by Checkmarx); this plugin
is a thin, hardened wrapper that **guarantees cx is ready, installs it when missing, and wires
the remediation MCP** — nothing more.

### Remediation (MCP)

When a finding needs fixing, remediation runs through the **Checkmarx MCP server**
(`cx mcp bridge`). Codex CLI registers MCP servers via `[mcp_servers.<name>]` TOML in
`~/.codex/config.toml` (or `<repo>/.codex/config.toml`) — **not** a `.mcp.json` file. This plugin
ships a best-effort `.mcp.json` as a forward-compatibility bet in case a future Codex plugin
loader auto-discovers it, but the **documented, supported** registration path today is manual:
see [Configuration → Registering the MCP server](#registering-the-mcp-server-manual) below and
[`skills/codex-cli-setup/references/mcp.md`](skills/codex-cli-setup/references/mcp.md). A single
`cx` sign-in covers both the CLI and the MCP.

---

## Fail-closed by design

The gate is engineered so that **uncertainty blocks.** Only the hook's `exit 2` (or
`permissionDecision: deny`) blocks a tool call; *anything else is treated by Codex CLI as
non-blocking*. So every "can't evaluate" path is deliberately routed to `exit 2`, and the gate is
hardened against the cross-OS holes that would otherwise **fail open** (let an unscanned action
through):

- **Windows** — hooks invoke `sh` (which only ever resolves to Git Bash), never bare `bash`
  (which Windows resolves to the System32 WSL stub → exit 127 → unscanned).
- **Linux / macOS** — the launcher requires Python 3, and all shipped scripts are pinned to LF
  line endings, so a stray Python 2 or a `\r` can't slip an action past the scan.
- **Any OS** — an unexpected error inside the gate denies fail-closed instead of crashing through.

If cx is missing, below the minimum version, missing the required subcommands (`incapable`), or
unauthenticated, the gate denies with a clear, actionable message pointing at
`$codex-cli-setup`.

---

## External dependency: cx CLI capability

Unlike the readiness checks (present/recent/authenticated), the native scan step requires the
external `cx` CLI to expose `cx hooks codex-pre-tool-use`, `cx hooks codex-pre-file-write`, and
`cx hooks codex-stop` subcommands. These are **not part of this repository** — they ship in the
`cx` (ast-cli) binary, maintained centrally by Checkmarx. Until a build with these subcommands is
published, `_CAPABILITY_PROBES` in `hooks/cx_check.py` will always report `incapable`, and the
gate will correctly **block every gated action** rather than scan with a build that can't. This
is expected fail-closed behavior, not a bug in this plugin.

---

## Plugin structure

```
plugins/codex-devassist/
├── .codex-plugin/
│   └── plugin.json              # plugin manifest (name/version/hooks/skills/mcpServers pointers)
├── .mcp.json                    # best-effort MCP declaration (forward-compat; see caveat above)
├── README.md
├── config/
│   └── cx-onboarding.properties # OPTIONAL admin pre-fill of Checkmarx One URL + tenant (onboarding)
├── hooks/
│   ├── hooks.json               # Codex CLI PreToolUse / Stop wiring
│   ├── cx_check.sh              # POSIX launcher — resolves Git Bash + Python 3, then runs the gate
│   ├── cx_check.py              # the fail-closed gate (present → recent → capable → authenticated)
│   ├── _cx_bootstrap_match.sh   # shared bootstrap-command matcher for the shell stages
│   ├── cx_run.sh                # resolves cx by absolute path; runs the native scanner + MCP bridge
│   └── cx_log.py                # structured, redacted JSONL logging
├── scripts/
│   ├── cx-bootstrap.sh          # download + checksum-verify + install the cx CLI (self-install)
│   ├── cx-asset-resolver.sh     # OS/arch → release asset name
│   ├── cx-mcp-guard.sh          # shared version/capability decision for `cx mcp bridge`
│   ├── cx-path-probe.sh         # first writable on-PATH directory
│   └── cx-min-version           # minimum cx version (numeric floor)
└── skills/
    ├── codex-cli-setup/            # guided cx install + authentication (router + references/)
    ├── codex-devassist-asca/       # on-demand SAST (ASCA) scan + remediation for source files
    └── codex-devassist-sca/        # on-demand SCA (OSS) scan + remediation for dependency manifests
```

> Tests live at the **repo root** (`tests/`), outside the shipped plugin, so they aren't
> distributed.

### On-demand scanning (skills)

Beyond the automatic PreToolUse gate, two skills scan on request and remediate via the Checkmarx
MCP. Codex CLI invokes skills with a **`$name`** prefix (not a `/slash-command` or
`namespace:skill-name`):

| Ask | Skill | Engine |
|---|---|---|
| "scan this file" / "check app.py" (source code) | `$codex-devassist-asca` | SAST (ASCA) → `mcp__Checkmarx__codeRemediation` |
| "scan my dependencies" / "check package.json" (manifest/lockfile) | `$codex-devassist-sca` | SCA / OSS → `mcp__Checkmarx__packageRemediation` |
| whole project / cloud-scale scan | Checkmarx MCP (Cx1 cloud) tools | — |

A bare "scan this file" routes by the target: source code → ASCA; a dependency manifest/lockfile
→ SCA.

**Skill discovery caveat:** Codex CLI's confirmed skill-discovery paths are `.agents/skills`
(repo, user, and admin scope) — not a plugin-relative `skills/` folder the way Claude Code and
Copilot CLI auto-discover skills. This plugin ships `skills/` for packaging/versioning, but you
must symlink or copy its contents into `.agents/skills` for Codex to find them — see
[Installation](#installation).

### Admin onboarding pre-fill (optional)

An administrator can pre-seed the Checkmarx One **URL** and **tenant** for browser (OAuth)
sign-in by editing `config/cx-onboarding.properties`. When set (and valid), the values are
embedded straight into the gate's `cx auth login` recovery command and the `codex-cli-setup`
skill skips the URL/tenant question. Edit the file in your **forked / internal copy** (the
reviewed, versioned artifact) — not in an end-user's live install, which is overwritten on
update. Values are strictly validated (https-only host for the URL; a shell-inert charset for
the tenant); an invalid value is ignored and the developer is asked as usual. There is
deliberately no out-of-tree (`~/.checkmarx` / env) override.

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
(safe). But if the **POSIX shell** (`sh`) is missing — the default on Windows without Git for
Windows — the hook cannot spawn at all, which Codex CLI is expected to treat as a non-blocking
hook error (same failure mode documented for Claude Code), so the action would proceed
**UNSCANNED**. Without Git for Windows, Codex CLI's own Bash tool does not work either, so
**Git for Windows is a hard prerequisite** — install and verify it *before* relying on the gate.

Then the **`cx` CLI** itself, which the bundled **`codex-cli-setup`** skill installs (with
download checksum verification), puts on PATH, and authenticates (API key or OAuth). The minimum
version is a numeric floor in `scripts/cx-min-version`; the real capability decision is a runtime
probe (the `cx mcp bridge` and `cx hooks codex-*` subcommands must all respond to `--help`) — see
[External dependency](#external-dependency-cx-cli-capability).

---

## Installation

### Via the local marketplace (recommended)

This repo ships a repo-scoped marketplace at
[`.agents/plugins/marketplace.json`](../../.agents/plugins/marketplace.json) that points a
`cx-devassist` plugin entry at `./plugins/codex-devassist` — the same plugin name used by the
Claude Code and Copilot CLI marketplaces, so all three surfaces refer to "cx-devassist"
consistently even though each has its own packaged folder.

1. Clone this repository (or your internal fork) somewhere durable.
2. Point Codex at the marketplace:
   ```bash
   codex plugin marketplace add "/path/to/cx-agentic-ai"
   ```
3. Enable the plugin (`codex plugin marketplace list` to confirm the marketplace registered, then
   enable `cx-devassist` from the Codex plugin picker or `config.toml`).
4. Restart the Codex CLI session so it re-reads `config.toml` and loads the plugin's hooks and
   skills. Trust the hooks when prompted — plugin-bundled hooks are non-managed and Codex skips
   them until reviewed.

The MCP server may still need manual registration — see below.

### Manual installation (fallback)

If the marketplace mechanism isn't available in your Codex CLI build, wire the plugin by hand:

1. Clone this repository (or your internal fork) somewhere durable.
2. Symlink or copy the skills so Codex can discover them:
   ```bash
   mkdir -p .agents/skills
   cp -r /path/to/cx-agentic-ai/plugins/codex-devassist/skills/* .agents/skills/
   ```
   (repo-scoped `.agents/skills`, or `~/.agents/skills` for a user-wide install).
3. Register the hooks — copy or symlink `plugins/codex-devassist/hooks/hooks.json` to
   `~/.codex/hooks.json` (user-wide) or `<repo>/.codex/hooks.json` (project-scoped), replacing
   `${PLUGIN_ROOT}` in every `command` with the **absolute path** to your cloned
   `plugins/codex-devassist` directory (that variable is only meaningful when a plugin loader
   sets it — a hand-copied hooks.json needs the literal path).
4. Register the MCP server — see below.

On first use the gate will detect that `cx` is missing and walk you through installing and
authenticating it via the **`codex-cli-setup`** skill (`$codex-cli-setup`).

### Registering the MCP server (manual)

Add, verbatim, to `~/.codex/config.toml` or `<repo>/.codex/config.toml`:

```toml
[mcp_servers.Checkmarx]
command = "sh"
args = ["<absolute-path-to-plugin>/hooks/cx_run.sh", "mcp", "bridge"]
```

Use the **resolved absolute path** to your `plugins/codex-devassist` directory, not
`${PLUGIN_ROOT}` — that variable is only meaningful at hook-invocation time, not inside a
user-edited config file. Restart the Codex CLI session afterward so it re-reads `config.toml`
and spawns the server.

---

## Configuration

All optional — sensible defaults apply.

| Variable | Purpose |
|---|---|
| `CX_BINARY` | Absolute path to `cx` when it isn't on `PATH` (validated: must be a real, recent, capable, authenticated cx). |
| `CX_LOG_DIR` | Override the log directory (default `~/.checkmarx/agent-logs/codex/`). |
| `CX_LOG_DISABLE=1` | Turn structured logging off entirely. |
| `CX_ASSISTANT` | Label the assistant in logs (default `codex`). |
| `CX_REQUIRE_CHECKSUM=1` | Make `cx-bootstrap.sh` refuse to install an asset it can't checksum-verify. |
| `CX_ALLOW_UNSCANNED=1` | Audited emergency bypass — runs the action **unscanned** and records it to the audit log. |

---

## Privacy & logging

The gate writes one redacted JSONL record per decision to
`~/.checkmarx/agent-logs/codex/cx-devassist.jsonl` — both the stage-1 readiness gate's own
allow/deny (`gate_decision`) and the stage-2 native scanner's allow/deny (`scan_decision`), so a
tool call blocked because of an actual finding is recorded, not just a
blocked-because-cx-isn't-ready decision. Logging uses a **redaction allowlist**: each event
declares the exact keys it may write and a type coercer per key. Anything else — source code,
secrets, tokens, prompts, free-form strings — is dropped before it can reach disk;
`scan_decision` in particular never carries the finding/reason text, only the outcome. Every
record's `ts` is a UTC ISO-8601 timestamp (e.g. `2026-07-09T14:23:01Z`). The MCP bridge sends
your credential only in the `Authorization` header, never to chat or logs. Logging never raises
into the gate, and `CX_LOG_DISABLE=1` turns it off.

---

## Open unknowns

This plugin was built against OpenAI's published Codex CLI documentation without hands-on
end-to-end validation against a live Codex CLI session. The following are documented,
lowest-risk defaults rather than confirmed behavior:

1. **External `cx` CLI capability** — see [above](#external-dependency-cx-cli-capability).
2. **MCP auto-registration** — a plugin-bundled `.mcp.json` may or may not be auto-discovered by
   Codex; the manual `config.toml` step is the documented, supported path. `.mcp.json` now uses
   the `mcp_servers` (snake_case) wrapped-map shape documented by OpenAI's plugin docs (it
   previously used an unsupported `mcpServers` camelCase key, which matched neither of the two
   accepted formats and is the likely cause of the `Auth: Unsupported` / no-tools result seen in a
   live Codex session before this fix) — but whether Codex actually auto-loads a plugin's
   `.mcp.json` at all remains unconfirmed.
3. **Skills auto-discovery** — a plugin-relative `skills/` folder may or may not be
   auto-discovered; manual copy/symlink into `.agents/skills` is the documented, supported path.
4. **Plugin manifest / marketplace** — a `.codex-plugin/plugin.json` manifest is now shipped
   (name/version/description/`hooks`/`skills`/`mcpServers` pointers, per OpenAI's published plugin
   docs), but Codex's marketplace distribution mechanism was not fully confirmed at build time and
   no marketplace listing is published for this plugin — install from a cloned copy of this
   repository instead, using the manual steps above.

---

## License

Apache 2.0 — see [LICENSE](../../LICENSE) at the repo root, which governs this plugin along with
the rest of [Checkmarx Agentic AI](../../README.md).
