# Codex CLI Plugin

Developer Assist for OpenAI's Codex CLI intercepts file writes (`apply_patch`) and Checkmarx MCP tool
calls performed by Codex, runs security scans on the targeted content, and returns findings directly to
the agent — enabling it to automatically remediate issues and retry the operation before the action is
allowed to proceed. Remediation occurs automatically upon risk detection, with no need for user action
to initiate it. The plugin is installed from a repo-scoped marketplace shipped in this repository. The
Checkmarx CLI is installed automatically as part of the process — the only requirement is
authenticating with Checkmarx One. Once in place, the plugin runs automatically on every file write and
Checkmarx MCP tool call Codex CLI performs. Shell commands are **not** gated — see
[Realtime Scanners](#realtime-scanners) below.

> **Status: depends on an unshipped `cx` CLI capability.** This plugin's native scanner calls
> `cx hooks codex-pre-tool-use` / `codex-pre-file-write` / `codex-stop` — subcommands that do not yet
> exist in any published `cx` (ast-cli) release. Until a capable build ships, the gate correctly
> **fails closed** (blocks every gated action) rather than running unscanned. See
> [External dependency](#external-dependency-cx-cli-capability) below.

Part of [Checkmarx Agentic AI](../../README.md). The Claude Code and GitHub Copilot CLI counterparts
live at [plugins/cx-devassist](../cx-devassist/README.md) and
[plugins/copilot-devassist](../copilot-devassist/README.md).

## Realtime Scanners

This plugin currently runs the following scanners:

- **ASCA** (source code) — on `apply_patch`, Codex's file-write/edit tool, for [scannable file
  types](#scannable-file-types)
- **Policy check** — on Checkmarx MCP tool calls (`mcp__Checkmarx__*`), before the call is allowed

Both run through the native `cx hooks codex-*` subcommands, gated by a readiness check that proves cx
is present, current, capable, and authenticated before any content is scanned. **Shell commands
(`Bash`) are not gated** — see [How it works](#how-it-works) below.

## Prerequisites

- Codex CLI is installed and available on your system.
- A Checkmarx One account with a Checkmarx One Assist license. Also, Dev Assist must be activated for
  your tenant account in the Checkmarx One UI under **Global Settings → Plugins**. This must be done
  by an account admin. Users will need to provide:
  - an API Key (see [Generating an API Key](#)), OR
  - login credentials (Base URL, Tenant name, Username and Password) for OAuth browser sign-in

The plugin is based on the Checkmarx CLI, which it installs automatically. However, it relies on
host-provided dependencies that must be installed beforehand:

| Requirement | Why it's needed | Windows | macOS | Linux |
|---|---|---|---|---|
| POSIX shell (`sh`) | Runs the hooks. On Windows this is Git Bash. | **Git for Windows — mandatory.** If missing, hooks cannot spawn at all and every action proceeds **UNSCANNED** with no warning (Codex CLI treats an un-spawnable hook as non-blocking). Codex CLI's own shell tool also requires Git Bash on Windows. | Built in | Built in |
| Python 3 or above | Runs the readiness/gate logic. | Install from python.org — **not** the Microsoft Store stub. | `xcode-select --install` or `brew install python3` | `apt` / `dnf` / `apk install python3` |
| `curl` or `wget` | Downloads the cx CLI during install/upgrade. | Bundled with Git for Windows | Built-in `curl` | Usually present; minimal images may need it |

Unlike the missing-shell case, a missing Python 3 **fails closed** — the gate blocks the action with
an install hint rather than letting it through unscanned.

### Connectivity Requirements

The following network connections must be available:

- **GitHub** — `https://github.com/Checkmarx/ast-cli` — needed specifically during download and
  version updates.
- **Checkmarx tenant URL** — required for authentication, scanning, remediation, etc. (Checkmarx One
  Server Base URLs.)
- **Identity/sign-in host (IdP/auth URL)** — for sign-in, when using OAuth (Checkmarx One
  Authentication URLs.)

If your environment requires an HTTP proxy for outbound network access, configure it using the
`http_proxy` or `CX_HTTP_PROXY` environment variable.

## Installation and Setup

This repo ships a repo-scoped marketplace at
[`.agents/plugins/marketplace.json`](../../.agents/plugins/marketplace.json) that points a
`cx-devassist` plugin entry at `./plugins/codex-devassist` — the same plugin name used by the Claude
Code and Copilot CLI marketplaces, so all three surfaces refer to "cx-devassist" consistently even
though each has its own packaged folder.

1. Clone this repository (or your internal fork) somewhere durable.

2. From your CLI terminal, add the marketplace:

   ```bash
   codex plugin marketplace add "/path/to/cx-agentic-ai"
   ```

   This registers it as `cx-devassist-marketplace` (the `name` declared in
   [`.agents/plugins/marketplace.json`](../../.agents/plugins/marketplace.json)). Confirm with:

   ```bash
   codex plugin marketplace list
   ```

3. Install the plugin from that marketplace:

   ```bash
   codex plugin add cx-devassist@cx-devassist-marketplace
   ```

   Confirm it installed with `codex plugin list --marketplace cx-devassist-marketplace`.

4. Restart the Codex CLI session so it re-reads `config.toml` and loads the plugin's hooks and
   skills. Trust the hooks when prompted — plugin-bundled hooks are non-managed and Codex skips them
   until reviewed.

5. During this process, the plugin verifies that the minimum required version of the Checkmarx CLI is
   installed. If it isn't already installed, it installs automatically (with download checksum
   verification).

6. You will be prompted to authenticate with Checkmarx. The prompt asks you to choose an
   authentication method — **API Key** or **Browser sign-in (OAuth)**. If this doesn't run
   automatically, trigger it yourself with `$cx-cli-setup`.

   - For **API Key** (recommended), enter a Checkmarx One API Key. To generate one, see [Creating an
     API Key for Checkmarx One Integrations](#).
   - For **OAuth**, you will be redirected to browser-based login. You will need to specify your
     Checkmarx One base URL, tenant name, username and password. If an admin has configured
     `config/cx-onboarding.properties` for your deployment, you won't be required to enter the base
     URL and tenant name — see [Admin onboarding pre-fill](#admin-onboarding-pre-fill-optional).

7. If the MCP server wasn't auto-registered, register it manually — see
   [Registering the MCP server](#registering-the-mcp-server-manual) below.

8. Confirm the setup is complete by checking `/mcp` in the agent — you should see `Checkmarx` listed
   as connected.

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
   `plugins/codex-devassist` directory (that variable is only meaningful when a plugin loader sets
   it — a hand-copied hooks.json needs the literal path).
4. Register the MCP server — see below.

On first use the gate will detect that `cx` is missing and walk you through installing and
authenticating it via the **`cx-cli-setup`** skill (`$cx-cli-setup`).

### Registering the MCP server (manual)

Add, verbatim, to `~/.codex/config.toml` or `<repo>/.codex/config.toml`:

```toml
[mcp_servers.Checkmarx]
command = "sh"
args = ["<absolute-path-to-plugin>/hooks/cx_run.sh", "mcp", "bridge"]
```

Use the **resolved absolute path** to your `plugins/codex-devassist` directory, not `${PLUGIN_ROOT}` —
that variable is only meaningful at hook-invocation time, not inside a user-edited config file.
Restart the Codex CLI session afterward so it re-reads `config.toml` and spawns the server.

## Optional Configuration

You can optionally customize the plugin functionality by adjusting these variables. If not
configured, sensible defaults are applied.

| Variable | Purpose |
|---|---|
| `CX_BINARY` | Absolute path to `cx` when it is not available on `PATH`. The specified file must be a valid, recent, capable, and authenticated `cx` executable. |
| `CX_GATE_ALL_FILES=1` | Gate every file write, not just [types the Checkmarx engines can scan](#scannable-file-types) — restores pre-scoping behavior. |
| `CX_LOG_DIR` | Overrides the log directory. Default: `~/.checkmarx/agent-logs/codex/`. |
| `CX_ALLOW_UNLICENSED=1` | Allow writes to proceed (with a logged warning) when cx is authenticated but has no AI-scanning license, instead of denying — accepts that those writes are unscanned. |
| `CX_LOG_DISABLE=1` | Disables structured logging entirely. |
| `CX_ASSISTANT` | Specifies the assistant label used in logs. Default: `codex`. |
| `CX_REQUIRE_CHECKSUM=1` | Make `cx-bootstrap.sh` refuse to install an asset it can't checksum-verify. |
| `CX_ALLOW_UNSCANNED=1` | Enables an audited emergency bypass that runs the action without scanning and records the action in the audit log. |

## Triggering Scans

Checkmarx Realtime scanners run automatically on every `apply_patch` call and Checkmarx MCP tool call
Codex CLI performs (shell commands are not gated — see [How it works](#how-it-works)). In addition, you
can manually run the scanners by asking Codex to scan a file or check your dependencies. When you ask
to scan a source code file, the ASCA scanner runs. When you ask to scan a manifest file, the
OSS-Realtime scanner runs.

You can run the ASCA and OSS scanners explicitly by calling the dedicated skills `$cx-devassist-asca`
and `$cx-devassist-sca` respectively (Codex CLI invokes skills with a **`$name`** prefix, not a
`/slash-command` or `namespace:skill-name`).

**Skill discovery caveat:** Codex CLI's confirmed skill-discovery paths are `.agents/skills` (repo,
user, and admin scope) — not a plugin-relative `skills/` folder the way Claude Code and Copilot CLI
auto-discover skills. This plugin ships `skills/` for packaging/versioning, but you must symlink or
copy its contents into `.agents/skills` for Codex to find them — see [Installation and
Setup](#installation-and-setup).

## How it works

Every gated tool call runs a **two-stage PreToolUse chain**:

1. **The gate** — `sh cx_check.sh --codex` → `cx_check.py` — proves the scanner is trustworthy before
   anything is scanned: cx is **present → recent enough → capable → authenticated**. If any step
   can't be proven, it **denies** and stage 2 never runs.
2. **The scanner** — a native `cx hooks codex-*` subcommand that performs the actual analysis and
   decides whether to allow or block the action.

`hooks/hooks.json` wires the following:

| Tool event | Gate | Native scanner | What it checks |
|---|---|---|---|
| `apply_patch` — scannable file | `cx_check` | `cx hooks codex-pre-file-write` | Static analysis (ASCA / SAST) of the proposed file content |
| `apply_patch` — any other file type | — | — | Nothing: no engine can scan it, so the write proceeds (see [Scannable file types](#scannable-file-types)) |
| `Bash` | — | — | **Not gated.** One non-blocking observer runs (`cx_record_login.sh`) — see below |
| MCP calls (`mcp__Checkmarx__*`) | `cx_check` | `cx hooks codex-pre-tool-use` | Policy check before the MCP call is allowed |
| Session stop | — | `cx hooks codex-stop` | Session-end hook |

### Scannable file types

The gate blocks a file write only when one of the three engines can analyse that file. The list is
[`config/cx-scannable-files`](config/cx-scannable-files):

| Engine | Files |
|---|---|
| **ASCA** (SAST) | `.java` `.js` `.jsx` `.ts` `.tsx` `.mjs` `.cjs` `.cs` `.go` `.py` `.pyw` |
| **KICS** (IaC) | `.tf` `.yaml` `.yml` `.json` `.proto` `.dockerfile` `.auto.tfvars` `.terraform.tfvars`, and `Dockerfile` |
| **SCA** (manifests) | `.csproj` `.sbt`; `pom.xml` `package.json` `bower.json` `yarn.lock` `Directory.Packages.props` `packages.config` `go.mod` `build.gradle` `build.gradle.kts` `libs.versions.toml` `setup.cfg` `setup.py` `pyproject.toml`; and `*.txt` starting `requirement`/`packages`/`constraint` |

Everything else (`.md`, `.txt`, `.html`, `.css`, `.sql`, …) is not gated, because no engine would scan
it. Restore the previous behavior (gate every `apply_patch` regardless of file type) with
`CX_GATE_ALL_FILES=1`.

### Remembered login environments (automatic)

`cx auth login` normally requires the developer to supply a Checkmarx One URL and tenant on every
fresh OAuth sign-in. The `Bash` matcher carries one non-blocking observer hook —
[`hooks/cx_record_login.sh`](hooks/cx_record_login.sh) — which records the URL/tenant pair from an
agent-issued `cx auth login` so a later logged-out session can offer it back instead of re-asking from
scratch. Stored in `cx_login_history.json` in the gate's private `0700` state dir (honours
`CX_LOG_DIR`). OAuth only — an API-key setup carries no URL/tenant to record.

### External dependency: cx CLI capability

Unlike the readiness checks (present/recent/authenticated), the native scan step requires the
external `cx` CLI to expose `cx hooks codex-pre-tool-use`, `cx hooks codex-pre-file-write`, and
`cx hooks codex-stop` subcommands. These are **not part of this repository** — they ship in the `cx`
(ast-cli) binary, maintained centrally by Checkmarx. Until a build with these subcommands is
published, the gate will correctly **block every gated action** rather than scan with a build that
can't. This is expected fail-closed behavior, not a bug in this plugin.

### Admin onboarding pre-fill (optional)

An administrator can pre-seed the Checkmarx One **URL** and **tenant** for browser (OAuth) sign-in by
editing `config/cx-onboarding.properties`. When set (and valid), the values are embedded straight into
the gate's `cx auth login` recovery command and the `cx-cli-setup` skill skips the URL/tenant
question. Edit the file in your **forked / internal copy** (the reviewed, versioned artifact) — not in
an end-user's live install, which is overwritten on update.

## Uninstall

**If installed via the local marketplace:**

```bash
codex plugin remove cx-devassist@cx-devassist-marketplace
```

This removes the plugin from local config and cache but leaves the marketplace registered (so it can
be reinstalled later). To also unregister the marketplace itself:

```bash
codex plugin marketplace remove cx-devassist-marketplace
```

**If installed manually** (see [Manual installation](#manual-installation-fallback)):

1. Remove the `[mcp_servers.Checkmarx]` block from `config.toml`.
2. Remove or restore the entries you added to `~/.codex/hooks.json` / `<repo>/.codex/hooks.json`.
3. Remove the copied/symlinked skills from `.agents/skills` (or `~/.agents/skills`).
4. Restart the Codex CLI session so it re-reads `config.toml` / `hooks.json`.

Either way, removing the plugin does **not** remove the `cx` CLI binary or its credentials/logs. To
remove those as well:

```bash
rm -rf ~/.checkmarx        # Unix / macOS / WSL
rmdir %LOCALAPPDATA%\Checkmarx  # Windows PowerShell
```

## Upgrade

**If installed via the local marketplace:** there is no single "update the plugin" command — refresh
the marketplace snapshot, then reinstall the plugin from it:

```bash
codex plugin marketplace upgrade cx-devassist-marketplace
codex plugin add cx-devassist@cx-devassist-marketplace
```

**If installed manually:** pull the latest changes in your cloned repo, then re-copy/symlink the
updated `skills/` contents into `.agents/skills` and re-copy `hooks/hooks.json` (re-substituting
`${PLUGIN_ROOT}` with the absolute path).

Either way, restart the Codex CLI session afterward so it re-reads `config.toml` / `hooks.json`.

The `cx` CLI itself updates independently. Run `$cx-cli-setup` if prompted, or manually upgrade via
`sh scripts/cx-bootstrap.sh upgrade` from within the plugin directory.

## Troubleshooting

| # | Error | Likely cause | Fix |
|---|---|---|---|
| 1 | Message says cx CLI is not installed or cannot be found. | cx is missing, or the plugin cannot resolve its path. | Run `$cx-cli-setup`. If `cx version` still shows "command not found" (exit code 127) right after, that is expected — do not re-run the installer. Proceed to use the plugin and see if the error persists. |
| 2 | Message says cx is older than the required version. | The installed cx is older than the minimum supported version for this plugin. | Run `$cx-cli-setup` — it detects the outdated build and upgrades automatically. Then restart the Codex CLI session so the remediation MCP picks up the new binary. |
| 3 | Message says required scanner commands are missing (`incapable`). | The installed cx build has the right version number but is missing the agent-security subcommands. Re-running setup re-downloads the same build. | This is a **terminal** state until a capability-complete `cx` build is published — see [External dependency](#external-dependency-cx-cli-capability). If you have access to an internal capable build, set `CX_BINARY` to its absolute path. Otherwise contact Checkmarx support. |
| 4 | Signed in but the very next action is immediately blocked. | Token propagation delay — the credential was just written but validation is still returning invalid. | Wait ~30–60s and retry the SAME action. Do NOT sign in again — each sign-in cancels the previous token and restarts the wait, creating a loop. |
| 5 | Message says authentication to Checkmarx One failed. | Credential is missing, expired, or the tenant is unreachable. | Check the error text: `invalid`/`unauthorized`/`401` = credential — re-authenticate via `$cx-cli-setup`. `no such host`/`connection refused`/`timeout` = network — check firewall, proxy, and tenant URL. |
| 6 | The Checkmarx MCP is not connected. | Remediation service started before cx was authenticated, or cannot reach the tenant URL. | Confirm cx sign-in is valid (`cx auth validate`), then restart the Codex CLI session so it re-spawns the MCP bridge. |
| 7 | First file scan is slow or times out. | Scanner engine cold start — the first scan takes longer; subsequent scans are warm. | Retry the write. If it fails consistently, check tenant connectivity and proxy settings. |
| 8 | `cx` install fails — download error. | No route to GitHub, or proxy not applied to the install. | Set the proxy with `export CX_HTTP_PROXY=<proxy-url>` (or `cx configure set --prop-name http_proxy`), then re-run `$cx-cli-setup`. GitHub must be reachable for install; only the tenant URL is needed at runtime. |
| 9 | Every action is blocked with "Python 3 not found". | No usable Python 3. On Windows, may be the Microsoft Store stub. | Install a real Python 3. Windows: python.org (not the Store stub). macOS: `xcode-select --install` or `brew install python3`. Linux: `apt`/`dnf`/`apk install python3`. |
| 10 | On Windows, actions are running without any security check. | Git for Windows is not installed. The hook cannot start, and Codex CLI treats an un-spawnable hook as non-blocking — actions proceed unscanned with no warning. | Install Git for Windows. Verify by confirming Codex CLI's own shell tool works. The plugin isn't effective until this is in place. |
| 11 | Block message mentions an invalid `CX_BINARY` path. | The path is relative, does not exist, or is not executable. | Set `CX_BINARY` to a valid absolute path, or unset it to let the plugin resolve cx automatically. |
| 12 | `cx version` works in the terminal but actions are still blocked. | The gate resolves `cx` by absolute path (`CX_BINARY` → canonical store → PATH) in its own process — "version works when I type it" doesn't by itself prove the gate is satisfied. | Read the deny message — the reason is almost always authentication, version, or capability. Do not move binaries or edit PATH. |
| 13 | Blocked after credentials expire. | API keys expire after 30–365 days (tenant policy). OAuth tokens can also expire. | Run `cx auth logout` to clear the expired credential, then re-authenticate via `$cx-cli-setup`. No reinstall needed. |
| 14 | Actions blocked with a "pass-through" / "scanner_passthrough" message after browser sign-in. | The scanner requires an API key credential, not a browser OAuth token — `cx hooks codex-*` authenticates only by extracting a Checkmarx API key. | Switch to an API key. Generate one in Checkmarx One under **Settings → Identity and Access Management → API Keys**, then run `$cx-cli-setup` to set it. |
| 15 | Install stops with a checksum mismatch error. | The downloaded `cx` binary is corrupted or tampered with. | Always fatal — cannot be overridden. Re-run `$cx-cli-setup` to try again. If the mismatch repeats, contact Checkmarx support. |
| 16 | Remediation returns "unauthorized" right after re-signing in. | Re-signing in rotates the token; the remediation service may briefly hold the old credential. | This self-heals — the service re-reads the credential on its next call. Wait a moment and retry. No re-registration needed. |
| 17 | The security gate itself won't run (Git-Bash missing on Windows). | The gate launches via `sh`, which on Windows only resolves through Git for Windows. | Install Git for Windows. Verify by confirming Codex CLI's own shell tool works — the plugin isn't effective until this is in place. |

## Privacy & Logging

The gate writes one redacted JSONL record per decision to
`~/.checkmarx/agent-logs/codex/cx-devassist.jsonl` — both the stage-1 readiness gate's own allow/deny
(`gate_decision`) and the stage-2 native scanner's allow/deny (`scan_decision`), so a tool call
blocked because of an actual finding is recorded, not just a blocked-because-cx-isn't-ready decision.
Logging uses a **redaction allowlist**: each event declares the exact keys it may write and a type
coercer per key. Anything else — source code, secrets, tokens, prompts, free-form strings — is
dropped before it can reach disk; `scan_decision` in particular never carries the finding/reason text,
only the outcome. The MCP bridge sends your credential only in the `Authorization` header, never to
chat or logs. Logging never raises into the gate, and `CX_LOG_DISABLE=1` turns it off.

## Plugin structure

```
plugins/codex-devassist/
├── .codex-plugin/
│   └── plugin.json              # plugin manifest (name/version/hooks/skills/mcpServers pointers)
├── .mcp.json                    # best-effort MCP declaration (forward-compat)
├── README.md
├── config/
│   ├── cx-onboarding.properties # OPTIONAL admin pre-fill of Checkmarx One URL + tenant (onboarding)
│   └── cx-scannable-files       # the file types the gate blocks on — mirrors ASCA/KICS/SCA filters
├── hooks/
│   ├── hooks.json               # Codex CLI PreToolUse / Stop wiring
│   ├── cx_check.sh              # POSIX launcher — resolves Git Bash + Python 3, then runs the gate
│   ├── cx_check.py              # the fail-closed gate (present → recent → capable → authenticated)
│   ├── _cx_bootstrap_match.sh   # shared bootstrap-command matcher for the shell stages
│   ├── cx_record_login.sh       # non-blocking observer: remembers OAuth URL + tenant
│   ├── cx_run.sh                # resolves cx by absolute path; runs the native scanner + MCP bridge
│   └── cx_log.py                # structured, redacted JSONL logging
├── scripts/
│   ├── cx-bootstrap.sh          # download + checksum-verify + install the cx CLI (self-install)
│   ├── cx-asset-resolver.sh     # OS/arch → release asset name
│   ├── cx-mcp-guard.sh          # shared version/capability decision for `cx mcp bridge`
│   ├── cx-path-probe.sh         # first writable on-PATH directory
│   └── cx-min-version           # minimum cx version (numeric floor)
└── skills/
    ├── cx-cli-setup/            # guided cx install + authentication (router + references/)
    ├── cx-devassist-asca/       # on-demand SAST (ASCA) scan + remediation for source files
    └── cx-devassist-sca/        # on-demand SCA (OSS) scan + remediation for dependency manifests
```

> Tests live at the **repo root** (`tests/`), outside the shipped plugin, so they aren't distributed.

## License

Apache 2.0 — see [LICENSE](../../LICENSE) at the repo root, which governs this plugin along with the
rest of [Checkmarx Agentic AI](../../README.md).
