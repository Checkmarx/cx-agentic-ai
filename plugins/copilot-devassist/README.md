# Cx-Devassist For Copilot CLI

A **fail-closed security gate** for **GitHub Copilot CLI**, backed by
[Checkmarx CxOne](https://checkmarx.com/).

Before Copilot creates or edits a file the Checkmarx engines can scan — source code, IaC, or a
dependency manifest — the plugin asks the Checkmarx `cx` CLI to scan the proposed content. If a real
vulnerability or policy violation is found — **or if the scanner can't be trusted to run** — the
action is **blocked**, not silently allowed. Found issues are remediated interactively through the
bundled Checkmarx MCP server.

Shell commands and file types no engine can scan are **not** gated: nothing would have been scanned
there, so blocking them cost developers time without buying protection. See
[Scannable file types](#scannable-file-types).

---

## How it works

`hooks/hooks-copilot-cli.json` wires a **two-stage PreToolUse chain** on file writes:

1. **The gate** — `sh cx_check.sh --copilot-cli` → `cx_check.py` — proves the scanner is trustworthy
   before anything is scanned: cx is **present → recent enough → capable → authenticated**. If any step
   can't be proven, it denies and stage 2 never runs.
2. **The scanner** — a native `cx hooks copilot-cli-*` subcommand that performs the actual analysis and
   decides whether to allow or block the action.

| Tool event | Gate | Native scanner | What it checks |
|---|---|---|---|
| `create` / `edit` — **scannable file** | `cx_check` | `cx hooks copilot-cli-pre-file-write` | Static analysis of the proposed content: ASCA (SAST), KICS (IaC), SCA (manifests) |
| `create` / `edit` — any other file type | — | — | Nothing: no engine can scan it, so the write proceeds |
| `bash` / `powershell` / `shell` | — | — | **Not gated.** One non-blocking observer runs (`cx_record_login`) — see below |
| `Stop` (`agentStop`) — the agent finishes a turn | — | `cx hooks copilot-cli-stop` | Advisory, non-blocking lifecycle hook (e.g. session/usage bookkeeping); never blocks the agent |

**Shell commands are never blocked.** They previously ran the full readiness gate, which blocked
`git status`, `npm test`, `mvn verify` and the like whenever cx was missing or unauthenticated — while
protecting nothing: the native shell handler never inspects file content, so shell-written code
(`cat > app.py`) was already unscanned on a healthy cx. The shell matcher now carries a single observer,
[`hooks/cx_record_login.sh`](hooks/cx_record_login.sh), which notes the URL + tenant of a
`cx auth login` (see [Remembered login environments](#remembered-login-environments-automatic)) and
**exits 0 on every path**, so it cannot block. A pure-shell prefilter means an ordinary command spawns
nothing beyond `sh` itself.

The scanning logic itself lives in the `cx` CLI (maintained centrally by Checkmarx); this plugin is a
thin, hardened wrapper that **guarantees cx is ready, installs it when missing, and wires the
remediation MCP** — nothing more.

### Remediation (MCP)

When a finding needs fixing, remediation runs through the **Checkmarx MCP server** (`cx mcp bridge`),
declared in `.mcp.json` and started automatically by Copilot CLI — no manual registration step. It
exposes code- and package-remediation tools (`mcp__Checkmarx__codeRemediation`, …) that the agent calls
directly. A single `cx` sign-in covers both the CLI and the MCP. See
[`skills/checkmarx-cli-setup/references/mcp.md`](skills/checkmarx-cli-setup/references/mcp.md).

---

## Fail-closed by design

The gate is engineered so that **uncertainty blocks.** Copilot CLI's hook contract differs from other
clients: a `preToolUse` hook **denies via `exit 0` with `{"permissionDecision":"deny", ...}` on
stdout** — any *non-zero* exit is treated as a hook **error**, which Copilot CLI does **not** block on
(fail-open, unscanned). `cx_check.sh`/`cx_check.py` handle this explicitly via the `--copilot-cli` flag,
so every "can't evaluate" path is routed to the correct deny shape for this client, and the gate is
hardened against the cross-OS holes that would otherwise let an unscanned action through:

- **Windows** — hooks invoke `sh` (which only ever resolves to Git Bash), never bare `bash` (which
  Windows resolves to the System32 WSL stub → exit 127 → treated as a hook error → fail-open).
- **Linux / macOS** — the launcher requires Python 3, and all shipped scripts are pinned to LF line
  endings, so a stray Python 2 or a `\r` can't slip an action past the scan.
- **Any OS** — an unexpected error inside the gate still emits a deny (not a crash) so the action stays
  blocked.

If cx is missing, below the minimum version, missing the required subcommands (`incapable`), or
unauthenticated, the gate denies with a clear, actionable message pointing at `/checkmarx-cli-setup`.

**What that deny covers:** writes to [scannable files](#scannable-file-types). **What it does not:**
shell commands — ever. So a developer whose cx is broken can still run `git`, `npm`, `mvn`, `pytest`
and `docker`, and — crucially — install and authenticate cx to unblock themselves. Writes to other
file types also proceed, except when the gate cannot evaluate the file type at all (no Python 3),
which denies every write.

### Scannable file types

The gate blocks a file write only when one of the three engines can analyse that file. The list is
[`config/cx-scannable-files`](config/cx-scannable-files), and it mirrors the engines' own filters in
[`ast-cli`](https://github.com/Checkmarx/ast-cli):

| Engine | Files |
|---|---|
| **ASCA** (SAST) | `.java` `.js` `.jsx` `.ts` `.tsx` `.mjs` `.cjs` `.cs` `.go` `.py` `.pyw` |
| **KICS** (IaC) | `.tf` `.yaml` `.yml` `.json` `.proto` `.dockerfile` `.auto.tfvars` `.terraform.tfvars`, and `Dockerfile` |
| **SCA** (manifests) | `.csproj` `.sbt` `.podspec`; `pom.xml` `package.json` `bower.json` `yarn.lock` `Directory.Packages.props` `packages.config` `go.mod` `build.gradle` `build.gradle.kts` `libs.versions.toml` `setup.cfg` `setup.py` `pyproject.toml` `Podfile` `Cartfile` `Gemfile` `composer.json` `pubspec.yaml` `Package.swift`; and `*.txt` starting `requirement`/`packages`/`constraint` |

Everything else — `.md`, `.html`, `.css`, `.sql`, `.sh`, `.rb`, `.php`, `.c`, `.rs` — is not gated,
because no engine would scan it. Two consequences worth knowing:

- `.json` and `.yaml` **are** gated, because KICS scans them. A `tsconfig.json` write still runs the
  full readiness check even though it is not IaC.
- A plain `.tfvars` is **not** gated: KICS lists only the compound `.auto.tfvars` /
  `.terraform.tfvars` suffixes, so it would not be scanned either.

The file has exactly one reader — `cx_check.py`'s `_is_scannable_file`. If the config file is
unreadable or empty, every write is gated again: fail-closed, never fail-open. Editing it is how an
administrator adjusts coverage; distribute it in your forked/internal copy of the plugin, not in a
live install directory (same boundary as `config/cx-onboarding.properties`).

---

## Plugin structure

```
plugins/copilot-devassist/
├── plugin.json                  # GitHub Copilot CLI manifest (name, version, hooks, skills)
├── .mcp.json                    # declares the Checkmarx MCP server (cx mcp bridge); auto-discovered
├── README.md
├── config/
│   ├── cx-onboarding.properties # OPTIONAL admin pre-fill of Checkmarx One URL + tenant (onboarding)
│   └── cx-scannable-files       # the file types the gate blocks on — mirrors ASCA/KICS/SCA filters
├── hooks/
│   ├── hooks-copilot-cli.json   # GitHub Copilot CLI PreToolUse wiring
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
    ├── checkmarx-cli-setup/            # guided cx install + authentication (router + references/)
    ├── checkmarx-devassist-asca/       # on-demand SAST (ASCA) scan + remediation for source files
    └── checkmarx-devassist-sca/        # on-demand SCA (OSS) scan + remediation for dependency manifests
```

> Tests live at the **repo root** (`tests/`), outside the shipped plugin, so they aren't distributed.

### On-demand scanning (skills)

Beyond the automatic PreToolUse gate, two skills scan on request and remediate via the Checkmarx MCP:

| Ask | Skill | Engine |
|---|---|---|
| "scan this file" / "check app.py" (source code) | `checkmarx-devassist-asca` | SAST (ASCA) → `mcp__Checkmarx__codeRemediation` |
| "scan my dependencies" / "check package.json" (manifest/lockfile) | `checkmarx-devassist-sca` | SCA / OSS → `mcp__Checkmarx__packageRemediation` |
| whole project / cloud-scale scan | Checkmarx MCP (Cx1 cloud) tools | — |

A bare "scan this file" routes by the target: source code → ASCA; a dependency manifest/lockfile → SCA.

### Admin onboarding pre-fill (optional)

An administrator can pre-seed the Checkmarx One **URL** and **tenant** for browser (OAuth) sign-in by
editing `config/cx-onboarding.properties`. When set (and valid), the values are embedded straight into
the gate's `cx auth login` recovery command and the `checkmarx-cli-setup` skill skips the URL/tenant
question. Edit the file in your **forked / internal marketplace copy** (the reviewed, versioned
artifact) — not in an end-user's live install, which is overwritten on plugin update. Values are
strictly validated (https-only host for the URL; a shell-inert charset for the tenant); an invalid value
is ignored and the developer is asked as usual. There is deliberately no out-of-tree (`~/.checkmarx` /
env) override.

### Remembered login environments (automatic)

Without an admin pre-fill, every fresh OAuth sign-in used to re-ask the developer for their Checkmarx
One URL **and** tenant. `cx auth login` takes two paths (`auth_login.go:57-86` in
[`ast-cli`](https://github.com/Checkmarx/ast-cli)):

| Form | Prompt | Persisted to `checkmarxcli.yaml` |
|---|---|---|
| `cx auth login --base-uri … --tenant …` | skipped (`connectionFlagsProvided`) | refresh token **only** (`auth_login.go:102`) |
| `cx auth login` (bare, interactive) | `PromptAuthConnection` | token **+** `cx_base_uri` / `cx_base_auth_uri` / `cx_tenant` (`configuration.go:98-119`) |

An agent cannot answer an interactive prompt, so an agent-issued login is always the **flag** form —
the one that persists nothing. Observing the command as it is issued is therefore the mechanism used,
which is why the shell matcher keeps one hook: [`hooks/cx_record_login.sh`](hooks/cx_record_login.sh).
It records the pair as *pending* (snapshotting the credential file's timestamp **before** the login
runs), the gate promotes it to *confirmed* on the next successful authenticated call, and a later
logged-out deny offers up to 3 confirmed pairs as choices the developer picks from — never auto-used.
Stored in `cx_login_history.json` in the gate's private `0700` state dir (honours `CX_LOG_DIR`).

The observer is **not** a gate: it emits no decision and exits 0 on every path, including a missing
Python or an unwritable state dir. It cannot block a command. OAuth only — an API-key setup
(`cx configure set --prop-name cx_apikey …`) carries no URL/tenant to record.

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
(safe). But if the **POSIX shell** (`sh`) is missing — the default on Windows without Git for Windows —
the hook cannot spawn at all, which Copilot CLI treats as a non-blocking hook error, so the action
proceeds **UNSCANNED**. Without Git for Windows, Copilot CLI's own Bash tool falls back to PowerShell
and the `sh`-based gate can't launch either, so **Git for Windows is a hard prerequisite** — install and
verify it *before* relying on the gate.

Then the **`cx` CLI** itself, which the bundled **`checkmarx-cli-setup`** skill installs (with download
checksum verification), puts on PATH, and authenticates (API key or OAuth). The minimum version is a
numeric floor in `scripts/cx-min-version`; the real capability decision is a runtime probe (the
`cx mcp bridge` and `cx hooks copilot-cli-*` subcommands must all respond to `--help`).

---

## Installation

**Marketplace** (recommended):

```
/plugin marketplace add https://github.com/Checkmarx/cx-agentic-ai
/plugin install checkmarx-devassist@checkmarx-devassist-marketplace
```

After updating hook scripts, reload them into the session:

```
/restart
```

On first use the gate will detect that `cx` is missing and walk you through installing and
authenticating it via the **`checkmarx-cli-setup`** skill (`/checkmarx-cli-setup`).

---

## Updating

Update the plugin to the latest version published on the marketplace:

```
/plugin update checkmarx-devassist@checkmarx-devassist-marketplace
```

Update the marketplace listing itself (picks up newly published plugin versions):

```
/plugin marketplace update checkmarx-devassist-marketplace
```

After updating hook scripts, reload them into the session:

```
/restart
```

> If update fails with an `Access is denied` error, see [Troubleshooting](#troubleshooting).

---

## Uninstalling

Remove just the plugin (keeps the marketplace registered, so it can be reinstalled later):

```
/plugin uninstall checkmarx-devassist@checkmarx-devassist-marketplace
```

Remove the marketplace entirely (also removes any plugins installed from it):

```
/plugin marketplace remove checkmarx-devassist-marketplace
```

Uninstalling the plugin removes the hook wiring and skills, but does **not** remove the `cx` CLI itself
or its credentials/logs under `~/.checkmarx/`; remove those manually if a full cleanup is needed.

> If uninstall fails with an `Access is denied` error, see [Troubleshooting](#troubleshooting).

---

## Troubleshooting

**Windows file lock during update / uninstall** — `/plugin update`, `/plugin marketplace update`,
`/plugin uninstall`, or `/plugin marketplace remove` can fail with:

```
Failed to uninstall plugin: Failed to uninstall plugin: Access is denied. (os error 5)
```

This means another process is holding a file in the plugin directory open, so Windows won't let it be
replaced or deleted. Close any background processes or IDEs that use Copilot (VS Code, Visual Studio,
IntelliJ, Eclipse), then retry the update/uninstall.

---

## Configuration

All optional — sensible defaults apply.

| Variable | Purpose |
|---|---|
| `CX_BINARY` | Absolute path to `cx` when it isn't on `PATH` (validated: must be a real, recent, capable, authenticated cx). |
| `CX_GATE_ALL_FILES=1` | Gate **every** file write, not just [scannable types](#scannable-file-types) — restores the previous blocking behaviour for files. |
| `CX_LOG_DIR` | Override the log directory (default `~/.checkmarx/agent-logs/<assistant>/`). |
| `CX_LOG_DISABLE=1` | Turn structured logging off entirely. |
| `CX_ASSISTANT` | Label the assistant in logs (set to `copilot-cli` by `hooks-copilot-cli.json`). |
| `CX_REQUIRE_CHECKSUM=0` | Downgrade `cx-bootstrap.sh` to warn-and-proceed when it can't checksum-verify a download (checksum verification is **required by default**; not recommended). |
| `CX_ALLOW_UNSCANNED=1` | Audited emergency bypass — runs the action **unscanned** and records it to the audit log. |

---

## Privacy & logging

The gate writes one redacted JSONL record per decision to
`~/.checkmarx/agent-logs/copilot-cli/checkmarx-devassist.jsonl` — both the stage-1 readiness gate's own
allow/deny (`gate_decision`) and the stage-2 native scanner's allow/deny (`scan_decision`), so a tool
call blocked because of an actual finding is recorded, not just a blocked-because-cx-isn't-ready
decision. Logging uses a **redaction allowlist**: each event declares the exact keys it may write and a
type coercer per key. Anything else — source code, secrets, tokens, prompts, free-form strings — is
dropped before it can reach disk; `scan_decision` in particular never carries the finding/reason text,
only the outcome. Every record's `ts` is a UTC ISO-8601 timestamp (e.g. `2026-07-09T14:23:01Z`). The MCP
bridge sends your credential only in the `Authorization` header, never to chat or logs. Logging never
raises into the gate, and `CX_LOG_DISABLE=1` turns it off.

---

## License

Apache 2.0 — see [LICENSE](../../LICENSE) at the repo root, which governs this plugin along with the
rest of [Checkmarx Agentic AI](../../README.md).
