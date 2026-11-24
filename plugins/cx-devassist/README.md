# cx-devassist

A **fail-closed security gate** for **Claude Code**, backed by
[Checkmarx CxOne](https://checkmarx.com/).

Before Claude writes or edits a file, the plugin asks the `cx` CLI to scan the proposed content —
source code, IaC, dependency manifests, and **hardcoded secrets** in any file. If a real vulnerability,
secret or policy violation is found — **or if the scanner can't be trusted to run** — the write is
**blocked**, not silently allowed. Found issues are remediated interactively through the bundled
Checkmarx MCP server; a secret value is never shown in chat.

Shell commands are **not** gated, and with the secrets scanner switched off neither are file types no
other engine can scan: nothing would have been scanned there, so blocking them cost developers time
without buying protection. See [Scannable file types](#scannable-file-types).

> **Secrets engine caveat:** the native secret scan in `cx hooks claude-pre-file-write` needs cx
> 2.3.71 or later (the plugin's minimum). It fails open on a scanner error, a licence or feature-flag
> miss, or a crash, and on an `Edit` only **new** secrets block.

Part of [Checkmarx Agentic AI](../../README.md).

---

## How it works

Every gated tool call runs a **two-stage PreToolUse chain**:

1. **The gate** — `sh cx_check.sh` → `cx_check.py` — proves the scanner is trustworthy before anything
   is scanned: cx is **present → recent enough → capable → authenticated**. If any step can't be
   proven, it **denies (exit 2)** and stage 2 never runs.
2. **The scanner** — a native `cx hooks claude-*` subcommand that performs the actual analysis and
   decides whether to allow or block the action.

`hooks/hooks.json` wires the following:

| Tool event | Gate | Native scanner | What it checks |
|---|---|---|---|
| `Write` / `Edit` / `MultiEdit` / `NotebookEdit` — **scannable file** | `cx_check` | `cx hooks claude-pre-file-write` | Static analysis of the proposed content: ASCA (SAST), KICS (IaC), SCA (manifests), secrets |
| `Write` / `Edit` / … — any other file type, **secrets scanner off** | — | — | Nothing: no enabled engine scans it, so the write proceeds |
| `Bash` / `PowerShell` | — | — | **Not gated.** One non-blocking observer runs (`cx_record_login`) — see below |
| MCP calls (`mcp__Checkmarx__*`) | `cx_check` | `cx hooks claude-pre-tool-use` | Policy check before the MCP call is allowed |
| Session stop | — | `cx hooks claude-stop` | Session-end hook |

**Shell commands are never blocked.** They previously ran the full readiness gate, which blocked
`git status`, `npm test`, `mvn verify` and the like whenever cx was missing or unauthenticated — while
protecting nothing: the native shell handler only checks an admin blacklist and dependency installs
and **never inspects file content**, so shell-written code (`cat > app.py`) was already unscanned on a
healthy cx. The `Bash`/`PowerShell` matcher now carries a single observer,
[`hooks/cx_record_login.sh`](hooks/cx_record_login.sh), which notes the URL + tenant of a
`cx auth login` (see [Remembered login environments](#remembered-login-environments-automatic)) and
**exits 0 on every path**, so it cannot block. A pure-shell prefilter means an ordinary command spawns
nothing beyond `sh` itself.

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

**What that deny covers:** writes to [scannable files](#scannable-file-types) and Checkmarx MCP calls.
**What it does not:** shell commands — ever. So a developer whose cx is broken can still run `git`,
`npm`, `mvn`, `pytest` and `docker`, and — crucially — install and authenticate cx to unblock
themselves. With the secrets scanner on (the default) every file write is scannable; with it off,
writes to other file types also proceed, except in the two states where the gate cannot evaluate the
file type at all (cx unresolvable, or no Python 3), which deny every write.

### Scannable file types

The gate blocks a file write only when one of the engines can analyse that file. The ASCA / KICS / SCA
list is [`config/cx-scannable-files`](config/cx-scannable-files), and it mirrors the engines' own filters
in `ast-cli`; the secret engine has no filter:

| Engine | Files |
|---|---|
| **ASCA** (SAST) | `.java` `.js` `.jsx` `.ts` `.tsx` `.mjs` `.cjs` `.cs` `.go` `.py` `.pyw` |
| **KICS** (IaC) | `.tf` `.yaml` `.yml` `.json` `.proto` `.dockerfile` `.auto.tfvars` `.terraform.tfvars`, and `Dockerfile` |
| **SCA** (manifests) | `.csproj` `.sbt`; `pom.xml` `package.json` `bower.json` `yarn.lock` `Directory.Packages.props` `packages.config` `go.mod` `build.gradle` `build.gradle.kts` `libs.versions.toml` `setup.cfg` `setup.py` `pyproject.toml`; and `*.txt` starting `requirement`/`packages`/`constraint` |
| **Secrets** | Every other file — `.md`, `.txt`, `.env`, `.html`, `.css`, `.sql`, `.sh`, `.rb`, `.php`, `.c`, `.rs`, … — while `cx_secret_scanner_enabled` is on (the default) |

So with the shipped settings **every file write is gated**. With `cx_secret_scanner_enabled=false` in
`~/.checkmarx/cx-onboarding.properties`, everything outside the ASCA / KICS / SCA rows is not gated,
because no enabled engine would scan it; the write would have gone through unscanned even on a healthy
cx, so blocking it would be friction rather than protection. Two consequences worth knowing:

- `.json` and `.yaml` **are** gated, because KICS scans them. A `tsconfig.json` write still runs the
  full readiness check even though it is not IaC.
- With secrets off, a plain `.tfvars` is **not** gated: KICS lists only the compound `.auto.tfvars` /
  `.terraform.tfvars` suffixes, so it would not be scanned either.

The file has exactly one reader — `cx_check.py`'s `_is_scannable_file`. An earlier revision mirrored
the rule in POSIX shell so the two shell deny paths could apply it too; keeping two implementations of
one security decision in agreement proved unworkable (three fail-open divergences shipped), so the
shell copy was removed. Neither path needed one: when cx is missing entirely, stage 2 **defers** to
stage 1, which has already applied the rule correctly (it denies a scannable write on cx-absence and
allows an unscannable one). Only **no working Python 3** denies every file write, since the rule cannot
be evaluated at all without it. If the config file is unreadable or empty, every write is gated again:
fail-closed, never fail-open.

Editing it is how an administrator adjusts coverage; distribute it in your forked/internal copy of the
plugin, not in a live install directory (the same place an administrator sets the URL / tenant pre-fill in
`config/cx-onboarding.properties`).

---

## Plugin structure

```
plugins/cx-devassist/
├── .claude-plugin/
│   └── plugin.json              # Claude Code manifest (name, version, license)
├── .mcp.json                    # declares the Checkmarx MCP server (cx mcp bridge); auto-discovered
├── README.md
├── config/
│   ├── cx-onboarding.properties # URL + tenant pre-fill, scanner switches, severity threshold (seeded to ~/.checkmarx)
│   └── cx-scannable-files       # the file types the gate blocks on — mirrors ASCA/KICS/SCA filters (secrets: every file)
├── hooks/
│   ├── hooks.json               # Claude Code PreToolUse / Stop wiring
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
│   ├── cx-min-version           # minimum cx version (numeric floor)
│   └── cx-release-tag           # pinned ast-cli release the bootstrap downloads
└── skills/
    ├── cx-cli-setup/            # guided cx install + authentication (router + references/)
    ├── cx-devassist-asca/       # on-demand SAST (ASCA) scan + remediation for source files
    ├── cx-devassist-sca/        # on-demand SCA (OSS) scan + remediation for dependency manifests
    ├── cx-devassist-kics/       # on-demand IaC (KICS) scan + remediation for Dockerfile/Terraform/K8s YAML
    └── cx-devassist-secrets/    # on-demand secret scan + remediation for hardcoded secrets in any file
```

> Tests live at the **repo root** (`tests/`), outside the shipped plugin, so they aren't distributed.

### On-demand scanning (skills)

Beyond the automatic PreToolUse gate, four skills scan on request and remediate via the Checkmarx MCP:

| Ask | Skill | Engine |
|---|---|---|
| "scan this file" / "check app.py" (source code) | `cx-devassist-asca` | SAST (ASCA) → `mcp__Checkmarx__codeRemediation` |
| "scan my dependencies" / "check package.json" (manifest/lockfile) | `cx-devassist-sca` | SCA / OSS → `mcp__Checkmarx__packageRemediation` |
| "scan this Dockerfile" / "check main.tf" (IaC file) | `cx-devassist-kics` | IaC (KICS) → `mcp__Checkmarx__codeRemediation` |
| "scan this file for secrets" / "check .env.example" (hardcoded secrets) | `cx-devassist-secrets` | Secrets → `mcp__Checkmarx__codeRemediation` (`type: secret`) |
| whole project / cloud-scale scan | Checkmarx MCP (Cx1 cloud) tools | — |

A bare "scan this file" routes by the target: source code → ASCA; a dependency manifest/lockfile → SCA;
an IaC file (Dockerfile, `.tf`, `.yaml`/`.yml`, …) → KICS; hardcoded secrets → secrets.

### URL / tenant pre-fill (optional)

Set `cx_base_auth_uri` and `cx_tenant` in `~/.checkmarx/cx-onboarding.properties` (the developer's copy) or
in the bundled `config/cx-onboarding.properties` (an administrator, in the **forked / internal marketplace
copy**; a live install is overwritten on update). A valid value in the user copy wins over the bundled one,
per key. When both resolve, they are embedded straight into the gate's `cx auth login` recovery command and
the `cx-cli-setup` skill skips the URL/tenant question. Values are strictly validated for both files (https-only
host for the URL; a shell-inert charset for the tenant); an invalid value is ignored and the developer is
asked as usual.

### Scanner switches and severity threshold (user-editable)

The first time a hook runs after install (or the MCP bridge starts), the plugin copies
`config/cx-onboarding.properties` to `~/.checkmarx/cx-onboarding.properties` (Windows:
`%USERPROFILE%\.checkmarx\`). It is never overwritten afterwards, so edits survive plugin updates; an update
only appends settings it newly introduced (delete the file to re-seed). The copy is shared with other
cx-devassist plugins on the machine (e.g. Copilot CLI). Every scanner is **enabled by default**; set
`cx_asca_scanner_enabled`, `cx_sca_scanner_enabled`, `cx_kics_scanner_enabled` or `cx_secret_scanner_enabled`
to `false` to skip that scanner's skill. With the secrets scanner off, the gate also stops requiring a ready,
authenticated cx for a file only the secret engine would scan (e.g. `app.env`). `cx_severity_threshold`
(`low`…`critical`; blank or invalid = `low`) limits what the skills report and remediate and, with a cx build
that includes the ast-cli change, what ASCA/KICS/SCA block; the secrets skill applies it too. Malicious packages
are never relaxed. Switches only narrow behaviour and never cause a hook to deny; a typo leaves the scanner
enabled. A cx CLI build that reads this file (ast-cli `agenthooks/scannerconfig`) also skips each disabled engine
in the native pre-write scan; older builds ignore the switches.

### Remembered login environments (automatic)

Without an admin pre-fill, every fresh OAuth sign-in used to re-ask the developer for their Checkmarx
One URL **and** tenant. `cx auth login` takes two paths (`auth_login.go:57-86` in `ast-cli`):

| Form | Prompt | Persisted to `checkmarxcli.yaml` |
|---|---|---|
| `cx auth login --base-uri … --tenant …` | skipped (`connectionFlagsProvided`) | refresh token **only** (`auth_login.go:102`) |
| `cx auth login` (bare, interactive) | `PromptAuthConnection` | token **+** `cx_base_uri` / `cx_base_auth_uri` / `cx_tenant` (`configuration.go:98-119`) |

An agent cannot answer an interactive prompt, so an agent-issued login is always the **flag** form —
the one that persists nothing (a non-interactive stdin sets nothing either). With an API key the values
are not even that — they live only inside the JWT, whose `iss` yields the IAM host rather than the app
host a developer types. A developer's *own* interactive login does leave them on disk, so reading
`checkmarxcli.yaml` would be a valid additional source for the offer; that is not done today.

Observing the command as it is issued is therefore the mechanism used, which is why the
`Bash`/`PowerShell` matcher keeps one hook: [`hooks/cx_record_login.sh`](hooks/cx_record_login.sh).
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
/plugin marketplace add Checkmarx/cx-agentic-ai
/plugin install cx-devassist@cx-devassist-marketplace
```

Verify:

```bash
claude plugin list      # cx-devassist@cx-devassist-marketplace  ✔ enabled
```

**Direct plugin-dir** (quick local testing):

```bash
claude --plugin-dir /path/to/cxone-scanners/plugins/cx-devassist
```

After updating hook scripts, reload them into the session:

```
/reload-plugins
```

On first use the gate will detect that `cx` is missing and walk you through installing and
authenticating it via the **`cx-cli-setup`** skill (`/cx-cli-setup`).

---

## Uninstall

To remove the plugin entirely:

```bash
claude plugin uninstall cx-devassist@cx-devassist-marketplace
```

This removes the plugin from Claude Code. The `cx` CLI binary itself remains on your system (in `~/.checkmarx` or
your configured location). To remove it as well:

```bash
rm -rf ~/.checkmarx        # Unix / macOS / WSL
rmdir %LOCALAPPDATA%\Checkmarx  # Windows PowerShell
```

Cached logs and state are stored in `~/.checkmarx/agent-logs/`; remove them separately if desired.

---

## Upgrade

The plugin auto-updates through Claude Code's marketplace system. To manually check for updates:

```bash
/plugin update cx-devassist@cx-devassist-marketplace
```

After updating the plugin, reload it in your current session:

```bash
/reload-plugins
```

The `cx` CLI itself updates independently. Run `/cx-cli-setup` if prompted, or manually upgrade via:

```bash
sh scripts/cx-bootstrap.sh upgrade
```

from within the plugin directory. The bootstrap script will download and install the latest compatible
version of the `cx` CLI, verify its checksum, and update your PATH if needed.

---

## Configuration

All optional — sensible defaults apply.

| Variable | Purpose |
|---|---|
| `CX_BINARY` | Absolute path to `cx` when it isn't on `PATH` (validated: must be a real, recent, capable, authenticated cx). |
| `CX_GATE_ALL_FILES=1` | Gate **every** file write, not just [scannable types](#scannable-file-types) — restores the previous blocking behaviour for files. |
| `CX_LOG_DIR` | Override the log directory (default `~/.checkmarx/agent-logs/<assistant>/`). |
| `CX_LOG_DISABLE=1` | Turn structured logging off entirely. |
| `CX_ASSISTANT` | Label the assistant in logs (default `claude`). |
| `CX_REQUIRE_CHECKSUM=1` | Make `cx-bootstrap.sh` refuse to install an asset it can't checksum-verify. |

---

## Privacy & logging

The gate writes one redacted JSONL record per decision to
`~/.checkmarx/agent-logs/<assistant>/cx-devassist.jsonl` — both the stage-1 readiness gate's own
allow/deny (`gate_decision`) and the stage-2 native scanner's allow/deny (`scan_decision`), so a tool
call blocked because of an actual finding is recorded, not just a blocked-because-cx-isn't-ready
decision. Logging uses a **redaction allowlist**: each event declares the exact keys it may write and
a type coercer per key. Anything else — source code, secrets, tokens, prompts, free-form strings — is
dropped before it can reach disk; `scan_decision` in particular never carries the finding/reason text,
only the outcome. Every record's `ts` is a UTC ISO-8601 timestamp (e.g. `2026-07-09T14:23:01Z`). The
MCP bridge sends your credential only in the `Authorization` header, never to chat or logs. Logging
never raises into the gate, and `CX_LOG_DISABLE=1` turns it off.

---

## License

Apache 2.0 — see [LICENSE](../../LICENSE) at the repo root, which governs this plugin along with the
rest of [Checkmarx Agentic AI](../../README.md).
