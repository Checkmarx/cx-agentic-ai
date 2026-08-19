# Cx-Devassist For Gemini CLI

A **fail-closed security gate** for **Gemini CLI**, backed by
[Checkmarx CxOne](https://checkmarx.com/).

Before Gemini creates or edits a file, the plugin asks the Checkmarx `cx` CLI to scan the proposed
content. If a real vulnerability or policy violation is found — **or if the scanner can't be trusted to
run** — the action is **blocked**, not silently allowed. The agent then asks whether to **remediate**
(MCP fix) or **suppress** (false positive) — same as Claude Code — before calling Checkmarx MCP tools.

---

## How it works

`hooks/hooks.json` wires a **two-stage `BeforeTool` chain** (Gemini CLI's pre-tool-call
hook event — see the
[Gemini CLI hooks reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md)):

1. **The gate** — `sh cx_check.sh --gemini-cli` → `cx_check.py` — proves the scanner is trustworthy
   before anything is scanned: cx is **present → recent enough → capable → authenticated**. If any step
   can't be proven, it denies and stage 2 never runs.
2. **The scanner** — a native `cx hooks gemini-cli-*` subcommand that performs the actual analysis and
   decides whether to allow or block the action.

| Tool event | Gate | Native scanner | What it checks |
|---|---|---|---|
| `WriteFile` / `write_file` / `write_.*` / `replace` — **scannable file** | `cx_check` | `cx hooks gemini-before-file-tool` | Static analysis (ASCA / SAST, KICS / IaC, SCA / manifests) of the proposed content |
| `WriteFile` / `write_file` / `write_.*` / `replace` — any other file type | — | — | Nothing: no engine can scan it, so the write proceeds |
| `run_shell_command` | — | — | **Not gated.** One non-blocking observer runs (`cx_record_login`) — see below |
| `mcp_.*` | `cx_check` | `cx hooks gemini-before-tool` | Policy check before the MCP call is allowed |

Route names (`gemini-before-tool`, `gemini-before-file-tool`, …) match the dispatch routes ast-cx-hooks'
route catalog defines for Gemini CLI — the same routes `cx hooks install` writes into
`~/.gemini/settings.json` when installing hooks natively without this plugin.

The scanning logic itself lives in the `cx` CLI (maintained centrally by Checkmarx); this plugin is a
thin, hardened wrapper that **guarantees cx is ready, installs it when missing, and wires the
remediation MCP** — nothing more.

### Remediation (MCP)

When a finding needs fixing, remediation runs through the **Checkmarx MCP server** (`cx mcp bridge`),
declared in the `mcpServers` block of `gemini-extension.json` and started automatically by Gemini CLI —
no manual registration step. It exposes code- and package-remediation tools
(`mcp__Checkmarx__codeRemediation`, …) that the agent calls directly. A single `cx` sign-in covers both
the CLI and the MCP. See
[`skills/checkmarx-cli-setup/references/mcp.md`](skills/checkmarx-cli-setup/references/mcp.md).

**End-to-end flow after a hook deny (finding):**

1. Agent presents findings and asks **remediate** vs **suppress** (see `GEMINI.md`).
2. **Remediate** → activate `checkmarx-devassist-asca` or `checkmarx-devassist-sca` and run **Flow 2
   Steps 2–5** (MCP fix → apply via file-write tool → **mandatory Step 4 re-scan** → summary).
3. When Step 4 is clean for in-scope findings → **retry the original blocked write once** (hooks
   re-scan proposed content).
4. **Suppress** → run `cx ignore-vulnerability` from the deny message, then retry the write once.

Fixes must use the **file-write tool**, not `run_shell_command` — shell commands are never scanned.
Step 4 re-scan (`cx scan asca` / `cx scan oss-realtime`) is verification, not optional proactive scanning.

---

## Fail-closed by design

The gate is engineered so that **uncertainty blocks.** A Gemini CLI `BeforeTool` hook **denies via
exit code 0 with `{"decision":"deny","reason":"...","systemMessage":"..."}` on stdout** — Gemini
treats only exit 0 as hook success; `decision:"deny"` blocks the tool and `systemMessage` is shown
to the user in the terminal (non-zero exit marks the hook as *failed* and surfaces only a generic
F12 warning). `cx_check.sh`/`cx_check.py` handle this explicitly via the `--gemini-cli` flag (flat
JSON + exit 0 for Gemini; nested `hookSpecificOutput` + exit 2 for Claude Code), so every "can't
evaluate" path is routed to the correct deny shape for this client, and the gate is hardened against
the cross-OS holes that would otherwise let an unscanned action through:

- **Windows** — hooks invoke `sh` (which only ever resolves to Git Bash), never bare `bash` (which
  Windows resolves to the System32 WSL stub → exit 127 → treated as a hook error → fail-open).
- **Linux / macOS** — the launcher requires Python 3, and all shipped scripts are pinned to LF line
  endings, so a stray Python 2 or a `\r` can't slip an action past the scan.
- **Any OS** — an unexpected error inside the gate still emits a deny (not a crash) so the action stays
  blocked.

If cx is missing, below the minimum version, missing the required subcommands (`incapable`), or
unauthenticated, the gate denies with a clear, actionable message pointing at `/checkmarx-cli-setup`.

**What that deny covers:** writes to [scannable files](#scannable-file-types) and Checkmarx MCP calls.
**What it does not:** shell commands — ever. So a developer whose cx is broken can still run `git`,
`npm`, `mvn`, `pytest` and `docker`, and — crucially — install and authenticate cx to unblock
themselves. The `run_shell_command` matcher carries a single observer,
[`hooks/cx_record_login.sh`](../hooks/cx_record_login.sh), which notes the URL + tenant of a
`cx auth login` (see [Remembered login environments](#remembered-login-environments-automatic)) and
never blocks.

### Scannable file types

The gate blocks a file write only when one of the three engines can analyse that file. The list is
[`config/cx-scannable-files`](../config/cx-scannable-files), and it mirrors the realtime-scanner
filters in `ast-vscode-extension` (`packages/core/src/utils/common/constants.ts`), plus — for SCA
manifests only — the wider package-manager coverage added in `ast-jetbrains-plugin` PR #452
(`DevAssistConstants.MANIFEST_FILE_PATTERNS`):

| Engine | Files |
|---|---|
| **ASCA** (SAST) | `.java` `.cs` `.go` `.py` `.js` `.jsx` |
| **KICS** (IaC) | `.tf` `.yaml` `.yml` `.json` `.proto` `.dockerfile` `.auto.tfvars` `.terraform.tfvars`, and `Dockerfile` |
| **SCA** (manifests) | `.csproj` `.sbt` `.gradle` `.gradle.kts` `.podspec` `.podspec.json`; `pom.xml` `package.json` `Directory.Packages.props` `packages.config` `go.mod` `libs.versions.toml` `setup.cfg` `setup.py` `pyproject.toml` `Podfile` `Cartfile` `Cartfile.private` `Package.swift` `Gemfile` `bower.json` `composer.json` `pubspec.yaml`; and `*.txt` starting `requirement`/`constraint` |

`Package@swift-*.swift` (a versioned Swift Package Manager manifest) has no exact representation in
this file's `ext`/`suffix`/`base`/`txtprefix` vocabulary and is knowingly not covered — adding it would
mean gating every `.swift` file.

Everything else — `.md`, `.txt`, `.html`, `.css`, `.sql`, `.sh`, `.rb`, `.php`, `.c`, `.rs` — is not
gated, because no engine would scan it; the write would have gone through unscanned even on a healthy
cx, so blocking it was friction rather than protection. Two consequences worth knowing:

- `.json` and `.yaml` **are** gated, because KICS scans them. A `tsconfig.json` write still runs the
  full readiness check even though it is not IaC.
- A plain `.tfvars` is **not** gated: KICS lists only the compound `.auto.tfvars` /
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
extension, not in a live install directory (same boundary as `config/cx-onboarding.properties`).

---

## Plugin structure

> The extension manifest, `gemini-extension.json`, lives at the **repository root** — so that when
> installed/linked under `~/.gemini/extensions/cx-devassist`, the manifest is automatically discovered.
> All paths within the manifest and the hooks config resolve relative to `${extensionPath}` (the root
> of the installed extension).

```
cx-agentic-ai/                   # repo root — also the extension root
├── gemini-extension.json
├── GEMINI.md                    # extension context — hooks vs skills routing (loaded every session)
├── config/
│   ├── cx-onboarding.properties # OPTIONAL admin pre-fill of Checkmarx One URL + tenant (onboarding)
│   └── cx-scannable-files       # the file types the gate blocks on — mirrors ASCA/KICS/SCA filters
├── hooks/
│   ├── hooks.json               # Gemini CLI BeforeTool/hook registration config
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

Beyond the automatic PreToolUse gate, two skills scan on request and remediate via the Checkmarx MCP.
**Skills are explicit-only** — do not activate them for normal file creation or dependency edits; the
hooks already scan those writes. See `GEMINI.md` for routing rules.

| Ask | Skill | Engine |
|---|---|---|
| "scan this file" / "check app.py" (source code) | `checkmarx-devassist-asca` | SAST (ASCA) → `mcp__Checkmarx__codeRemediation` |
| "scan my dependencies" / "audit package.json for vulnerabilities" (manifest/lockfile) | `checkmarx-devassist-sca` | SCA / OSS → `mcp__Checkmarx__packageRemediation` |
| whole project / cloud-scale scan | Checkmarx MCP (Cx1 cloud) tools | — |

A bare "scan this file" routes by the target: source code → ASCA; a dependency manifest/lockfile → SCA.
Creating or editing `package.json` is **not** a scan request — just write the file and let the hook scan it.

### Admin onboarding pre-fill (optional)

An administrator can pre-seed the Checkmarx One **URL** and **tenant** for browser (OAuth) sign-in by
editing `config/cx-onboarding.properties`. When set (and valid), the values are embedded straight into
the gate's `cx auth login` recovery command and the `checkmarx-cli-setup` skill skips the URL/tenant
question. Edit the file in your **forked / internal copy** (the reviewed, versioned artifact) — not in
an end-user's live install, which is overwritten on extension update. Values are
strictly validated (https-only host for the URL; a shell-inert charset for the tenant); an invalid value
is ignored and the developer is asked as usual. There is deliberately no out-of-tree (`~/.checkmarx` /
env) override.

### Remembered login environments (automatic)

Without an admin pre-fill, every fresh OAuth sign-in used to re-ask the developer for their Checkmarx
One URL **and** tenant. `cx auth login` takes two paths in `ast-cli`:

| Form | Prompt | Persisted to `checkmarxcli.yaml` |
|---|---|---|
| `cx auth login --base-uri … --tenant …` | skipped | refresh token **only** |
| `cx auth login` (bare, interactive) | interactive | token **+** URL / tenant |

An agent cannot answer an interactive prompt, so an agent-issued login is always the **flag** form —
the one that persists nothing. Observing the command as it is issued is therefore the mechanism used,
which is why the `run_shell_command` matcher keeps one hook:
[`hooks/cx_record_login.sh`](../hooks/cx_record_login.sh). It records the pair as *pending*
(snapshotting the credential file's timestamp **before** the login runs), the gate promotes it to
*confirmed* on the next successful authenticated call, and a later logged-out deny offers up to 3
confirmed pairs as choices the developer picks from — never auto-used. Stored in `cx_login_history.json` under
`~/.checkmarx/agent-logs/<assistant>/` (Gemini CLI: `…/gemini-cli/cx_login_history.json`; honours
`CX_LOG_DIR`).

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
the hook cannot spawn at all; whether that fails open or closed depends on how the installed Gemini CLI
version treats an unspawnable hook, so **Git for Windows is a hard prerequisite regardless** — install
and verify it *before* relying on the gate.

Then the **`cx` CLI** itself, which the bundled **`checkmarx-cli-setup`** skill installs (with download
checksum verification), puts on PATH, and authenticates (API key or OAuth). The minimum version is a
numeric floor in `scripts/cx-min-version`; the real capability decision is a runtime probe (the
`cx mcp bridge` and `cx hooks gemini-before-*` subcommands must all respond to `--help`).

---

## Installation

Gemini CLI installs extensions from a Git repository or a **local directory that contains
`gemini-extension.json` at its root**. `gemini-extension.json` lives at the root of this monorepo,
so install/link the repository root directly.

**From GitHub**:

```
gemini extensions install https://github.com/Checkmarx/cx-agentic-ai.git
```

**Local development**:

```
gemini extensions install "C:\path\to\cx-agentic-ai"
```

Or link for live iteration:

```
gemini extensions link "C:\path\to\cx-agentic-ai"
```

Restart Gemini CLI (or run `/extensions reload`) so hooks, MCP, and skills are picked up. Then verify:

```
/extensions list
/skills list
/skills reload
```

You should see extension `cx-devassist` and three skills (`checkmarx-cli-setup`,
`checkmarx-devassist-asca`, `checkmarx-devassist-sca`). If `/skills list` is empty, the extension
was installed from the wrong directory — uninstall and reinstall using the path above.

> `gemini extensions install` flags (`--ref` to pin a branch/tag, `--path` for monorepo subdirs, …)
> can change between Gemini CLI releases — check `gemini extensions install --help` if a command
> above doesn't match your installed version.

On first use the gate will detect that `cx` is missing and walk you through installing and
authenticating it via the **`checkmarx-cli-setup`** skill (`/checkmarx-cli-setup`).

---

## Updating

```
gemini extensions update cx-devassist
```

Restart Gemini CLI (or `/extensions reload`) after updating so the hook scripts and MCP server config
reload.

---

## Uninstalling

```
gemini extensions uninstall cx-devassist
```

Uninstalling the extension removes the hook wiring and skills, but does **not** remove the `cx` CLI
itself or its credentials/logs under `~/.checkmarx/`; remove those manually if a full cleanup is needed.

---

## Troubleshooting

**`/skills list` shows "No skills available"** — check these in order:

1. **UTF-8 BOM in `SKILL.md`** — if `gemini extensions list` shows `cx-devassist` with hooks/MCP
   but **no "Agent skills"**, frontmatter could not be parsed. Re-save `skills/*/SKILL.md` as
   UTF-8 **without BOM** (must start with `---`).
2. **Wrong install path** — install from the repository root, which is where `gemini-extension.json`
   lives (see [Installation](#installation)).
3. Reload — `/extensions reload` then `/skills reload`.

**Vulnerable code writes are not blocked** — Gemini CLI may invoke `WriteFile` (not `write_file`).
If hooks were installed from the wrong path, or the matcher omitted `WriteFile`, the scanner never
runs. Reinstall the extension from the repository root and retry; the hook matchers now
include `WriteFile|write_file|write_.*|replace`.

**Windows file lock during update / uninstall** — if `gemini extensions update`/`uninstall` fails
because a file in the extension directory is in use, close any background processes or IDEs that use
Gemini CLI, then retry.

---

## Configuration

All optional — sensible defaults apply.

| Variable | Purpose |
|---|---|
| `CX_BINARY` | Absolute path to `cx` when it isn't on `PATH` (validated: must be a real, recent, capable, authenticated cx). |
| `CX_LOG_DIR` | Override the log directory (default `~/.checkmarx/agent-logs/<assistant>/`). |
| `CX_LOG_DISABLE=1` | Turn structured logging off entirely. |
| `CX_ASSISTANT` | Label the assistant in logs (set to `gemini-cli` by `hooks.json`). |
| `CX_REQUIRE_CHECKSUM=0` | Downgrade `cx-bootstrap.sh` to warn-and-proceed when it can't checksum-verify a download (checksum verification is **required by default**; not recommended). |
| `CX_GATE_ALL_FILES=1` | Gate **every** file write, not just [scannable types](#scannable-file-types) — restores the previous blocking behaviour for files. |
| `CX_ALLOW_UNSCANNED=1` | Audited emergency bypass — runs the action **unscanned** and records it to the audit log. |

---

## Privacy & logging

The gate writes one redacted JSONL record per decision to
`~/.checkmarx/agent-logs/gemini-cli/checkmarx-devassist.jsonl` — both the stage-1 readiness gate's own
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

Apache 2.0 — see [LICENSE](../LICENSE) at the repo root, which governs this plugin along with the
rest of [Checkmarx Agentic AI](../README.md).
