# Checkmarx DevAssist for Cursor (`cx-devassist-cursor`)

A **fail-closed security gate** for **Cursor**, backed by
[Checkmarx CxOne](https://checkmarx.com/). Plugin id `cx-devassist` · version `1.0.0` · Apache-2.0.

Before Cursor writes or edits a file the Checkmarx engines can scan — source code, IaC, or a dependency
manifest — the plugin asks the `cx` CLI to scan the proposed content **before the write lands**, and
can deny it outright on a real finding. Shell commands and file types no engine can scan are **not**
gated: nothing would have been scanned there, so blocking them cost developers time without buying
protection. MCP calls are still fully gated. A separate, advisory-only hook fires when the agent tries
to stop — it cannot block the agent from stopping.


### Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Fail-closed by design](#fail-closed-by-design)
- [Cross-shell behaviour](#cross-shell-behaviour-powershell--cmdexe--bash--sh)
- [Plugin structure](#plugin-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Uninstalling](#uninstalling)
- [Privacy & logging](#privacy--logging)
- [License](#license)

---

## Quick start

1. **Install the plugin:**
   ```bash
   cursor-agent plugin marketplace add https://github.com/Checkmarx/cx-agentic-ai
   ```
   (or copy/symlink this folder to `~/.cursor/plugins/local/cx-devassist-cursor/` — see
   [Installation](#installation) for the manual/offline alternative).
2. **Wire hooks + rules and install `cx`** — from a Cursor CLI terminal (`agent`), run:
   ```text
   /cx-install-wiring
   ```
   then restart the CLI session (`/exit`, then `agent` again) so the hooks, rules, and MCP bridge load.
3. **Start coding.** Every scannable file write and every Checkmarx MCP call is now scanned
   automatically; `/cx-devassist-asca` and `/cx-devassist-sca` are available on demand for source files
   and dependency manifests.

Already have `cx` installed and hooks wired elsewhere? Just authenticate: run `/cx-cli-setup` any time
`cx` is missing, outdated, or a hook denies with an auth error.

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
| `beforeShellExecution` | — | — | **Not gated.** One non-blocking observer (`cx_record_login.sh`) notes `cx auth login` URL/tenant for later re-auth |
| `beforeMCPExecution` | `cx_check` | `cx hooks cursor-before-mcp` | **Deny** if cx missing / not authed, or a real finding |
| `preToolUse` (Write/StrReplace/Edit/…) — **scannable file** | `cx_check` | `cx hooks cursor-before-file-write` | **Deny** if cx missing / not authed, or a real finding |
| `preToolUse` — other file types | — | — | Nothing: no engine can scan it, so the write proceeds |
| `stop` | — | `cx hooks cursor-stop` | Session end; advisory only — this hook cannot block the agent from stopping |

`preToolUse` is the only one of these that can actually block: it denies both when cx itself isn't
ready (missing/outdated/unauthenticated) **and** when the native scanner finds a real vulnerability in
the proposed content. `stop` runs after the agent has already decided to stop, so it cannot block
anything either (see [Session-end hook](#session-end-hook-stop) below).

### Scannable file types

The gate blocks a file write only when one of the three engines can analyse that file. The list is
[`config/cx-scannable-files`](config/cx-scannable-files), mirroring the engines' own filters in
`ast-cli` (ASCA/SAST, KICS/IaC, SCA/manifests). Everything else — `.md`, `.css`, `.sql`, `.sh` — is
not gated. The file has exactly one reader — `cx_check.py`'s `_is_scannable_file`. Set
`CX_GATE_ALL_FILES=1` to restore the previous "gate every file write" behaviour.

### Session-end hook (`stop`)

`hooks.json` wires `stop` straight to the native `sh cx_run.sh hooks cursor-stop` (10s timeout, no
`failClosed`) — unlike the scan hooks above, `cx_run.sh` does not intercept or interpret this call at
all; it resolves `cx` and execs it transparently, relaying whatever that native subcommand prints and
exits with, unchanged. `cx_run.sh`'s own fallback path for this event (cx absent) documents it as an
"advisory lifecycle hook" that "stays non-blocking" — this plugin makes no claims about, and does not
depend on, any specific field or retry behavior the native subcommand's output may contain, and there
is no `followup_message` concept anywhere in this plugin's own hook code.

The scanning logic itself lives in the `cx` CLI (maintained centrally by Checkmarx); this plugin is a
thin, hardened wrapper that **guarantees cx is ready, installs it when missing, and wires the
remediation MCP** — nothing more.

### Remediation (MCP)

When a finding needs fixing, remediation runs through the **Checkmarx MCP server** (`cx mcp bridge`),
declared in `mcp.json` and loaded automatically . It exposes code- and package-remediation tools
(`mcp__plugin-cx-devassist-Checkmarx__codeRemediation`, …) that the agent calls directly. A single `cx` sign-in covers
both the CLI and the MCP.

---

## Fail-closed by design

The gate is engineered so that **uncertainty blocks** scannable file writes and MCP calls wherever
Cursor allows it. Shell commands are never blocked — a broken cx must not stop `git`, `npm`, or
bootstrap install commands.

- **Windows** — hooks invoke `sh` (which only ever resolves to Git Bash), never bare `bash` (which
  Windows resolves to the System32 WSL stub → exit 127 → unscanned).
- **Linux / macOS** — the launcher requires Python 3, and all shipped scripts are pinned to LF line
  endings, so a stray Python 2 or a `\r` can't slip an action past the scan.
- **Any OS** — an unexpected error inside the gate denies fail-closed instead of crashing through.

If cx is missing, below the minimum version, missing the required subcommands (`incapable`), or
unauthenticated, scannable file writes and MCP calls are denied with a clear, actionable message that
names the exact bootstrap command to run. Shell commands and writes to unscannable file types still
proceed (except when Python 3 is absent — then every file write is blocked because the gate cannot
evaluate file types at all).

**Hook-chain failures vs. policy decisions.** A deny always means one of two things, and the deny
text says which: (1) a real policy decision — cx isn't ready, or the native scanner found something —
or (2) a hook-CHAIN failure — the gate or scanner crashed/timed out **before or during** the scan, so
no content was ever evaluated. Both stages log and label case (2) distinctly (`gate_crash` in
`cx_check.py`'s crash guard, `error_during_block` in `cx_run.sh`'s scan-decision classification) so
`cx-devassist.jsonl` and the message shown to the agent never conflate "the scan denied this" with
"the scan never ran." Retrying the same operation once is the right response to a hook-chain failure.

**Batched writes and probe contention.** Cursor can fire several `Write`/`Edit` hooks at once (e.g. a
multi-file batch). On a cold/expired cache, each of those invocations independently needs the same
`cx version` / `cx auth validate` / `cx hooks check-auth` result — without coordination, all of them
would spawn that subprocess simultaneously, and the resulting CPU/network contention was a common
cause of an otherwise-healthy invocation blowing its own hooks.json timeout (case (2) above). The gate
serializes each cache miss with a short-lived, self-expiring lock file (`_acquire_probe_lock` in
`cx_check.py`) so only one invocation in the batch actually probes; the rest reuse its result. The
lock is best-effort and bounded — it can never itself block or fail the gate open.

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
/plugins/cursor-devassist/
├── .cursor-plugin/
│   └── plugin.json              # Cursor manifest (hooks → hooks/hooks.json, mcp → mcp.json)
├── mcp.json                     # Checkmarx MCP server (${CURSOR_PLUGIN_ROOT})
├── README.md
├── config/
│   ├── cx-onboarding.properties # OPTIONAL admin pre-fill of Checkmarx One URL + tenant (onboarding)
│   └── cx-scannable-files       # file types the gate blocks on — mirrors ASCA/KICS/SCA filters
├── hooks/
│   ├── hooks.json               # Cursor hook wiring (${CURSOR_PLUGIN_ROOT}/hooks/ paths)
│   ├── hooks.json.template      # Template for install-hooks.sh (sed __CURSOR_PLUGIN_ROOT__ → absolute path)
│   ├── cx_check.sh              # POSIX launcher — resolves Git Bash + Python 3, then runs the gate
│   ├── cx_check.py              # the fail-closed gate (present → recent → capable → authenticated)
│   ├── cx_shell.py              # cross-shell command parsing + rendering (PowerShell/cmd/bash/sh)
│   ├── _cx_bootstrap_match.sh   # trusted-setup matcher for the shell stages (delegates to cx_check.py)
│   ├── cx_record_login.sh       # non-blocking observer: remembers OAuth URL + tenant
│   ├── cx_run.sh                # resolves cx by absolute path; runs the native scanner + MCP bridge
│   └── cx_log.py                # structured, redacted JSONL logging
├── scripts/
│   ├── cx-bootstrap.sh          # download + checksum-verify + install the cx CLI (self-install)
│   ├── cx-asset-resolver.sh     # OS/arch → release asset name
│   ├── cx-mcp-guard.sh          # version/capability decision for `cx mcp bridge`
│   ├── cx-path-probe.sh         # first writable on-PATH directory
│   ├── cx-min-version           # minimum cx version (numeric floor)
│   ├── install-hooks.sh         # merges hooks + syncs rules into user/project .cursor/ (user or project scope)
│   ├── cx-hooks-merge.py        # JSON merge for hooks — preserves unrelated hooks, replaces only ours
│   └── cx-rules-install.py      # syncs cx-*.mdc rules into .cursor/rules/ (preserves unrelated rules)
├── skills/
│   ├── cx-cli-setup/            # guided cx install + authentication (router + references/)
│   ├── cx-install-wiring/       # on-demand CLI-only: hooks + rules → auto-continues into cx-cli-setup
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
| "scan this file" / "check app.py" (source code) | `cx-devassist-asca` | SAST (ASCA) → `mcp__plugin-cx-devassist-Checkmarx__codeRemediation` |
| "scan my dependencies" / "check package.json" (manifest/lockfile) | `cx-devassist-sca` | SCA / OSS → `mcp__plugin-cx-devassist-Checkmarx__packageRemediation` |

A bare "scan this file" routes by the target: source code → ASCA; a dependency manifest/lockfile → SCA.

### Setup skills (when to use which)

| Skill | Surface | When |
|---|---|---|
| `/cx-install-wiring` | **Cursor CLI** (intended) | **On-demand** — developer types `/cx-install-wiring`. Wires hooks + rules, then auto-continues into `cx` install/auth. **Always run Phase 1 when invoked** — do not refuse based on IDE vs CLI guessing. |
| `/cx-cli-setup` | Cursor CLI **or** IDE | `cx` missing, outdated, unauthenticated, or re-auth. Also used when a **hook deny** surfaces setup (hooks already wired — never run `install-hooks.sh` from this path). |

`/cx-install-wiring` is **on-demand only** (`disable-model-invocation: true`) — it is not auto-selected
by the agent. After it finishes in CLI, **restart the terminal / start a new `agent` session** (not
**Developer: Reload Window**, which is IDE-only).

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

### Marketplace install (recommended)

From a **Cursor CLI** terminal (`cursor-agent`), add this repo as a plugin marketplace, then install
the plugin from it:

```bash
cursor-agent plugin marketplace add https://github.com/Checkmarx/cx-agentic-ai
```

`cx-cursor-marketplace` is this repo's Cursor marketplace name (`.cursor-plugin/marketplace.json`);
`cx-devassist` is this plugin's id within it (`.cursor-plugin/plugin.json`). Once installed, continue
with [First-time setup](#first-time-setup-cursor-cli) below.

### Local plugin install (manual / offline)

```text
~/.cursor/plugins/local/cx-devassist-cursor/
├── .cursor-plugin/plugin.json   ← required for Cursor to load the plugin
├── hooks/hooks.json             ← Cursor hook wiring (relative ./hooks/ paths)
├── mcp.json                     ← Checkmarx MCP
└── ...
```

Copy or symlink this plugin folder there — useful for a local checkout, a fork, or an environment
without access to the marketplace.

### First-time setup (Cursor CLI)

From a **Cursor CLI** terminal session (`agent` in your project directory), run **on demand**:

```text
/cx-install-wiring
```

This skill is **intended for Cursor CLI** (`agent` in a terminal) and is **on-demand** only. When
invoked, it will:

1. Ask **User** vs **Project** scope. For **Project**, ask whether to use **this repo** (show the
   resolved path) or **another path** (developer supplies it); validate the directory exists, then
   run `install-hooks.sh` (hooks + rules).
2. Automatically continue into `cx` CLI install and authentication (reads `cx-cli-setup` in the same session).

When setup completes, **exit and restart your CLI session** (`/exit`, then `agent` again, or restart the
terminal) so hooks, rules, and the MCP bridge load. Do **not** use **Developer: Reload Window** — that
is for the IDE.

For **hook-deny recovery** or **re-auth only** (hooks already wired), use `/cx-cli-setup` from CLI or IDE.

### IDE / manual hook install

**User-level hooks** (optional; IDE users or non-interactive install):

To run it by hand instead (e.g. non-interactively, or from CI):

```bash
# User scope
bash /plugins/cursor-devassist/scripts/install-hooks.sh
# or from the local plugin copy:
CX_PLUGIN_ROOT=~/.cursor/plugins/local/cx-devassist-cursor bash scripts/install-hooks.sh

# Project scope — set CX_PROJECT_PATH to the validated repo root (defaults to cwd if unset)
CX_CURSOR_HOOKS_TARGET=project CX_PROJECT_PATH=/path/to/repo bash scripts/install-hooks.sh
```

When the script finishes, **restart your Cursor CLI session** (exit `agent` and start again, or restart
the terminal) — not **Developer: Reload Window** (IDE only).

This **merges** this plugin's hooks into the target `hooks.json` and **syncs** its `cx-*.mdc` rules
into the matching `.cursor/rules/` directory (visible in Settings → Hooks and Rules) with absolute
paths to this plugin — any hooks/rules you already have for other tools are preserved untouched;
only this plugin's own prior entries are replaced. Replaced files are backed up to `*.bak` first
(`scripts/cx-hooks-merge.py` and `scripts/cx-rules-install.py`; need Python 3, already a hard
prerequisite below). Plugin-level hooks may still run without the hooks file, but they often do not
appear in the Hooks settings UI without it.

On first use the gate will detect that `cx` is missing and name the exact bootstrap command to run
(`bash scripts/cx-bootstrap.sh install`), then walk you through authenticating it.

Optional: `export CX_ASSISTANT=cursor` (this is already the default for this plugin) so logs land in
`~/.checkmarx/agent-logs/cursor/`.

---

## Configuration

All optional — sensible defaults apply, and every one of these **narrows or restores** gate
behavior; none is required for normal use.

### Runtime (read by the gate on every hook invocation)

| Variable | Purpose |
|---|---|
| `CX_BINARY` | Absolute path to `cx` when it isn't on `PATH` (validated: must be a real, recent, capable, authenticated cx). Takes priority over the canonical install store. |
| `CX_GATE_ALL_FILES=1` | Gate **every** file write, not just types the Checkmarx engines can scan — restores pre-scoping behavior. |
| `CX_GATE_ALL_COMMANDS=1` | Disable the read-only-command and `cx version`/`cx utils env` diagnostic carve-outs, so every Shell command is evaluated by the gate's own logic (shell commands themselves are still never blocked by this gate — see [Fail-closed by design](#fail-closed-by-design)). |
| `CX_ALLOW_UNLICENSED=1` | Allow writes to proceed (with a logged warning) when cx is authenticated but has no AI-scanning license, instead of denying — accepts that those writes are **unscanned**. |
| `CX_LOG_DIR` | Override the log directory (default `~/.checkmarx/agent-logs/cursor/`). |
| `CX_LOG_DISABLE=1` | Turn structured logging off entirely. |
| `CX_ASSISTANT` | Label the assistant in logs (default `cursor`). |
| `CX_REQUIRE_CHECKSUM=1` | Make `cx-bootstrap.sh` refuse to install an asset it can't checksum-verify. |

### Install-time (read only by `scripts/install-hooks.sh`)

| Variable | Purpose |
|---|---|
| `CX_CURSOR_HOOKS_TARGET=project` | Install hooks/rules under a project's `.cursor/` instead of the user-level `~/.cursor/` (default `user`). |
| `CX_PROJECT_PATH` | The project root to install into when `CX_CURSOR_HOOKS_TARGET=project`; defaults to the current directory. |
| `CX_PLUGIN_ROOT` | Override plugin-root detection (rarely needed — the script infers it from its own location). |

---

## Troubleshooting

Start with the deny message itself — it always names the exact cause and the exact command to run
next (a `/cx-cli-setup` step, or `bash scripts/cx-bootstrap.sh install|upgrade`). Common cases:

| Symptom | Likely cause | Fix |
|---|---|---|
| Deny says cx is missing / below version / incapable / unauthenticated | A real, named gate condition | Follow the command in the deny message, or run `/cx-cli-setup` |
| Deny says the gate/scanner "did not return a result" or hit an "internal error" | A **hook-chain failure** (crash/timeout before or during the scan) — see [Fail-closed by design](#fail-closed-by-design) | Retry the same operation once; if it recurs, check `~/.checkmarx/agent-logs/cursor/cx-devassist.jsonl` for `reason_code":"gate_crash"` / `"error_during_block"` and re-run the bundled bootstrap |
| A batch of several Write/Edit calls at once denies with a timeout | Probe/scan contention across the batch (mitigated, not eliminated, by the gate's cache-miss lock) | Retry the failed file(s); a warm cache (post-first-success) makes this rare |
| Hooks/rules don't show up in Settings → Hooks and Rules | Not re-installed after a plugin update, or installed to the wrong scope | Re-run `/cx-install-wiring` (CLI) or `scripts/install-hooks.sh`, then restart the session |
| `cx` on PATH but the gate still denies "not installed" | The gate resolves by absolute path (`CX_BINARY` → canonical store → PATH), not PATH alone | See `skills/cx-cli-setup/references/troubleshooting.md` → *"A gated action is still denied after `cx version` works"* |
| Locked-down machine, `cx` can't be placed on any writable PATH | — | Set `CX_BINARY` — see `references/troubleshooting.md` → *"CX_BINARY — point the gate at an explicit cx"* |

For install errors, auth failures, self-hosted base URIs, and the `CX_BINARY` override in full, see
[`skills/cx-cli-setup/references/troubleshooting.md`](skills/cx-cli-setup/references/troubleshooting.md).

---

## Uninstalling

1. **Remove the plugin folder** — delete (or unlink) `~/.cursor/plugins/local/cx-devassist-cursor/`
   (or wherever it was copied/symlinked).
2. **Remove the merged hooks/rules**, if `install-hooks.sh` was run:
   - Hooks: edit `~/.cursor/hooks.json` (or `<project>/.cursor/hooks.json`) and delete the entries
     whose `command` points at this plugin's `hooks/` scripts. A `hooks.json.bak` from the last merge
     sits alongside it if you'd rather restore the pre-install file directly.
   - Rules: delete the `cx-*.mdc` files from `~/.cursor/rules/` (or `<project>/.cursor/rules/`); any
     `*.bak` backups from the install are alongside them.
3. **Restart your Cursor CLI session** (or reload the IDE window) so the removed hooks/rules/MCP
   server stop loading.
4. **Optional cleanup** — the `cx` CLI itself, its credentials (`~/.checkmarx/checkmarxcli.yaml`), and
   this plugin's logs/caches (`~/.checkmarx/agent-logs/cursor/`) are left in place, since `cx` is a
   general-purpose CLI other tools may still use. Remove them by hand if you want a full clean state.

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
