---
name: cx-cli-setup
description: "Installs, configures, and authenticates the Checkmarx cx CLI (API key or browser OAuth sign-in). Use when the cx CLI is missing, outdated, or not authenticated. Invoke as: $cx-cli-setup"
---

# CX CLI Setup

Guides the developer through installing, upgrading, and authenticating the Checkmarx One `cx` CLI so
the security plugin can operate. The OS is known from the Codex CLI session — use the matching
path; no detection command is needed. Detailed steps live under `references/` (see Additional
Resources); this router is the spine.

## When to Use

- The `cx` CLI is not installed or not found in PATH
- A hook blocked an operation because `cx` is missing or below the minimum version
- The developer explicitly runs `$cx-cli-setup` to reconfigure or reauthenticate
- The plugin detected expired credentials and needs a re-auth step

## Phase 0 — Assess Current State

**If a gate deny message sent you here, it already contains the answer — read it before running
anything.** Every deny states whether cx resolved (with its absolute path), the installed vs required
version, and whether auth succeeded. Do not spend commands rediscovering what it just told you.

Otherwise run the two checks below — **one bare command each**. The gate admits only bare commands,
so a chained probe like `which cx || where cx 2>nul` is REJECTED (the `||` is chaining and `nul` is an
ordinary file, not a null device, under Git-Bash).

```bash
which cx            # Bash tool — is the CLI on PATH?
cx auth validate    # only if present
```

```powershell
Get-Command cx      # PowerShell tool — is the CLI on PATH? (`where.exe cx` also works)
cx auth validate    # only if present
```

A bare `cx` can be missing from PATH even when cx **is** installed (a first-install session captured
the old PATH), so check the canonical store directly before concluding it is absent —
`ls -l "$HOME/.checkmarx/bin/cx"` (Unix) or `Test-Path "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe"`
(Windows). All of these pass the gate's read-only carve-out in either shell.

| CLI present | Auth result | Action |
|---|---|---|
| No | — | Offer the custom-path option (`references/troubleshooting.md`), then go to Phase 1 |
| Yes | Success | Tell the developer all looks good; ask if they want to reconfigure/reauth anyway. If no, exit. |
| Yes | Credential failure (invalid/revoked/expired) | CLI is installed but auth failed — skip to Phase 2. |
| Yes | Network failure (DNS/refused/timeout) | CLI is installed but the server is unreachable — do not go to Phase 2; have them check network/proxy, then re-run `cx auth validate`. |

Distinguish the two failures from the `cx auth validate` error text: credential failures contain
"invalid"/"unauthorized"/"401"/"forbidden"; network failures contain "no such host"/"connection
refused"/"timeout"/"dial tcp".

> **Run these checks yourself — the gate admits them even while it is blocking everything else**,
> through **either the Bash or the PowerShell tool**:
> - `cx version` — the *diagnostic* carve-out. Exact shape, no extra arguments. Works in **every**
>   broken state, including a below-minimum or capability-incomplete build.
> - `cx auth validate` / `cx auth --help` / `cx auth login` / `cx configure …` — the *auth-recovery*
>   carve-out. Arguments allowed. Blocked only on a below-minimum build, where the remedy is an
>   upgrade rather than a login, so there is nothing to check until cx is upgraded.
>
> Read-only inspection (`ls`, `cat`, `grep`; `Get-ChildItem`, `Get-Content`, `Select-String`) is also
> allowed in either shell. Do not hand any of these to the developer to run manually because an
> earlier unrelated command was denied.

## Phase 1 — Install the CLI

The plugin ships a self-contained installer, `scripts/cx-bootstrap.sh`, that downloads the right
release asset for this OS/arch, verifies its checksum (fail-closed by default), and installs `cx` to
the **canonical store** (`%LOCALAPPDATA%\Checkmarx\cx\cx.exe` on Windows, `~/.checkmarx/bin/cx` on
Unix). It needs only `bash` (Git Bash on Windows) — no Python.

> **In-session activation:** the gate resolves cx from the canonical store by **absolute path**, so it
> clears on your **next tool call with no restart** — even though a running Codex CLI session captured
> its PATH at startup and cannot see the newly-persisted PATH entry. You do **not** need to place cx
> into an on-PATH folder or "activate" it, and you must **never hand-place a second copy**. (The
> remediation MCP resolves cx by absolute path too, via `cx_run.sh`; it activates after restarting the
> Codex CLI session — Codex CLI has no confirmed hot-reload equivalent to Claude Code's `/restart`.)

When a hook blocked an operation, its deny message already contains the exact command by resolved
absolute path — e.g. `sh "/…/plugins/codex-devassist/scripts/cx-bootstrap.sh" install`. Use it
verbatim. **Do not** substitute `${PLUGIN_ROOT}` — it is injected only into hook execution
and is empty in the Bash shell, so a path built from it will not resolve.

**Run the bootstrap command yourself — do not just print it and wait.** When a hook's deny message
contains the resolved bootstrap command, immediately execute it (via the Bash tool) as your very next
action; do not stop after displaying it and do not ask the developer to copy/paste or run it manually.
Tell the developer you are installing/upgrading now (a one-line heads-up, not a yes/no prompt): **"cx
CLI is missing/outdated — installing it now via the bundled bootstrap."** Only fall back to asking the
developer, or to the per-OS steps in `references/manual-install.md`, if `bash`/Git Bash is unavailable
in this environment (the bootstrap genuinely cannot run) or the bootstrap command itself fails. Then go
to Phase 1a.

## Phase 1a — Verify Installation

```bash
cx version
```

- **Returns a version** → "The `cx` CLI is installed. Version: `<version>`." Proceed to Phase 2.
- **Fails with `command not found` / 127** → on a **first-install session this is EXPECTED and does
  NOT mean the install failed.** The bootstrap writes cx to the **canonical store**
  (`%LOCALAPPDATA%\Checkmarx\cx\cx.exe` / `~/.checkmarx/bin/cx`), which the **gate** resolves by
  absolute path — but that store is **not on the agent shell's frozen PATH**, so a bare `cx` 127s here.
  Do **NOT** loop re-running the bootstrap because of it. The real installed/capable signal is the
  **gate's deny reason on your next gated action**:
  - **"not authenticated"** → cx is installed **and** capable — proceed to Phase 2 (auth).
  - **"not installed"** → the bootstrap genuinely did not land cx; re-run `install` once.
  - **"incapable" / below minimum version** → not a PATH problem, and re-installing won't help (see
    `references/troubleshooting.md`); do **not** hand-place a cx binary.

  To confirm the binary directly without relying on PATH, invoke it by its canonical absolute path:
  `"$HOME/.checkmarx/bin/cx" version` (Unix) or `"$LOCALAPPDATA/Checkmarx/cx/cx.exe" version` (Windows;
  PowerShell tool: `& "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" version` — a quoted path needs the `&`
  call operator there). These exact shapes pass the gate's diagnostic carve-out even while everything
  else is blocked — run them yourself.

**Version gate:** the minimum is `scripts/cx-min-version` — the oldest ast-cli release this plugin
supports. A build **below** it is a hard block on every gated action — including
`cx auth login` — so upgrade via `references/upgrade.md`. The deny message names **both** the
installed and the required version (e.g. *"cx v2.4.0 is older than the required v2.5.0"*): report
both numbers to the developer and offer the upgrade. Do **not** check authentication first — on an
outdated build the remedy is the upgrade regardless of auth state. A `cx version` reporting the literal `dev`
sentinel bypasses the numeric check (auth still applies); don't treat `dev` as a failure.

## Phase 2 — Authenticate the CLI

Two methods: **API key** (simplest — the key encodes server URL, auth URL, and tenant) and **browser
sign-in (OAuth)** (logs in via browser/MFA; saves a refresh token as `cx_apikey`).

> **Admin pre-fill (OAuth only):** if an administrator filled the plugin's
> `config/cx-onboarding.properties` with a URL + tenant, those values are embedded directly into the
> gate's `cx auth login` recovery command, and the OAuth flow **skips the URL/tenant question**. See
> `references/oauth.md`. An API key needs neither, so this pre-fill does not affect Path A.
>
> **Remembered environments (OAuth only):** without an admin pre-fill, the gate's deny message may
> instead list URL + tenant pairs this developer **previously logged in** with (remembered per
> machine from earlier successful `cx auth login` runs). The OAuth flow then asks Question 2 as an
> `AskUserQuestion` over those pairs instead of free text — see `references/oauth.md` (history
> form). The developer always confirms the choice; nothing is auto-used.

**Capability check — does this build support browser sign-in?** Exit codes vary, so check the
subcommand list:

```bash
cx auth --help
```

(This passes the gate's auth-recovery carve-out on both shell tools — run it yourself. The one
exception: a **below-minimum** build blocks even `cx auth …`; only `cx version` runs there —
upgrade first.)

- `login` listed (with `logout`/`register`/`validate`) → both paths available; ask the choice below.
- `login` NOT listed → this build predates browser sign-in; only **Path A (API key)** is available.

When both are available, ask **Question 1 — auth method** with the **`AskUserQuestion` tool** (not a
chat message), `multiSelect: false`, header `Auth method`, **API key first**:

- **API key** — *"Simplest. The key already carries your server URL and tenant."*
- **Browser sign-in (OAuth)** — *"Log in through your browser with MFA. I'll need your Checkmarx One URL and tenant."*

(Ignore any auto-appended "Other"; don't add a third option.) Route — **ask this only once**: **API
key → Path A** (below); **Browser sign-in → Path B** (`references/oauth.md`).

### Path A — API key

Give the full instructions in one message; do not ask the developer to paste the key into chat:

> "1. In the Checkmarx One portal: **Settings → Identity and Access Management → API Keys → Create
> Key**. 2. Copy the key (it is shown once). 3. Run, replacing `<your-api-key>`:
> ```
> cx configure set --prop-name cx_apikey --prop-value <your-api-key>
> ```
> Let me know once you've run it. Docs: https://docs.checkmarx.com/en/34965-188712-creating-api-keys.html"

Wait for confirmation. The CLI extracts the server URL, auth URL, and tenant from the key — no
further questions. The credential is stored in plaintext in `~/.checkmarx/checkmarxcli.yaml`
(Windows: `%USERPROFILE%\.checkmarx\checkmarxcli.yaml`) — protect it like an SSH key (`chmod 600`).

## Phase 3 — Verify Connectivity

```bash
cx auth validate
```

- **Success** → "Authentication verified. The plugin is ready to scan."
- **Credential failure** → offer to re-enter (return to Phase 2). Do not proceed.
- **Server unreachable** → likely self-hosted base URIs or a network/proxy issue: `references/troubleshooting.md`.
- **Permission error** (authenticated, no project access) → advise contacting the Checkmarx admin.

## Phase 4 — Complete

**Acceptance is that the _hook path_ is live — not merely that `cx version` prints in the shell.**
The hooks resolve `cx` in a separate process with a different PATH snapshot, so confirm both:

1. **The gate clears** — the next gated tool call proceeds (no longer denied) and the `Stop` hook no
   longer errors with `cx: command not found`. After a bootstrap install this happens on the very next
   call with **no restart**, because the gate resolves the canonical store by absolute path.
2. **The MCP is loaded** — restart the Codex CLI session so it re-reads `config.toml`, then confirm the
   `Checkmarx` MCP server is connected (`references/mcp.md`).

Only once the gate clears: "Setup complete. The `cx` CLI is installed, configured, and
authenticated, and the security hooks are enforcing." If a gated action is still denied after `cx
version` works in the shell, see `references/troubleshooting.md`.

## Error Handling (Any Phase)

- Surface the specific error — never a generic "something went wrong."
- Identify which phase failed; let the developer correct and retry **that step only** — no restart.
- If they cancel: "Setup is incomplete; the plugin stays blocked. Run `$cx-cli-setup` to resume."

## Re-Authentication Only (Expired Credentials)

If invoked only because credentials expired (CLI already installed and configured), skip Phases 0–1
and start at Phase 2: "Your Checkmarx One credentials have expired. Let's re-authenticate — no
reconfiguration needed." Re-show the Question 1 auth-method choice, pre-selecting the method the
developer originally used, then route: **API key →** generate a new key and re-run the Phase 2 Path A
`cx configure set` (keys expire after 30–365 days per tenant policy); **Browser sign-in →**
`references/oauth.md` (re-auth section) — the gate's deny message usually lists the previously used
environment(s), offered there as choices via the history form of Question 2.

## Additional Resources

- `references/manual-install.md` — per-OS manual install (no bootstrap / no bash); `CX_REQUIRE_CHECKSUM`.
- `references/windows-path-activation.md` — Windows in-session placement + User-scope PATH persistence.
- `references/oauth.md` — Path B browser sign-in, token safety, re-auth.
- `references/upgrade.md` — upgrading a below-minimum CLI.
- `references/mcp.md` — the remediation MCP and the manual `config.toml` registration step.
- `references/troubleshooting.md` — cx-not-on-PATH, self-hosted URIs, gate-still-denied, `CX_BINARY`.

## Quick Reference

| Command | Purpose |
|---|---|
| `cx version` | Verify CLI is installed |
| `cx configure set --prop-name cx_apikey --prop-value <key>` | Path A: set API key (extracts server/tenant automatically) |
| `cx auth login --base-auth-uri <URL> --tenant <tenant>` | Path B: browser OAuth — both flags every login; needs a build that supports it |
| `cx auth logout` | Revoke the current refresh token and clear stored credentials |
| `cx auth validate` | Verify authentication |
| `cx utils env` | Show current configuration |

Releases: https://github.com/Checkmarx/ast-cli/releases ·
Quick-start: https://docs.checkmarx.com/en/34965-68621-checkmarx-one-cli-quick-start-guide.html ·
Environment/region URLs + tenant lookup: https://docs.checkmarx.com/en/34965-68530-logging-in-to-checkmarx-one.html
