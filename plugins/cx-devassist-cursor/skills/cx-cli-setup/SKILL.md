---
name: cx-cli-setup
description: "Installs, configures, and authenticates the Checkmarx cx CLI (API key or browser OAuth sign-in). Use when the cx CLI is missing, outdated, or not authenticated. Invoke as: /cx-cli-setup"
---

# CX CLI Setup

Guides the developer through installing, upgrading, and authenticating the Checkmarx One `cx` CLI so
the security plugin can operate. The OS is known from the Cursor session — use the matching
path; no detection command is needed. Detailed steps live under `references/` (see Additional
Resources); this router is the spine.

## When to Use

- The `cx` CLI is not installed or not found in PATH
- A hook blocked an operation because `cx` is missing or below the minimum version
- The developer explicitly runs `/cx-cli-setup` to reconfigure or reauthenticate
- The plugin detected expired credentials and needs a re-auth step

## Phase 0 — Assess Current State

Run both checks to decide where to enter. Run them as **two separate commands, one at a time** —
never chained with `||`/`&&`/`;`: the security gate only lets a bare, unchained command through
this early (before cx is installed/authenticated), so a chained probe is itself blocked and never
reaches cx at all. The OS is already known from the Cursor session, so run only the matching
Check 1 — do not try both:

```bash
# Check 1 — is the CLI present? (bare command, no chaining/redirect)
which cx          # bash / sh (macOS, Linux, Git Bash)
where cx          # cmd.exe
Get-Command cx    # PowerShell
```

```bash
# Check 2 — only if present (identical in every shell)
cx auth validate
```

> **Shell syntax matters from here on.** Cursor's Shell tool runs the workspace's default shell —
> **PowerShell** on Windows, bash/zsh on macOS/Linux, `cmd.exe` where configured — and they disagree
> about invoking a quoted path, discarding stdout, and referencing environment variables. Every
> per-shell form used below is spelled out once in **`references/shells.md`**; read it before writing
> a command that names an absolute path or a redirect.

| CLI present | Auth result | Action |
|---|---|---|
| No | — | Offer the custom-path option (`references/troubleshooting.md`), then go to Phase 1 |
| Yes | Success | Tell the developer all looks good; ask if they want to reconfigure/reauth anyway. If no, exit. |
| Yes | Credential failure (invalid/revoked/expired) | CLI is installed but auth failed — skip to Phase 2. |
| Yes | Network failure (DNS/refused/timeout) | CLI is installed but the server is unreachable — do not go to Phase 2; have them check network/proxy, then re-run `cx auth validate`. |

Distinguish the two failures from the `cx auth validate` error text: credential failures contain
"invalid"/"unauthorized"/"401"/"forbidden"; network failures contain "no such host"/"connection
refused"/"timeout"/"dial tcp".

## Phase 1 — Install the CLI

The plugin ships a self-contained installer, `scripts/cx-bootstrap.sh`, that downloads the right
release asset for this OS/arch, verifies its checksum (fail-closed by default), and installs `cx` to
the **canonical store** (`%LOCALAPPDATA%\Checkmarx\cx\cx.exe` on Windows, `~/.checkmarx/bin/cx` on
Unix). It needs only `bash` (Git Bash on Windows) — no Python.

> **In-session activation:** the gate resolves cx from the canonical store by **absolute path**, so it
> clears on your **next tool call with no restart** — even though a running Cursor captured its
> PATH at startup and cannot see the newly-persisted PATH entry. You do **not** need to place cx into
> an on-PATH folder or "activate" it, and you must **never hand-place a second copy**. (The
> remediation MCP resolves cx by absolute path too, via `cx_run.sh`; it activates after one **Developer:
> Reload Window**.)

When a hook blocked an operation, its deny message already contains the exact command by resolved
absolute path — e.g. `bash "/…/plugins/cx-devassist-cursor/scripts/cx-bootstrap.sh" install`. Use it
verbatim. **Do not** substitute `${CURSOR_PLUGIN_ROOT}` — it is injected only into hook execution
and is empty in the Bash shell, so a path built from it will not resolve.

Ask the developer once: **"Install/upgrade Checkmarx CLI now? (Y/n)"** On **Y**, run the bootstrap
command (`install`). On **n**, or if `bash`/Git Bash is unavailable, use the per-OS steps in
`references/manual-install.md`. Then go to Phase 1a.

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

  To confirm the binary directly without relying on PATH, invoke it by its canonical absolute path —
  using **your shell's** form (`references/shells.md`):

  ```bash
  "$HOME/.checkmarx/bin/cx" version                      # bash / sh (macOS, Linux)
  "$LOCALAPPDATA/Checkmarx/cx/cx.exe" version            # bash / sh (Git Bash on Windows)
  & "$env:LOCALAPPDATA\Checkmarx\cx\cx.exe" version      # PowerShell — the & call operator is REQUIRED
  "%LOCALAPPDATA%\Checkmarx\cx\cx.exe" version           # cmd.exe
  ```

**Version gate:** the minimum is `scripts/cx-min-version` — the oldest ast-cli release this plugin
supports. A build **below** it is a hard block on every gated action — including
`cx auth login` — so upgrade via `references/upgrade.md`. A `cx version` reporting the literal `dev`
sentinel bypasses the numeric check (auth still applies); don't treat `dev` as a failure.

## Phase 2 — Authenticate the CLI

Two methods: **API key** (simplest — the key encodes server URL, auth URL, and tenant) and **browser
sign-in (OAuth)** (logs in via browser/MFA; saves a refresh token as `cx_apikey`).

> **Admin pre-fill (OAuth only):** if an administrator filled the plugin's
> `config/cx-onboarding.properties` with a URL + tenant, those values are embedded directly into the
> gate's `cx auth login` recovery command, and the OAuth flow **skips the URL/tenant question**. See
> `references/oauth.md`. An API key needs neither, so this pre-fill does not affect Path A.

**Capability check — does this build support browser sign-in?** Exit codes vary, so check the
subcommand list:

```bash
cx auth --help
```

- `login` listed (with `logout`/`register`/`validate`) → both paths available; ask the choice below.
- `login` NOT listed → this build predates browser sign-in; only **Path A (API key)** is available.

When both are available, ask **Question 1 — auth method** as a plain chat message (offer the two
choices below and wait for the developer's pick), **API key first**:

- **API key** — *"Simplest. The key already carries your server URL and tenant."*
- **Browser sign-in (OAuth)** — *"Log in through your browser with MFA. I'll need your Checkmarx One URL and tenant."*

Route — **ask this only once**: **API key → Path A** (below); **Browser sign-in → Path B**
(`references/oauth.md`).

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

1. **The gate clears** — the next gated tool call proceeds (no longer denied) and the `stop` hook no
   longer errors with `cx: command not found`. After a bootstrap install this happens on the very next
   call with **no restart**, because the gate resolves the canonical store by absolute path.
2. **The MCP is loaded** — run **Developer: Reload Window** (Command Palette), then check your MCP
   settings show `Checkmarx` connected (`references/mcp.md`).

Only once the gate clears: "Setup complete. The `cx` CLI is installed, configured, and
authenticated, and the security hooks are enforcing." If a gated action is still denied after `cx
version` works in the shell, see `references/troubleshooting.md`.

## Error Handling (Any Phase)

- Surface the specific error — never a generic "something went wrong."
- Identify which phase failed; let the developer correct and retry **that step only** — no restart.
- If they cancel: "Setup is incomplete; the plugin stays blocked. Run `/cx-cli-setup` to resume."

## Re-Authentication Only (Expired Credentials)

If invoked only because credentials expired (CLI already installed and configured), skip Phases 0–1
and start at Phase 2: "Your Checkmarx One credentials have expired. Let's re-authenticate — no
reconfiguration needed." Re-show the Question 1 auth-method choice, pre-selecting the method the
developer originally used, then route: **API key →** generate a new key and re-run the Phase 2 Path A
`cx configure set` (keys expire after 30–365 days per tenant policy); **Browser sign-in →**
`references/oauth.md` (re-auth section).

## Additional Resources

- `references/shells.md` — **PowerShell / cmd.exe / bash / sh syntax for every command here** (call
  operator, null device, env vars, JSON arguments, paths with spaces). Read this first on Windows.
- `references/manual-install.md` — per-OS manual install (no bootstrap / no bash); `CX_REQUIRE_CHECKSUM`.
- `references/windows-path-activation.md` — Windows in-session placement + User-scope PATH persistence.
- `references/oauth.md` — Path B browser sign-in, token safety, re-auth.
- `references/upgrade.md` — upgrading a below-minimum CLI.
- `references/mcp.md` — the remediation MCP and reloading it.
- `references/troubleshooting.md` — cx-not-on-PATH, self-hosted URIs, gate-still-denied, `CX_BINARY`.

## Quick Reference

Shown as bare `cx …` (valid in every shell once cx is on PATH). Before cx is on PATH, prefix the
canonical absolute path using **your shell's** form — see `references/shells.md`.

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
