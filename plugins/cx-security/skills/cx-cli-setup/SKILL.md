---
name: cx-cli-setup
description: "Installs, configures, and authenticates the Checkmarx cx CLI (API key or browser OAuth sign-in). Use when the cx CLI is missing, outdated, or not authenticated. Invoke as: cx-security:cx-cli-setup"
---

# CX CLI Setup

Guides the developer through installing, upgrading, and authenticating the Checkmarx One `cx` CLI so
the security plugin can operate. The OS is known from the Claude Code session — use the matching
path; no detection command is needed. Detailed steps live under `references/` (see Additional
Resources); this router is the spine.

## When to Use

- The `cx` CLI is not installed or not found in PATH
- A hook blocked an operation because `cx` is missing or below the minimum version
- The developer explicitly runs `/cx-cli-setup` to reconfigure or reauthenticate
- The plugin detected expired credentials and needs a re-auth step

## Phase 0 — Assess Current State

Run both checks to decide where to enter:

```bash
which cx 2>/dev/null || where cx 2>nul   # Check 1 — is the CLI present?
cx auth validate                          # Check 2 — only if present
```

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
release asset for this OS/arch, verifies its checksum, and **places `cx` into a folder already on
this session's PATH**, so the gate clears on the next tool call with no restart. It needs only
`bash` (Git Bash on Windows) — no Python.

> **In-session activation (the one rule):** a running Claude Code captured its PATH at startup, so a
> *newly added* PATH directory is invisible to it. Place `cx` into a directory **already on PATH**
> (or use the `CX_BINARY` override); never rely on adding a new PATH entry for this session.
> Platform detail: `references/windows-path-activation.md`.

When a hook blocked an operation, its deny message already contains the exact command by resolved
absolute path — e.g. `bash "/…/plugins/cx-security/scripts/cx-bootstrap.sh" install`. Use it
verbatim. **Do not** substitute `${CLAUDE_PLUGIN_ROOT}` — it is injected only into hook execution
and is empty in the Bash shell, so a path built from it will not resolve.

Ask the developer once: **"Install/upgrade Checkmarx CLI now? (Y/n)"** On **Y**, run the bootstrap
command (`install`). On **n**, or if `bash`/Git Bash is unavailable, use the per-OS steps in
`references/manual-install.md`. Then go to Phase 1a.

## Phase 1a — Verify Installation

```bash
cx version
```

- **Returns a version** → "The `cx` CLI is installed. Version: `<version>`." Proceed to Phase 2.
- **Fails** → the install isn't on the hook's PATH. Re-place `cx` into an already-on-PATH folder
  (re-run the bootstrap, or `references/windows-path-activation.md`); don't tell the developer to
  "open a new terminal." Do not proceed until `cx version` passes.

**Version gate:** the minimum is `scripts/cx-min-version` (the first ast-cli release with `cx mcp
bridge` / `cx auth login`). A build **below** it is a hard block on every gated action — including
`cx auth login` — so upgrade via `references/upgrade.md`. A `cx version` reporting the literal `dev`
sentinel bypasses the numeric check (auth still applies); don't treat `dev` as a failure.

## Phase 2 — Authenticate the CLI

Two methods: **API key** (simplest — the key encodes server URL, auth URL, and tenant) and **browser
sign-in (OAuth)** (logs in via browser/MFA; saves a refresh token as `cx_apikey`).

**Capability check — does this build support browser sign-in?** Exit codes vary, so check the
subcommand list:

```bash
cx auth --help
```

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
   longer errors with `cx: command not found`. This is the real signal: if a *new* PATH folder was
   added instead of placing `cx` into an already-on-PATH folder, this is where it would still fail.
2. **The MCP is loaded** — run `/reload-plugins`, then `/mcp` shows `Checkmarx` Connected
   (`references/mcp.md`).

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

- `references/manual-install.md` — per-OS manual install (no bootstrap / no bash); `CX_REQUIRE_CHECKSUM`.
- `references/windows-path-activation.md` — Windows in-session placement + User-scope PATH persistence.
- `references/oauth.md` — Path B browser sign-in, token safety, re-auth.
- `references/upgrade.md` — upgrading a below-minimum CLI.
- `references/mcp.md` — the remediation MCP and `/reload-plugins`.
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
Quick-start: https://docs.checkmarx.com/en/34965-68621-checkmarx-one-cli-quick-start-guide.html
