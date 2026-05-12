---
name: cx-cli-setup
description: "Installs the Checkmarx cx CLI if it is not found on the system. Use when the cx CLI is missing. Invoke as: cx-security:cx-cli-setup"
---

# CX CLI Setup

Guides the developer through installing, configuring, and authenticating the Checkmarx One `cx` CLI so the security plugin can operate.

## When to Use

- The `cx` CLI is not installed or not found in PATH
- A hook blocked an operation because `cx` is missing
- The developer explicitly runs `/cx-cli-setup` to reconfigure or reauthenticate
- The plugin detected expired credentials and needs a re-auth step

---

## Prerequisites Check

The OS is already known from the Claude Code session environment — use it directly. No shell command is needed to detect it.

- macOS → use the macOS install path
- Linux → use the Linux install path
- Windows → use the Windows install path

---

## Phase 0 — Assess Current State

Run both checks to determine where to enter the flow:

**Check 1 — CLI presence:**

```bash
which cx 2>/dev/null || where cx 2>nul
```

**Check 2 — Authentication state (only if CLI is found):**

```bash
cx auth validate
```

Route based on the results:

| CLI present | Auth valid | Action |
|---|---|---|
| No | — | Offer custom path (see below), then proceed to Phase 1 |
| Yes | Yes | Tell the developer everything looks good. Ask if they want to reconfigure or reauthenticate anyway. If no, exit. |
| Yes | No / fails | Tell the developer the CLI is installed but authentication has failed. Skip to Phase 2. |

**Custom path offer** (when CLI is not found):

> "If you already have `cx` installed at a non-standard path, provide the full path now and I'll use it instead of installing a new copy. Otherwise, press Enter to continue with installation."

If a path is provided, run `"<provided-path>" version`:
- If it returns a version: the CLI is installed but not on PATH. Guide the developer to add its directory to their PATH permanently:
  - **macOS/Linux**: add `export PATH="<directory>:$PATH"` to `~/.zshrc` or `~/.bashrc`, then run `source ~/.zshrc` (or open a new terminal).
  - **Windows**: add the directory via System Properties → Environment Variables → Path.
  - Once done, verify `cx version` works without the full path, then re-run `cx auth validate` and route as the table above.
- If it fails, tell the developer the binary was not usable at that path and proceed with Phase 1.

---

## Phase 1 — Install the CLI

Releases are published at: https://github.com/Checkmarx/ast-cli/releases

Before running any command, explain to the developer what will be installed and how, then ask:
> "Shall I run this for you?"

Only proceed with execution after the developer confirms. If they decline, show them the command to run themselves and wait for them to confirm completion before moving to Phase 1a.

### macOS

**Primary method — Homebrew.** Tell the developer:
> "I'll install the Checkmarx One CLI using Homebrew (`brew install checkmarx/ast-cli/ast-cli`). Shall I run this for you?"

On confirmation:

```bash
brew install checkmarx/ast-cli/ast-cli
```

**If Homebrew is not available or the brew install fails**, tell the developer:
> "Homebrew isn't available. I'll fall back to downloading the binary directly from GitHub and placing it in `/usr/local/bin`. Shall I run this for you?"

On confirmation:

```bash
curl -fsSL https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_darwin_x64.tar.gz -o /tmp/cx-cli.tar.gz && \
sudo tar -xzf /tmp/cx-cli.tar.gz -C /usr/local/bin cx && \
rm /tmp/cx-cli.tar.gz
```

If `curl` is also unavailable, direct the developer to download manually:
https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_darwin_x64.tar.gz

### Linux

First detect the architecture:

```bash
uname -m
```

- `x86_64` → use `ast-cli_linux_x64.tar.gz`
- `aarch64` / `arm64` → use `ast-cli_linux_arm64.tar.gz`
- `armv6*` → use `ast-cli_linux_armv6.tar.gz`

Tell the developer:
> "I'll download the Checkmarx One CLI binary from GitHub and place it in `/usr/local/bin`. Shall I run this for you?"

On confirmation (x64 example — substitute the correct filename for the detected arch):

```bash
curl -fsSL https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_linux_x64.tar.gz -o /tmp/cx-cli.tar.gz && \
sudo tar -xzf /tmp/cx-cli.tar.gz -C /usr/local/bin cx && \
rm /tmp/cx-cli.tar.gz
```

If `curl` is unavailable, offer `wget` instead and ask the same confirmation question before running it.

If neither is available, direct the developer to download manually from the releases page.

### Windows

Tell the developer:
> "I'll download the Checkmarx One CLI from GitHub and extract it to `%LOCALAPPDATA%\Checkmarx\cx`. Shall I run this for you?"

On confirmation:

```powershell
$dest = "$env:LOCALAPPDATA\Checkmarx\cx"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Invoke-WebRequest -Uri "https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_windows_x64.zip" -OutFile "$env:TEMP\cx-cli.zip"
Expand-Archive "$env:TEMP\cx-cli.zip" -DestinationPath $dest -Force
$env:PATH += ";$dest"
```

Tell the developer they may need to add `$dest` to their permanent PATH via System Properties → Environment Variables.

---

## Phase 1a — Verify Installation

```bash
cx version
```

- **Returns a version**: confirm — "The `cx` CLI is installed. Version: `<version>`." Proceed to Phase 2.
- **Fails**: "The `cx` binary was not found after installation. The install directory may not be on your PATH. Open a new terminal or add the install directory to PATH, then confirm when ready." Retry `cx version` after confirmation. Do not proceed to Phase 2 until this passes.

**Version compatibility**: if the version is below `2.0.0`, inform the developer and guide them to upgrade using the same install method before continuing.

---

## Phase 2 — Configure the CLI

Tell the developer:

> "To configure the CLI I'll need your Checkmarx One API key. When using API key authentication, the CLI automatically extracts the server URL, auth URL, and tenant from the key — so the API key is all you need."

Direct them to generate one if they don't have it, and give them the full instructions in one message:

> "To configure the CLI:
>
> 1. Log in to the Checkmarx One web portal and go to **Settings → Identity and Access Management → API Keys → Create Key**.
> 2. Copy the key immediately — it is only shown once.
> 3. Run the following command in your terminal, replacing `<your-api-key>` with your actual key:
>
> ```
> cx configure set --prop-name cx_apikey --prop-value <your-api-key>
> ```
>
> Let me know once you've run it.
>
> For more details: https://docs.checkmarx.com/en/34965-188712-creating-api-keys.html"

Do NOT ask the developer to paste their API key into the chat. Wait for them to confirm they have run the command.

---

## Phase 3 — Verify Connectivity

```bash
cx auth validate
```

Interpret the result:

- **Exit code 0 / "Successfully authenticated"**: confirm — "Authentication verified. The plugin is ready to scan."
- **Auth/credential failure**: "Authentication check failed — your API key may be invalid. Would you like to re-enter it?" If yes, return to Phase 2. Do not proceed.
- **Server unreachable** (connection refused, DNS error, timeout): "Could not reach the Checkmarx One server. This may be a network issue. Setup is complete, but connectivity could not be verified — scanning will be unavailable until the server is reachable."
- **Permission error** (authenticated but no project access): "Authentication succeeded but you don't have access to any Checkmarx One projects. Please contact your Checkmarx administrator."

---

## Phase 4 — Complete

On successful verification:

> "Setup complete. The Checkmarx One CLI is installed, configured, and authenticated. Security scanning is now active."

The hook that triggered this skill will re-run automatically and the original agent action will proceed.

---

## Error Handling (Any Phase)

- Surface the specific error — never a generic "something went wrong."
- Identify which phase failed.
- Let the developer correct and retry **that step only** — no restarting the entire flow.
- If the developer cancels mid-flow: "Setup is incomplete. The plugin will remain blocked. Run `/cx-cli-setup` at any time to resume."

---

## Re-Authentication Only (Expired Credentials)

If invoked only because credentials expired (CLI already installed and configured), skip Phases 0–1 and start at Phase 2.

Tell the developer at the start: "Your Checkmarx One credentials have expired. API keys expire after 30–365 days depending on your tenant's policy. You'll need to generate a new one. Let's re-authenticate — no reconfiguration needed."

---

## Quick Reference

| CLI Command | Purpose |
|---|---|
| `cx version` | Verify CLI is installed |
| `cx configure set --prop-name cx_apikey --prop-value <key>` | Set API key (extracts server/tenant automatically) |
| `cx auth validate` | Verify authentication |
| `cx utils env` | Show current configuration |

Official releases: https://github.com/Checkmarx/ast-cli/releases
Quick-start guide: https://docs.checkmarx.com/en/34965-68621-checkmarx-one-cli-quick-start-guide.html

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-05-10 | Initial release — full install/configure/auth/verify flow |
