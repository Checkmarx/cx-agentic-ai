---
name: cx-cli-setup
description: "Installs, configures, or re-authenticates the Checkmarx cx CLI. Use when the cx CLI is missing, credentials have expired, or the CLI needs to be reconfigured. Invoke as: cx-security:cx-cli-setup"
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

| CLI present | Auth result | Action |
|---|---|---|
| No | — | Offer custom path (see below), then proceed to Phase 1 |
| Yes | Success | Tell the developer everything looks good. Ask if they want to reconfigure or reauthenticate anyway. If no, exit. |
| Yes | Credential failure (invalid/revoked/expired key) | Tell the developer the CLI is installed but authentication failed. Skip to Phase 2. |
| Yes | Network failure (DNS error, connection refused, timeout) | Tell the developer the CLI is installed but the server is unreachable. Do not proceed to Phase 2 — ask them to check their network or proxy, then re-run `cx auth validate` to confirm. |

To distinguish credential from network failure, check the error output of `cx auth validate`:
- Credential failure: typically contains "invalid", "unauthorized", "401", or "forbidden"
- Network failure: typically contains "no such host", "connection refused", "timeout", or "dial tcp"

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

**If Homebrew is not available or the brew install fails**, note that Checkmarx only publishes an x64 macOS binary — both Intel and Apple Silicon use it (Rosetta 2 handles the translation on M-series Macs).

Tell the developer:
> "Homebrew isn't available. I'll fall back to downloading the x64 binary from GitHub and extracting it to `~/.local/bin` (user-scope, no admin rights required). Shall I run this for you?"

On confirmation:

```bash
mkdir -p ~/.local/bin
curl -fsSL https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_darwin_x64.tar.gz -o /tmp/cx-cli.tar.gz && \
tar -xzf /tmp/cx-cli.tar.gz -C ~/.local/bin cx && \
rm /tmp/cx-cli.tar.gz
```

Then check whether `~/.local/bin` is on the PATH:

```bash
echo $PATH | grep -q "$HOME/.local/bin" && echo "on PATH" || echo "not on PATH"
```

If it is not on PATH, tell the developer:
> "Add the following line to your `~/.zshrc` (or `~/.bashrc`), then open a new terminal:
> ```
> export PATH="$HOME/.local/bin:$PATH"
> ```"

If `curl` is also unavailable, direct the developer to download manually from:
https://github.com/Checkmarx/ast-cli/releases/latest — download `ast-cli_darwin_x64.tar.gz`, extract `cx`, and move it to `~/.local/bin`.

### Linux

First detect the architecture:

```bash
uname -m
```

- `x86_64` → use `ast-cli_linux_x64.tar.gz`
- `aarch64` / `arm64` → use `ast-cli_linux_arm64.tar.gz`
- `armv6*` → use `ast-cli_linux_armv6.tar.gz`
- anything else → tell the developer: "Your architecture is not supported by the pre-built Checkmarx CLI binaries. Please check https://github.com/Checkmarx/ast-cli/releases for available builds or contact Checkmarx support." Do not proceed.

Tell the developer:
> "I'll download the Checkmarx One CLI binary from GitHub and extract it to `~/.local/bin` (user-scope, no admin rights required). Shall I run this for you?"

On confirmation (x64 example — substitute the correct filename for the detected arch):

```bash
mkdir -p ~/.local/bin
curl -fsSL https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_linux_x64.tar.gz -o /tmp/cx-cli.tar.gz && \
tar -xzf /tmp/cx-cli.tar.gz -C ~/.local/bin cx && \
rm /tmp/cx-cli.tar.gz
```

Then check whether `~/.local/bin` is on the PATH:

```bash
echo $PATH | grep -q "$HOME/.local/bin" && echo "on PATH" || echo "not on PATH"
```

If it is not on PATH, tell the developer:
> "Add the following line to your `~/.bashrc` (or `~/.zshrc`), then open a new terminal:
> ```
> export PATH="$HOME/.local/bin:$PATH"
> ```"

If `curl` is unavailable, offer `wget` instead:

```bash
mkdir -p ~/.local/bin
wget -qO /tmp/cx-cli.tar.gz https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_linux_x64.tar.gz && \
tar -xzf /tmp/cx-cli.tar.gz -C ~/.local/bin cx && \
rm /tmp/cx-cli.tar.gz
```

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
[Environment]::SetEnvironmentVariable("Path", "$([Environment]::GetEnvironmentVariable('Path','User'));$dest", "User")
$env:PATH += ";$dest"
```

The first line persists the PATH change at user scope (survives new terminals). The second updates the current session immediately.

---

## Phase 1a — Verify Installation

```bash
cx version
```

- **Returns a version**: confirm — "The `cx` CLI is installed. Version: `<version>`." Proceed to Phase 2.
- **Fails**: "The `cx` binary was not found after installation. The install directory may not be on your PATH. Open a new terminal or add the install directory to PATH, then confirm when ready." Retry `cx version` after confirmation. Do not proceed to Phase 2 until this passes.

`cx version` is a sanity check only — a binary can print a version and still be broken. The real acceptance test is `cx auth validate` in Phase 3. If Phase 3 fails after a fresh install with anything other than a credential error (e.g. a crash or unexpected exit), treat the install itself as suspect and re-run Phase 1 before asking the developer to reconfigure.

---

## Phase 2 — Configure the CLI

Tell the developer:

> "To configure the CLI I'll need your Checkmarx One API key. When using API key authentication, the CLI automatically extracts the server URL, auth URL, and tenant from the key — so the API key is all you need. Note that API keys expire after 30–365 days depending on your tenant's policy."

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

Once they confirm, note: "Your API key is stored in plaintext in `~/.checkmarx/checkmarxcli.yaml` (Windows: `%USERPROFILE%\.checkmarx\checkmarxcli.yaml`). Protect that file like an SSH private key — restrict permissions (`chmod 600 ~/.checkmarx/checkmarxcli.yaml` on macOS/Linux) and exclude it from backups or version control."

---

## Phase 3 — Verify Connectivity

```bash
cx auth validate
```

Interpret the result:

- **Exit code 0 / "Successfully authenticated"**: confirm — "Authentication verified. The plugin is ready to scan."
- **Auth/credential failure**: "Authentication check failed — your API key may be invalid. Would you like to re-enter it?" If yes, return to Phase 2. Do not proceed.
- **Server unreachable** (connection refused, DNS error, timeout): Ask the developer: "Could not reach the Checkmarx One server. Are you on a self-hosted or on-premises deployment?" If yes, the API key may not encode the server URL — ask them to also configure the base URIs:
  ```
  cx configure set --prop-name cx_base_uri --prop-value <your-base-url>
  cx configure set --prop-name cx_base_auth_uri --prop-value <your-auth-url>
  ```
  Then re-run `cx auth validate`. If they are on SaaS, treat it as a network/proxy issue and advise them to check connectivity before retrying.
- **Permission error** (authenticated but no project access): "Authentication succeeded but you don't have access to any Checkmarx One projects. Please contact your Checkmarx administrator."

---

## Phase 4 — Complete

Run:

```bash
cx utils env
```

Surface the tenant and server URL from the output so the developer can confirm they authenticated against the right environment.

Then tell the developer:

> "Setup complete. The Checkmarx One CLI is installed, configured, and authenticated. Security scanning is now active."

The hook that triggered this skill will re-run automatically and the original agent action will proceed.

---

## Error Handling (Any Phase)

- Surface the specific error — never a generic "something went wrong."
- Identify which phase failed.
- Let the developer correct and retry **that step only** — no restarting the entire flow.
- If the developer cancels mid-flow: "Setup is incomplete. The plugin will remain blocked. Run `/cx-cli-setup` at any time to resume."

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
| 0.9.0 | 2026-06-02 | Pre-release — full flow implemented, pending end-to-end test matrix across OS/arch |
