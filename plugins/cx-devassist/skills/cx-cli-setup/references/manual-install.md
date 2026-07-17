# Manual install (per-OS fallback)

Use this when the developer declines the bundled bootstrap, or when `bash` / Git Bash is
unavailable. Before running any command, explain what will be installed and where, then ask:

> "Shall I run this for you?"

Only execute after the developer confirms. If they decline, show the command and wait for them
to confirm completion before returning to **Phase 1a — Verify Installation**.

To print the exact release asset for this machine (instead of guessing the arch), run the
bundled resolver and download the name it prints:

```bash
bash "<plugin-root>/scripts/cx-asset-resolver.sh"   # e.g. ast-cli_linux_arm64.tar.gz
```

## macOS

**Primary — Homebrew:**

```bash
brew install checkmarx/ast-cli/ast-cli
```

**If Homebrew is unavailable or the install fails**, note that Checkmarx publishes only an x64
macOS binary — both Intel and Apple Silicon use it (Rosetta 2 translates on M-series Macs; if
`cx` later fails to launch on Apple Silicon, install Rosetta with
`softwareupdate --install-rosetta --agree-to-license`). Download to `~/.checkmarx/bin` — the
**canonical store** the gate resolves by absolute path (user scope, no admin rights):

```bash
mkdir -p ~/.checkmarx/bin
curl -fsSL https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_darwin_x64.tar.gz -o /tmp/cx-cli.tar.gz && \
tar -xzf /tmp/cx-cli.tar.gz -C ~/.checkmarx/bin cx && \
chmod +x ~/.checkmarx/bin/cx && \
rm /tmp/cx-cli.tar.gz
```

If `curl` is unavailable, direct the developer to download `ast-cli_darwin_x64.tar.gz` from
https://github.com/Checkmarx/ast-cli/releases/latest, extract `cx`, and move it to `~/.checkmarx/bin`
(`chmod +x`). Homebrew or `/usr/local/bin` are fine alternatives **only if already on PATH**, but
`~/.checkmarx/bin` is the reliable target the gate always finds.

## Linux

Resolve the asset for the architecture (`bash scripts/cx-asset-resolver.sh`), then download to
`~/.checkmarx/bin` — the **canonical store** the gate resolves by absolute path (x64 shown —
substitute the resolved name):

```bash
mkdir -p ~/.checkmarx/bin
curl -fsSL https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_linux_x64.tar.gz -o /tmp/cx-cli.tar.gz && \
tar -xzf /tmp/cx-cli.tar.gz -C ~/.checkmarx/bin cx && \
chmod +x ~/.checkmarx/bin/cx && \
rm /tmp/cx-cli.tar.gz
```

If only `wget` is available, swap the download line for
`wget -qO /tmp/cx-cli.tar.gz <url>`. If neither is available, direct the developer to the
releases page. An unsupported architecture (resolver prints `unsupported: …`) has no pre-built
binary — stop and point the developer to the releases page or Checkmarx support.

## Windows

**Git for Windows is mandatory.** The gate launches through `sh`, and Claude Code needs Git Bash
for its own Bash tool, so install it first from https://git-scm.com/download/win. Without it the
gate cannot run at all.

Install `cx.exe` into `%LOCALAPPDATA%\Checkmarx\cx\cx.exe` — the **canonical store** the gate
resolves by absolute path (matching what the bootstrap writes). Do **not** scatter it into some
folder that happens to be on PATH. From Git Bash:

```bash
mkdir -p "$LOCALAPPDATA/Checkmarx/cx"
curl -fsSL https://github.com/Checkmarx/ast-cli/releases/latest/download/ast-cli_windows_x64.zip -o /tmp/cx-cli.zip && \
unzip -o /tmp/cx-cli.zip cx.exe -d "$LOCALAPPDATA/Checkmarx/cx" && \
rm /tmp/cx-cli.zip
```

If `curl`/`unzip` are unavailable, direct the developer to download `ast-cli_windows_x64.zip`
from https://github.com/Checkmarx/ast-cli/releases/latest, extract `cx.exe`, and place it at
`%LOCALAPPDATA%\Checkmarx\cx\cx.exe`.

## Activation (all platforms)

Install into the **canonical store** and you are done: the gate resolves cx by absolute path
(`%LOCALAPPDATA%\Checkmarx\cx\cx.exe` on Windows, `~/.checkmarx/bin/cx` on Unix) on the **next
tool call** — no PATH placement, symlink, or restart needed. Only the remediation MCP needs one
`/reload-plugins` (see `references/mcp.md`).

## Install integrity (`CX_REQUIRE_CHECKSUM`)

The bundled `cx-bootstrap.sh` verifies the downloaded asset's SHA-256 against the release's
published `*_checksums.txt` before extracting, and aborts on a mismatch (corruption/tampering).
If the checksums file cannot be fetched (offline) or no hashing tool exists, it warns and
proceeds — unless `CX_REQUIRE_CHECKSUM=1` is set, which makes any inability to verify fatal.
Set it for high-assurance installs:

```bash
CX_REQUIRE_CHECKSUM=1 bash "<plugin-root>/scripts/cx-bootstrap.sh" install
```
