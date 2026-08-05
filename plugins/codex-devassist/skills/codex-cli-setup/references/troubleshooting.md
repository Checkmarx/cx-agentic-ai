# Troubleshooting

## An existing `cx` is installed but not on PATH

When Phase 0's custom-path offer yields a working binary at a non-standard path (`"<path>" version`
returns a version), the CLI is installed but not on PATH. Guide the developer to add its directory
to PATH permanently:

- **macOS/Linux:** add `export PATH="<directory>:$PATH"` to `~/.zshrc` or `~/.bashrc`, then
  `source` it (or open a new terminal).
- **Windows:** add the directory via System Properties → Environment Variables → Path, or use the
  User-scope persistence in `references/windows-path-activation.md`.

A *newly* added PATH directory is not visible to the running Codex CLI session — but the gate does
**not** depend on PATH: it resolves the **canonical store**
(`%LOCALAPPDATA%\Checkmarx\cx\cx.exe` on Windows, `~/.checkmarx/bin/cx` on Unix) by absolute path, so
a `$codex-cli-setup` install unblocks it immediately, with no restart. To use a cx that lives
*elsewhere*, set the `CX_BINARY` override below. If the provided path does not return a version, the
binary is not usable there — proceed with a fresh install (Phase 1).

## Server unreachable / self-hosted base URIs

If `cx auth validate` reports the server is unreachable (connection refused, DNS error, timeout),
ask whether the deployment is self-hosted / on-premises. If yes, the API key may not encode the
server URL — configure the base URIs explicitly:

```bash
cx configure set --prop-name cx_base_uri --prop-value <your-base-url>
cx configure set --prop-name cx_base_auth_uri --prop-value <your-auth-url>
```

Then re-run `cx auth validate`. On SaaS, treat unreachability as a network/proxy issue and check
connectivity before retrying.

## A gated action is still denied after `cx version` works

The gate resolves cx by absolute path — `CX_BINARY` → the canonical store
(`%LOCALAPPDATA%\Checkmarx\cx\cx.exe` / `~/.checkmarx/bin/cx`) → PATH — and runs it in its own
process, so "version works when I type it" does not by itself prove the gate is satisfied. After a
fresh `$codex-cli-setup` install the gate is **live on your next tool call, with no restart** (it finds
the canonical store directly). If an action is *still* denied, the cause is almost never PATH — read
the deny message: it is usually `below minimum version`, **incapable** (missing the agent-security
subcommands — see below), or **not authenticated**. Do **not** try to "fix PATH" by hand-placing a cx
binary or clearing caches; address the reason the deny actually states.

## The security gate itself won't run (missing Python 3 or Git-Bash)

If the deny reason is that the **gate could not run** (not that cx is missing/below-version/
unauthenticated), the host is missing one of the gate's two hard prerequisites: a POSIX `sh`
(Git for Windows on Windows) and **Python 3**. The gate launches via `sh` and executes Python, so
if either is absent it cannot start. It **fails closed** — a missing Python 3 makes the gate
**block** rather than wave the action through — so restoring the prerequisite is the only fix; do
not try to disable or bypass the gate.

Install pointers:

- **Windows** — install **Git for Windows** (https://git-scm.com/download/win) for `sh`, and
  **Python 3** from https://www.python.org/downloads/ (use the python.org installer, **not** the
  Microsoft Store stub). Git-Bash is a **hard prerequisite** on Windows: without it neither the
  gate nor Codex CLI's own shell tool can run (Codex CLI's shell tool requires Git Bash on
  Windows, and the `sh`-based gate then cannot launch without it).
- **macOS** — `sh` is built in; install Python 3 with `xcode-select --install` or
  `brew install python3`.
- **Linux** — `sh` is built in; install Python 3 with your package manager
  (`apt install python3`, `dnf install python3`, or `apk add python3`).

## `cx` is installed but INCAPABLE (missing the agent-security subcommands)

If the deny says cx is installed but **missing `cx mcp bridge` / `cx hooks claude-*`**, the installed
build predates the agent-security hooks. This is a **terminal** state: re-running install/upgrade just
re-fetches the same incapable build, so it will not help. A capability-complete cx build is required,
which **may not be publicly available yet**.

Do **not** try to work around the gate — do not hand-place a cx binary into a PATH folder, edit PATH,
run `setx`, or clear the gate's caches. Those only hide the block without restoring scanning and leave
the machine half-configured. Tell the developer a capable cx build is required, and stop. If the
developer already has an **internal** capable build, they can point the gate at it with `CX_BINARY`
(below).

## `CX_BINARY` — point the gate at an explicit cx (locked-down machines)

When `cx` cannot be placed on any writable PATH directory, set **`CX_BINARY`** to the absolute path
of the cx executable. The security gate then invokes **that** binary for all of its own probes
(version, capability, authentication) instead of resolving `cx` from PATH, so the gate stops denying
once it is configured:

```bash
# macOS/Linux (set where Codex CLI is launched, e.g. your shell profile):
export CX_BINARY="/opt/checkmarx/cx"
# Windows (User environment variable, so the Codex CLI process inherits it):
[Environment]::SetEnvironmentVariable('CX_BINARY', 'C:\Tools\Checkmarx\cx.exe', 'User')
```

Rules and guarantees:

- **Must be an absolute path to an existing executable.** A set-but-invalid `CX_BINARY` (not
  absolute, missing, or not executable) makes the gate fail **closed** — it denies with a clear
  message rather than silently falling back to a different binary.
- **It is not a trust bypass.** The override only changes *which* cx the gate runs; the same
  version, capability, and authentication checks then validate that binary is a real, recent,
  capable, authenticated cx before anything is allowed.
- **The stage-2 scanner and the remediation MCP honor it too** — both run through `hooks/cx_run.sh`,
  which uses the same precedence (CX_BINARY → canonical store → PATH), so scanning and remediation run
  the exact binary the gate validated. The MCP resolves cx by absolute path (no PATH placement or
  symlink needed); picking up a changed `CX_BINARY` requires restarting the Codex CLI session so it
  re-reads `config.toml` and re-spawns the bridge. Do not hand-edit the `config.toml` MCP stanza casually.
- `CX_BINARY` must be set in the environment Codex CLI is launched with (the hooks inherit it);
  setting it only inside an agent shell command will not reach the gate.
