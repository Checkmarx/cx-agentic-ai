# Troubleshooting

## An existing `cx` is installed but not on PATH

When Phase 0's custom-path offer yields a working binary at a non-standard path (`"<path>" version`
returns a version), the CLI is installed but not on PATH. Guide the developer to add its directory
to PATH permanently:

- **macOS/Linux:** add `export PATH="<directory>:$PATH"` to `~/.zshrc` or `~/.bashrc`, then
  `source` it (or open a new terminal).
- **Windows:** add the directory via System Properties → Environment Variables → Path, or use the
  User-scope persistence in `references/windows-path-activation.md`.

A *newly* added PATH directory is not visible to the running Claude Code session — to unblock the
gate **now**, either place `cx` into a folder already on PATH (see the main skill, Phase 1) or use
the `CX_BINARY` override below. If the provided path does not return a version, the binary is not
usable there — proceed with a fresh install (Phase 1).

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

The hooks resolve and run `cx` independently of the agent's Bash shell (a different PATH snapshot,
a separate process), so "version works when I type it" does **not** prove the gate is satisfied. If
an action is still denied after `cx version` succeeds in the shell, the install landed somewhere the
hook's PATH can't see it. Re-run the bootstrap (it places `cx` into an already-on-PATH folder), use
the in-session activation steps (Phase 1 / `windows-path-activation.md`), or set the `CX_BINARY`
override below. Do not declare success until the next gated tool call proceeds.

## `CX_BINARY` — point the gate at an explicit cx (locked-down machines)

When `cx` cannot be placed on any writable PATH directory, set **`CX_BINARY`** to the absolute path
of the cx executable. The security gate then invokes **that** binary for all of its own probes
(version, capability, authentication) instead of resolving `cx` from PATH, so the gate stops denying
once it is configured:

```bash
# macOS/Linux (set where Claude Code is launched, e.g. your shell profile):
export CX_BINARY="/opt/checkmarx/cx"
# Windows (User environment variable, so the Claude Code process inherits it):
[Environment]::SetEnvironmentVariable('CX_BINARY', 'C:\Tools\Checkmarx\cx.exe', 'User')
```

Rules and guarantees:

- **Must be an absolute path to an existing executable.** A set-but-invalid `CX_BINARY` (not
  absolute, missing, or not executable) makes the gate fail **closed** — it denies with a clear
  message rather than silently falling back to a different binary.
- **It is not a trust bypass.** The override only changes *which* cx the gate runs; the same
  version, capability, and authentication checks then validate that binary is a real, recent,
  capable, authenticated cx before anything is allowed.
- **It affects only the gate's own cx calls** — the agent's own `cx …` commands (and the bundled
  bootstrap) still resolve `cx` from PATH. Set `.mcp.json`'s `command` to the same absolute path so
  the remediation MCP bridge also runs, then `/reload-plugins`.
- `CX_BINARY` must be set in the environment Claude Code is launched with (the hooks inherit it);
  setting it only inside an agent Bash command will not reach the gate.
