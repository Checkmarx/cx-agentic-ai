# The Checkmarx Remediation MCP (bundled)

The `cx-devassist-asca` and `cx-devassist-sca` skills remediate findings via the **Checkmarx
Security MCP** (`mcp__Checkmarx__codeRemediation`). The plugin ships a best-effort `.mcp.json` as a
forward-compat bet, but the **supported, reliable path for Codex CLI is manual registration** in
`config.toml` — Codex is not confirmed to auto-discover a bundled `.mcp.json`.

**This registration is the agent's job, not the developer's.** When the remediation tool is
unavailable, do not just tell the developer to edit `config.toml` — read the file yourself, check
whether `[mcp_servers.Checkmarx]` is already present and points at this plugin's `cx_run.sh`, and if
not, add or correct it with the Edit/Write tool as a `[mcp_servers.<name>]` stanza in
`~/.codex/config.toml` or `<repo>/.codex/config.toml`:

```toml
[mcp_servers.Checkmarx]
command = "sh"
args = ["<absolute-path-to-plugin>/hooks/cx_run.sh", "mcp", "bridge"]
```

Use the **resolved absolute path** to the plugin directory here, not `${PLUGIN_ROOT}` — that variable
is only meaningful at hook-invocation time, not inside a config file the agent writes directly, so it
must be substituted with the literal path when writing this stanza. Never leave the
`<absolute-path-to-plugin>` placeholder literal in the file.

Once the stanza is written (or confirmed already correct), **retry the remediation tool call once
before assuming a restart is needed** — whether Codex CLI hot-reloads a freshly-written `config.toml`
MCP server is not consistently confirmed; it has been observed to connect live in the same session
without a restart. Only fall back to asking the developer to quit-and-relaunch (below) if the retry
still shows the tool unavailable.

The server command is the native **`cx mcp bridge`** subcommand, which reads the credential from the
cx config, derives the realm-scoped URL from its JWT, and proxies to the remote MCP over Streamable
HTTP. Whatever Phase 2 established — an API key (Path A) or an OAuth refresh token (Path B) — is what
the bridge uses, so a single sign-in covers both the CLI and the MCP. Nothing is pasted into chat.
(Requires a `cx` build that includes `cx mcp bridge` — verify with `cx mcp bridge --help`.)

## Restart the session — the single source of truth

An MCP server registered in `config.toml` loads when the Codex CLI process starts. After registering
the server, enabling the plugin, or authenticating in the same session, **the developer must quit
Codex CLI and relaunch it** so it re-reads `config.toml` and re-spawns the bridge against the current
`cx` and credential. There is **no in-session `/restart` or hot-reload command** — do not tell the
developer to run `/restart`; it does not exist. Concretely: exit the running `codex` process (e.g.
`/exit`, `Ctrl+D`, or closing the terminal), then run `codex` again — optionally `codex resume --last`
if they want the conversation history restored, or a plain `codex` to start fresh. Everywhere else in
this skill that says "reload the MCP" means quit-and-relaunch Codex CLI, not an in-session command.

> "I've added/verified the Checkmarx MCP registration in config.toml. Please quit this Codex CLI
> session (e.g. `/exit`) and start it again — optionally with `codex resume --last` to pick this
> conversation back up — so it re-reads the config and re-spawns the bridge. Once you're back, confirm
> the Checkmarx MCP server is connected and ask me to remediate. After that it connects automatically
> on every launch — no re-registration and no re-auth needed unless the config changes."

## Verify

Check your Codex CLI session's MCP connection status (the exact command, if any, is unconfirmed for
this plugin — use whatever mechanism your Codex CLI version provides to list connected MCP servers).

- **Checkmarx shows connected** → remediation is ready.
- **Not connected?** The bridge needs a valid credential to derive the URL and authenticate. Confirm
  `cx auth validate` passes (Phases 2–3) and `cx mcp bridge --help` works, then **quit and relaunch
  Codex CLI** so it re-reads `config.toml` and re-spawns the bridge (there is no in-session `/restart`
  or hot-reload — the process must actually exit and start again). If still not connected after that,
  for dev/on-prem hosts whose
  `iam`→`ast` mapping doesn't hold, pass the full URL via the `--mcp-url` flag in the `config.toml`
  `args` array. The bridge's stderr is captured in Codex CLI's own MCP connection diagnostics/logs
  (the exact location is not yet documented for this plugin) — check Codex CLI's own MCP logs there.

> The bridge reads the credential from the cx config and sends it **only** in the `Authorization`
> header — never printed to chat or logs. The server accepts the raw credential (it exchanges it
> server-side; no client-side OAuth flow). It derives the realm-scoped URL
> `https://<ast-base>/api/security-mcp/mcp/<realm>` by first match of: the `--mcp-url` arg → the
> `CX_MCP_URL` env var → the authoritative `ast-base-url` claim from a (cached, non-interactive) token
> exchange — so any region / on-prem / custom domain resolves automatically → an offline `iam`→`ast`
> host swap as a last resort. Only set `--mcp-url` when that ladder can't reach your host.

> **Credential rotation self-heals.** Because the bridge reads the credential live from cx config,
> re-authenticating is picked up automatically — there is no re-register step. If a request comes back
> unauthorized (e.g. the token rotated on a fresh `cx auth login`), the bridge re-reads the credential
> and retries, so a rotated token self-heals on the next remediation call.
