# The Checkmarx Remediation MCP (bundled)

The `cx-devassist-asca` skill remediates findings via the **Checkmarx Security MCP**
(`mcp__Checkmarx__codeRemediation`). The plugin declares this server in `.mcp.json`, so Claude Code
starts it **automatically** whenever the plugin is enabled — there is **no registration step and no
`claude mcp add`**. The server command is the native **`cx mcp bridge`** subcommand, which reads the
credential from the cx config, derives the realm-scoped URL from its JWT, and proxies to the remote
MCP over Streamable HTTP. Whatever Phase 2 established — an API key (Path A) or an OAuth refresh token
(Path B) — is what the bridge uses, so a single sign-in covers both the CLI and the MCP. Nothing is
pasted into chat. (Requires a `cx` build that includes `cx mcp bridge` — verify with
`cx mcp bridge --help`.)

## `/reload-plugins` — the single source of truth

A plugin-declared MCP server loads when the plugin is enabled / at session start. After enabling the
plugin or authenticating in the same session, the bridge must be (re-)spawned to pick up the change.
**`/reload-plugins` re-spawns the bridge** against the current `cx` and credential — no full restart.
Everywhere else in this skill that says "reload the MCP" means run `/reload-plugins`.

> "The Checkmarx MCP is bundled with the plugin. Run `/reload-plugins` to re-spawn it, then run
> `/mcp` to reconnect and confirm — reload alone doesn't always reconnect a session's existing MCP
> connection. After that it connects automatically on every launch — no registration and no re-auth."

## Verify

```
/mcp
```

- **`Checkmarx` shows Connected** → remediation is ready.
- **Not connected?** The bridge needs a valid credential to derive the URL and authenticate. Confirm
  `cx auth validate` passes (Phases 2–3) and `cx mcp bridge --help` works, then run `/reload-plugins`
  **followed by `/mcp`** (running `/reload-plugins` alone may not reconnect the MCP in an already-open
  session — `/mcp` is what re-establishes the connection). If still not connected after a restart, for
  dev/on-prem hosts whose `iam`→`ast` mapping doesn't hold, pass the full URL via
  the `--mcp-url` flag in `.mcp.json` args (Claude passes args, not the `env` block). The bridge's
  stderr is captured in the client MCP log under the Claude Code Node-CLI cache directory for the OS:
  - **Windows:** `%LOCALAPPDATA%\claude-cli-nodejs\Cache\<project>\mcp-logs-plugin-cx-devassist-Checkmarx\*.jsonl`
  - **macOS:** `~/Library/Caches/claude-cli-nodejs/<project>/mcp-logs-plugin-cx-devassist-Checkmarx/*.jsonl`
  - **Linux:** `~/.cache/claude-cli-nodejs/<project>/mcp-logs-plugin-cx-devassist-Checkmarx/*.jsonl`

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
