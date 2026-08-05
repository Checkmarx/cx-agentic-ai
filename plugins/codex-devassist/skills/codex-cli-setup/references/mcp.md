# The Checkmarx Remediation MCP (bundled)

The `codex-devassist-asca` skill remediates findings via the **Checkmarx Security MCP**
(`mcp__Checkmarx__codeRemediation`). The plugin ships a best-effort `.mcp.json` as a forward-compat
bet, but the **supported, reliable path for Codex CLI is manual registration** in `config.toml` — Codex
is not confirmed to auto-discover a bundled `.mcp.json`. Register the server as a
`[mcp_servers.<name>]` stanza in `~/.codex/config.toml` or `<repo>/.codex/config.toml`:

```toml
[mcp_servers.Checkmarx]
command = "sh"
args = ["<absolute-path-to-plugin>/hooks/cx_run.sh", "mcp", "bridge"]
```

Use the **resolved absolute path** to the plugin directory here, not `${PLUGIN_ROOT}` — that variable
is only meaningful at hook-invocation time, not inside a user-edited config file, so it must be
substituted with the literal path when writing this stanza.

The server command is the native **`cx mcp bridge`** subcommand, which reads the credential from the
cx config, derives the realm-scoped URL from its JWT, and proxies to the remote MCP over Streamable
HTTP. Whatever Phase 2 established — an API key (Path A) or an OAuth refresh token (Path B) — is what
the bridge uses, so a single sign-in covers both the CLI and the MCP. Nothing is pasted into chat.
(Requires a `cx` build that includes `cx mcp bridge` — verify with `cx mcp bridge --help`.)

## Restart the session — the single source of truth

An MCP server registered in `config.toml` loads when the Codex CLI session starts. After registering
the server, enabling the plugin, or authenticating in the same session, **Codex must be restarted**
so it re-reads `config.toml` and re-spawns the bridge against the current `cx` and credential — there
is **no confirmed hot-reload command** for Codex CLI. Everywhere else in this skill that says "reload
the MCP" means restart the Codex CLI session.

> "The Checkmarx MCP is registered via config.toml. Restart your Codex CLI session so it re-reads the
> config and re-spawns the bridge, then confirm the Checkmarx MCP server is connected. After that it
> connects automatically on every launch — no re-registration and no re-auth needed unless the
> config changes."

## Verify

Check your Codex CLI session's MCP connection status (the exact command, if any, is unconfirmed for
this plugin — use whatever mechanism your Codex CLI version provides to list connected MCP servers).

- **Checkmarx shows connected** → remediation is ready.
- **Not connected?** The bridge needs a valid credential to derive the URL and authenticate. Confirm
  `cx auth validate` passes (Phases 2–3) and `cx mcp bridge --help` works, then **restart the Codex
  CLI session** so it re-reads `config.toml` and re-spawns the bridge (a restart is required — there
  is no confirmed hot-reload). If still not connected after a restart, for dev/on-prem hosts whose
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
