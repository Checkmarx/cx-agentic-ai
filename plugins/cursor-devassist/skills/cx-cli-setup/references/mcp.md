# The Checkmarx Remediation MCP (bundled)

The `cx-devassist-asca` / `cx-devassist-sca` skills remediate findings via the **Checkmarx Security
MCP** (`mcp__plugin-cx-devassist-Checkmarx__codeRemediation` /
`mcp__plugin-cx-devassist-Checkmarx__packageRemediation`). The plugin declares this server in
`mcp.json` under the key `Checkmarx`, so Cursor starts it **automatically** whenever the plugin is
installed under `~/.cursor/plugins/local/` — there is **no manual registration step**. In Cursor's
MCP settings panel the server appears as **`plugin-cx-devassist-Checkmarx`** (plugin id +
`mcp.json` key). The server command is the native **`cx mcp bridge`** subcommand, which reads the
credential from the cx config, derives the realm-scoped URL from its JWT, and proxies to the remote
MCP over Streamable HTTP. Whatever Phase 2 established — an API key (Path A) or an OAuth refresh
token (Path B) — is what the bridge uses, so a single sign-in covers both the CLI and the MCP.
Nothing is pasted into chat. (Requires a `cx` build that includes `cx mcp bridge` — verify with
`cx mcp bridge --help`.)

## Reloading the MCP — the single source of truth

A plugin-declared MCP server loads when Cursor starts (or the plugin is installed/enabled). After
installing the plugin or authenticating in the same session, the bridge must be (re-)spawned to pick
up the change. **Developer: Reload Window** (Command Palette) re-spawns it against the current `cx`
and credential — no full application restart needed. Everywhere else in this skill that says "reload
the MCP" means run **Developer: Reload Window**.

> "The Checkmarx MCP is bundled with the plugin. Run **Developer: Reload Window** to re-spawn it,
> then check your MCP settings/panel to confirm **`plugin-cx-devassist-Checkmarx`** shows connected.
> After that it connects automatically on every launch — no registration and no re-auth."

## Verify

Open Cursor's MCP settings (or the equivalent status panel) and check the
**`plugin-cx-devassist-Checkmarx`** server's status.

- **`plugin-cx-devassist-Checkmarx` shows Connected** → remediation is ready.
- **Not connected?** The bridge needs a valid credential to derive the URL and authenticate. Confirm
  `cx auth validate` passes (Phases 2–3) and `cx mcp bridge --help` works, then run **Developer: Reload
  Window** and re-check the MCP status. If still not connected, for dev/on-prem hosts whose
  `iam`→`ast` mapping doesn't hold, pass the full URL via the `--mcp-url` flag in `mcp.json`'s `args`.
  If the MCP still won't connect, check Cursor's own MCP/output logs for the bridge's stderr.

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

## Discovering MCP tools

If a remediation call fails with "tool not found", use `GetMcpTools` with pattern `Checkmarx` or
`plugin-cx-devassist` to list the live tool names for this session. The expected names are:

| Tool | Full name |
|------|-----------|
| SAST / ASCA fix | `mcp__plugin-cx-devassist-Checkmarx__codeRemediation` |
| SCA / package fix | `mcp__plugin-cx-devassist-Checkmarx__packageRemediation` |
| IaC / image fix | `mcp__plugin-cx-devassist-Checkmarx__imageRemediation` |
