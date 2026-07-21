# Cursor IDE - Checkmarx MCP Setup Guide

The Checkmarx plugin registers its MCP server automatically through Cursor's plugin marketplace mechanism — no manual `mcp.json` editing, no environment variables, and no restarting your computer.

## Setup (1 minute)

1. Install the **Checkmarx** plugin from the Cursor Marketplace (or add this repo's `.cursor-plugin/marketplace.json` as a custom marketplace source).
2. When Cursor prompts you to configure the plugin, fill in:
   - **Checkmarx One API Host** — e.g. `ast.checkmarx.net`
   - **Tenant ID** — your Checkmarx tenant identifier
   - **API Key** *(optional)* — leave blank to authenticate via browser-based OAuth2 login on first use instead
3. Restart Cursor.

That's it — Cursor reads the plugin's `mcp.json` and registers the `Checkmarx` MCP server for you using the values you entered.

## Verify

Ask Cursor:
```
What MCP servers are available?
```
or
```
List all Checkmarx tools
```

If you left the API Key blank, the first tool call will open a browser window for you to log in to Checkmarx One. After that, token refresh is handled automatically.

## Updating configuration later

Reopen the plugin's configuration panel in Cursor (Settings → Plugins → Checkmarx → Configure) to change your API host, tenant ID, or API key — no file editing required.

## Troubleshooting

**MCP not appearing in Cursor**
- Confirm the plugin shows as installed and configured in Settings → Plugins.
- Confirm Cursor was restarted after installing/configuring the plugin.

**Connection error**
- Double-check the API host (e.g. `ast.checkmarx.net`, no `https://` prefix) and tenant ID.
- Confirm network access to your Checkmarx One tenant.

**401 Unauthorized**
- If using OAuth2 (API Key left blank), make sure you completed the browser login prompt.
- If using an API key, verify it hasn't expired and that your Checkmarx user has the required permissions.

See [docs/authentication.md](../../docs/authentication.md) for full authentication details.

## Getting help

Contact: support@checkmarx.com
