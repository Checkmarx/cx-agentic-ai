# Cursor IDE - Checkmarx MCP Setup Guide

The Checkmarx plugin registers its MCP server  through Cursor's plugin marketplace mechanism — no manual `mcp.json` editing, no environment variables, and no restarting your computer.

## Installation

### Option 1: From Cursor Marketplace

1. Open Cursor and navigate to **Settings → Plugins**.
2. Search for "Checkmarx" and click → **Add to Cursor**.
3. Cursor will prompt you for Checkmarx base URL and tenant ID.
4. Fill in the required information and click → **Connect**.
5. Cursor will open the browser for Checkmarx authentication, and the plugin will register the Checkmarx MCP server automatically.

### Option 2: Local Installation (Development)

1. Clone or download this repository.
2. In Cursor, go to **Settings → Plugins → Browse Marketplace**.
3. Click on → **+ ADD**.
4. Select **From Local Repo**.
5. Point to the `cloned repository` directory.
6. Cursor will load the plugin locally.
7. Click on → **Configure**. Cursor will prompt you for Checkmarx base URL and tenant ID.
8. Fill in the required information and click → **Connect**.
9. Cursor will open the browser for Checkmarx authentication, and the plugin will register the Checkmarx MCP server automatically.


## Setup (1 minute)

1. Click on → **Configure**. Cursor will prompts you to configure the plugin, fill in:
   - **Checkmarx One API Host** — e.g. `ast.checkmarx.net`
   - **Tenant ID** — your Checkmarx tenant identifier
   - **API Key** *(optional)* — leave blank to authenticate via browser-based OAuth2 login on first use instead
2. Cursor will open the browser for Checkmarx authentication, and the plugin will register the Checkmarx MCP server automatically..

That's it — Cursor can now use the registered `Checkmarx` MCP server tools.

## Verify

Ask Cursor:
```
What MCP servers are available?
```
or
```
List all Checkmarx tools
```

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
