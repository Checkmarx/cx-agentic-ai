# Troubleshooting

Common issues and solutions when using the Checkmarx Security MCP Server.

## Table of Contents

- [Connection Issues](#connection-issues)
- [Authentication Errors](#authentication-errors)
- [Tool Execution Errors](#tool-execution-errors)
- [Scan Issues](#scan-issues)
- [Client-Specific Issues](#client-specific-issues)
- [Getting Help](#getting-help)

---

## Connection Issues

### MCP client cannot connect to the server

**Symptoms:** Client shows "server not reachable", connection timeout, or no tools listed.

**Checks:**
1. Verify the server URL in your config matches the pattern `https://{api_host}/api/security-mcp/mcp/{tenant}`.
2. Confirm your `api_host` value (e.g., `ast.checkmarx.net`) — get this from your Checkmarx administrator.
3. Confirm your `tenant` value (e.g., `cx_eu`, `checkmarx`).
4. Check that your network allows outbound HTTPS traffic to the Checkmarx API host.
5. Test basic connectivity: `curl -I https://{api_host}/api/security-mcp/mcp/{tenant}`.

**Common mistakes:**
- Trailing slash in the URL (remove it).
- Using `http://` instead of `https://`.
- Wrong tenant — it is case-sensitive.

---

### TLS / certificate errors

**Symptoms:** `x509: certificate signed by unknown authority`, SSL handshake failures.

**Solution:**
- If your organization uses a corporate proxy or self-signed certificate, you may need to add the CA cert to your system trust store, or — in non-production environments only — set `HTTP_TLS_SKIP_VERIFY=true` in the server config.
- Do not disable TLS verification in production.

---

## Authentication Errors

### `401 Unauthorized`

**Symptoms:** All tool calls return 401 or "unauthorized".

**API Key authentication:**
1. Check that the `Authorization` header is set correctly in your client config.
2. Ensure the API key has not expired or been revoked.
3. Confirm the key was generated for the correct Checkmarx One tenant.
4. Re-generate the API key from the Checkmarx One portal if unsure.

**OAuth2 authentication:**
1. Try disconnecting and reconnecting the MCP server in your client to re-trigger the OAuth2 login flow.
2. Check that your Checkmarx One credentials are valid.
3. Ensure your account has the required permissions.

---

### `403 Forbidden`

**Symptoms:** Connected successfully but tools return 403.

**Solution:** Your API key or OAuth2 account may lack permission for the requested operation. Contact your Checkmarx administrator to verify your account has the necessary roles (e.g., scan permissions, project access).

---

### `invalid_token` or JWT errors

**Symptoms:** Token validation failures, "issuer not allowed", "audience mismatch".

**Solution:**
- Ensure the API key was generated from the correct Checkmarx One tenant.
- The server validates JWTs based on the tenant's issuer and audience — if these don't match, authentication will fail.
- API keys have an expiry — re-generate if the key is older than the configured TTL.

---

## Tool Execution Errors

### Tool returns empty results

**Symptoms:** `listProjects`, `listScans`, etc. return an empty list.

**Checks:**
1. Verify you are connected to the correct tenant.
2. Confirm your account has access to the projects/scans you expect.
3. Try listing with no filters first to see if any results exist.

---

### `resolveProject` returns "not found"

**Symptoms:** Project lookup returns no match.

**Checks:**
1. Project names are case-sensitive — verify the exact name in the Checkmarx One portal.
2. Use `listProjects` first to browse available projects.
3. Ensure your account has read access to the project.

---

### Scan fails to start (`triggerScan`)

**Symptoms:** `triggerScan` returns an error or the scan stays in a failed state.

**Checks:**
1. For CLI mode (local code): ensure the Checkmarx CLI is installed and accessible.
2. For API mode (repository URL): ensure the repository URL is accessible from the Checkmarx One platform.
3. Verify the project exists — use `resolveProject` first.
4. Check that the selected scan engines are enabled for your tenant.

---

### Scan stuck in `Running` state

**Symptoms:** `getScanDetails` keeps returning "Running" for a long time.

**Expected behavior:** Large scans may take several minutes. The server polls every 5 seconds with a default max wait of 2 minutes for `getScanDetails`. For longer scans, poll manually using `getScanDetails` or `getLatestScans`.

---

### `codeRemediation` returns no suggestions

**Symptoms:** Remediation tool returns empty or "no fix available".

**Checks:**
1. Verify the finding ID is correct — use `getFindingDetails` to confirm.
2. Not all finding types have AI-generated fixes available. SAST, IaC, and secret findings are supported.
3. For SCA findings, use `packageRemediation` instead.
4. For container image findings, use `imageRemediation`.

---

## Client-Specific Issues

### Cursor

- If tools are not listed, reload the MCP server from Cursor's MCP settings panel.
- For OAuth2 flow, Cursor opens a browser tab — ensure pop-ups are not blocked.

### Claude Desktop / Claude Code

- The config must use `"type": "http"` for HTTP transport.
- Verify the config file location: `~/.claude/claude_desktop_config.json` (macOS/Linux) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).
- Restart Claude Desktop after editing the config file.

### Windsurf

- Windsurf uses `serverUrl` (not `url`) in its MCP config.
- The `cx-origin: Windsurf` header is optional but helps with server-side analytics.

### GitHub Copilot (IntelliJ / VS Code)

- Uses `servers` (not `mcpServers`) and `url` (not `serverUrl`).
- Headers go under `requestInit.headers`.
- Restart the IDE after updating the MCP config.

---

## Getting Help

If the issue persists after following the steps above:

1. Check the [Checkmarx documentation](https://checkmarx.com/product/developer-assist/) for the latest setup guides.
2. Contact your **Checkmarx administrator** for tenant-specific configuration or permission issues.
3. Open an issue in the [GitHub repository](https://github.com/Checkmarx/cx-agentic-ai) with:
   - Your client (Cursor, Claude, Windsurf, etc.) and version
   - The error message or unexpected behavior
   - Steps to reproduce (omit any API keys or credentials)
