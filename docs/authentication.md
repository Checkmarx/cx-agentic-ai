# Authentication

The Checkmarx Security MCP Server supports two authentication methods: **API Key** and **OAuth2 with Dynamic Client Registration (DCR)**.

## Table of Contents

- [API Key Authentication](#api-key-authentication)
  - [Obtaining an API Key](#obtaining-an-api-key)
  - [Using the API Key](#using-the-api-key)
- [OAuth2 Authentication](#oauth2-authentication)
  - [How DCR Flow Works](#how-dcr-flow-works)
  - [OAuth2 Configuration](#oauth2-configuration)
- [Choosing an Authentication Method](#choosing-an-authentication-method)
- [Security Considerations](#security-considerations)

---

## API Key Authentication

API Key authentication is the simplest method. The client passes the API key in the `Authorization` header of every request to the MCP server.

### Obtaining an API Key

1. Log in to your **Checkmarx One** portal.
2. Navigate to **Access Management** → **API Keys**.
3. Generate a new API key and copy it.
4. Keep the key secure — treat it like a password.

> **Note:** You need valid Checkmarx One credentials and sufficient permissions to generate an API key.

### Using the API Key

Pass the API key in the `Authorization` header when configuring your MCP client. See the [examples/](../examples/) folder for ready-to-use client config files.

```json
{
    "Checkmarx": {
      "serverUrl": "https://{api_host}/api/security-mcp/mcp/{tenant}",
      "headers": {
        "cx-origin": "<client-name>",
        "Authorization": "API_KEY"
      }
    }
}
```
**Header format:**
```
Authorization: <your-api-key>
```

**How it works internally:**
- The API key is a JWT issued by Checkmarx IAM.
- The MCP server uses the JWT to perform token validation.

---

## OAuth2 Authentication

OAuth2 with Dynamic Client Registration (DCR) provides a more seamless login experience — no API key management required. The MCP client handles the token flow automatically.

### How DCR Flow Works

1. Configure your MCP client with only the server URL (no `Authorization` header needed).
2. When the client connects to the MCP server for the first time, it is redirected to the **Checkmarx One login page**.
3. You log in with your Checkmarx credentials.
4. Upon successful authentication, the MCP client receives tokens and can start using the tools.
5. Token refresh is handled automatically by the client.

### OAuth2 Configuration

For OAuth2, your MCP client config only needs the server URL:

```json
{
  "mcpServers": {
    "Checkmarx": {
      "serverUrl": "https://{api_host}/api/security-mcp/mcp/{tenant}"
    }
  }
}
```

Replace `{api_host}` and `{tenant}` with your values.

**OAuth2 discovery endpoints exposed by the server:**
- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`

---

## Choosing an Authentication Method

| | API Key | OAuth2 (DCR) |
|---|---|---|
| **Setup complexity** | Low — copy & paste key | Low — no key management |
| **User interaction** | None after setup | Browser login on first connect |
| **Key rotation** | Manual | Automatic token refresh |
| **Best for** | Automated pipelines, CI/CD, scripts | Interactive IDE usage, human users |
| **Supported clients** | All MCP clients | Clients with OAuth2/DCR support (Cursor, Claude, Windsurf, etc.) |

---

## Security Considerations

- **Protect your API key** — store it in your client's secure credential store, not in plain text config files committed to source control.
- **Scope** — ensure the API key or OAuth2 account has only the permissions it needs.
- **TLS** — all connections to the MCP server use HTTPS. Do not disable TLS verification in production.
- **Token caching** — access tokens are cached server-side for 120 seconds. This is intentional to reduce IAM load; tokens are still validated on each cache miss.
- **SSRF protection** — the server validates all OAuth redirect targets and token issuer URLs against an allowlist to prevent server-side request forgery.
- **JWT verification** — incoming JWTs are verified against the configured JWKS endpoint. Tokens with unknown issuers are rejected.

For questions about permissions or account setup, contact your Checkmarx administrator.
