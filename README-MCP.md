# Checkmarx Security MCP
[![MCP](https://img.shields.io/badge/MCP-Server-blue.svg)](https://modelcontextprotocol.io) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) 

> The Checkmarx Security [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that connects AI coding assistants to [Checkmarx One](https://checkmarx.com/product/application-security-platform/) — 
> enabling real-time security scanning, vulnerability management, and AI-generated remediation directly inside your IDE or AI agent.

Part of [Checkmarx Agentic AI](README.md).

## Table of Contents

- [Overview](#overview)
  - [Supported scan engines](#supported-scan-engines)
  - [Supported transport protocols](#supported-transport-protocols)
- [Features](#features)
- [Authentication](#authentication)
  - [OAuth2 Authentication (Recommended)](#oauth2-authentication-recommended)
  - [API Key Authentication](#api-key-authentication)
- [MCP Client Configuration](#mcp-client-configuration)
  - [Prerequisites](#prerequisites)
  - [JSON Configuration](#json-configuration)
- [Available Tools](#available-tools)
  - [Scanning](#scanning)
  - [Project management](#project-management)
  - [Application management](#application-management)
  - [Analytics & risk](#analytics--risk)
  - [Remediation](#remediation)

## Overview

The Checkmarx Security MCP server bridges your AI assistant (Claude, Cursor, Copilot, Gemini CLI, etc.) with Checkmarx One's enterprise application security platform. 
It exposes security workflows as natural-language-accessible MCP tools, 
allowing developers to scan code, investigate findings, and receive context-aware fixes without leaving their development environment.

### Supported scan engines:
- **SAST** — Static Application Security Testing (30+ languages)
- **SCA** — Software Composition Analysis (open-source dependencies)
- **KICS** — Infrastructure as Code security (Terraform, CloudFormation, Kubernetes, Dockerfile)
- **Secret Detection** — Hardcoded credentials, API keys, tokens

### Supported transport protocols
Multi-protocol support to facilitate secure and efficient communication between clients and the server:

- `stdio`: Standard input/output for CLI or embedded agents
- `sse` (Server-Sent Events): For real-time streaming to web-based clients
- `http`streamableHttp: HTTP-compatible protocol for stream-based messaging

## Features


| Category | Capabilities |
|---|---|
| **Scanning** | Plan, trigger, and monitor multi-engine security scans (CLI or API mode) |
| **Findings** | List, filter, and inspect vulnerabilities with severity and state tracking |
| **Remediation** | AI-generated fixes for code vulnerabilities, insecure packages, and container images |
| **Project Management** | Create, configure, and search Checkmarx One projects |
| **Application Management** | Group projects into applications and get org-wide security metrics |
| **Analytics** | Tenant-wide vulnerability summaries, risk scores, and time-windowed trends |
| **Supply Chain** | Detect malicious npm/Maven/PyPI/Go/NuGet packages via Dustico integration |
| **Enterprise Auth** | JWT (JWKS-verified), OAuth2 token exchange, Redis session caching |
| **Observability** | Structured logging (zerolog), OpenTelemetry tracing |


## Authentication

The server uses **API Key** and **OAuth2** authentication.

### OAuth2 Authentication (Recommended)
Checkmarx MCP supports Dynamic Client Registration (DCR) flow allows an AI client (such as Cursor, Claude Desktop, or Gemini CLI) to connect securely.
1. User only needs to configure the MCP client as mentioned in the [MCP Client Configuration](#mcp-client-configuration) section.
2. When the client attempts to connect to the MCP server, it will be redirected to Checkmarx One login page for authentication.
3. Once authentication is successful with valid Checkmarx credentials, the MCP client can use the tools provided by the MCP server.

### API Key Authentication

1. Clients authenticate to Checkmarx One and get an API key.
2. This API key will be used during MCP client configuration, include the API Key in the `Authorization` header as mentioned in the [MCP Client Configuration](#mcp-client-configuration) section.

**Note:** You required valid Checkmarx credentials to get the API Key or connect to the MCP server.

Refer [Authentication](/docs/authentication.md) for detailed authentication instructions and troubleshooting.

## MCP Client Configuration

### Prerequisites

- A Checkmarx One tenant 
- Checkmarx API Host 
- API Key (with required access if using API key authentication)

### JSON Configuration
Below are examples to add the server to your MCP client configuration. See the [examples/](examples) folder for ready-to-use client config files (`claude-mcp.json`, `cursor-mcp.json`, `copilot-mcp.json`, `gemini-mcp.json`, `windsurf-mcp.json`, `kiro-mcp.json`).

**Gemini CLI** lives in `~/.gemini/settings.json` and uses `httpUrl` for streamable HTTP (not `url`, which is SSE). See [examples/gemini-mcp.json](examples/gemini-mcp.json).


**OAuth2 Authentication**

```json
{
  "mcpServers": {
    "Checkmarx": {
      "type": "http",
      "url": "https://{cxone_base_url}/api/security-mcp/mcp/{tenant}"
    }
  }
}
```

**API Key Authentication:**

```json
{
  "servers":{
    "Checkmarx":{
      "url":"https://{cxone_base_url}/api/security-mcp/mcp/{tenant}",
      "headers":{
        "cx-origin":"<your_platform>",
        "Authorization":"<cxone_api_key>"
      }
    }
  }
}
```

## Available Tools

Refer [usage](docs/usage.md) for detail information.

### Scanning

| Tool | Description |
|---|---|
| `planScan` | Recommend scan engines based on the project |
| `triggerScan` | Start a scan (CLI for local code, API for repository URL) |
| `getScanDetails` | Get scan status, progress, and severity summary |
| `getLatestScans` | Retrieve recent scans for a project |
| `listScans` | List scans with status, date, and branch filters |
| `listFindings` | List vulnerabilities from a scan with severity filtering |
| `getFindingDetails` | Get detailed information for a specific finding |

### Project management

| Tool | Description |
|---|---|
| `resolveProject` | Look up a project by name |
| `createProject` | Create a new Checkmarx One project |
| `listProjects` | Browse or search all projects |
| `getProjectConfig` | Get full project configuration |

### Application management

| Tool | Description |
|---|---|
| `listApplications` | Browse or search applications |
| `createApplication` | Create a new application |
| `getApplicationDetails` | Get application details by ID |
| `associateProject` | Link projects to an application |

### Analytics & risk

| Tool | Description |
|---|---|
| `getTenantVulnerabilitiesSummary` | Returns org-wide severity counts by engine over a time window (trends). |

### Remediation

| Tool | Description |
|---|---|
| `codeRemediation` | Provides fixes for code-level issues: SAST, secrets, and IaC misconfigurations. |
| `packageRemediation` | Analyzes and remediates a specific vulnerable or malicious package/dependency. |
| `imageRemediation` | Provides remediation for container image CVEs and safer base-image alternatives. |


## License

Apache 2.0 — see [LICENSE](LICENSE) for details.


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, module architecture, and contribution guidelines.

Website: [Checkmarx](https://checkmarx.com/).


© 2026 Checkmarx Ltd.