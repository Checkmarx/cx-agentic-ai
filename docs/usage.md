# Usage Guide

This guide covers how to use the Checkmarx Security MCP Server with your AI coding assistant.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Available Tools](#available-tools)
  - [Scanning](#scanning)
  - [Project Management](#project-management)
  - [Application Management](#application-management)
  - [Analytics & Risk](#analytics--risk)
  - [Remediation](#remediation)
- [MCP Resources](#mcp-resources)
- [MCP Prompts](#mcp-prompts)
- [Example Workflows](#example-workflows)

---

## Overview

The Checkmarx Security MCP Server exposes Checkmarx One's application security platform as natural-language-accessible tools for AI coding assistants. Once configured, you can trigger security scans, investigate findings, and receive AI-generated remediation suggestions directly from your IDE or AI agent.

**Supported scan engines:**
- **SAST** — Static Application Security Testing (30+ languages)
- **SCA** — Software Composition Analysis (open-source dependencies)
- **KICS** — Infrastructure as Code security (Terraform, CloudFormation, Kubernetes, Dockerfile)
- **Secret Detection** — Hardcoded credentials, API keys, tokens

**Supported transport protocols:**
- `stdio` — Standard input/output for CLI or embedded agents
- `sse` — Server-Sent Events for real-time streaming
- `http` (streamableHttp) — HTTP-compatible stream-based messaging

---

## Prerequisites

Before using the MCP server you need:

1. A **Checkmarx One** tenant with valid credentials
2. Your **Checkmarx API host** (e.g., `ast.checkmarx.net`) — provided by your Checkmarx administrator
3. Your **tenant ID** (e.g., `cx_eu`, `checkmarx`)
4. An **API key** if using API Key authentication (see [authentication.md](authentication.md))
5. An MCP-compatible AI client (Cursor, Claude, Windsurf, GitHub Copilot, Gemini CLI, etc.)

---

## Quick Start

1. Obtain your API host and tenant ID from your Checkmarx administrator.
2. Generate an API key from the Checkmarx One portal (or use OAuth2 — see [authentication.md](authentication.md)).
3. Add the MCP server to your client configuration — see [examples/](../examples/) for ready-to-use configs.
4. Ask your AI assistant: *"Scan my project for security vulnerabilities"* or *"Show me the latest findings for project X"*.

---

## Available Tools

### Scanning

| Tool | Description |
|---|---|
| `planScan` | Recommend scan engines based on project content |
| `triggerScan` | Start a scan — CLI mode for local code, API mode for repository URL |
| `getScanDetails` | Get scan status, progress, and severity summary |
| `getLatestScans` | Retrieve recent scans for a project |
| `listScans` | List scans with status, date range, and branch filters |
| `listFindings` | List vulnerabilities from a scan with severity filtering |
| `getFindingDetails` | Get detailed information for a specific finding |

**Example prompts:**
- *"Scan my current project for security issues"*
- *"What scan engines should I use for this Node.js project?"*
- *"Show me all critical findings from the last scan"*
- *"Get details on finding ID abc123"*

---

### Project Management

| Tool | Description |
|---|---|
| `resolveProject` | Look up a project by name (returns exact match, candidates, or not found) |
| `createProject` | Create a new Checkmarx One project |
| `listProjects` | Browse or search all projects |
| `getProjectConfig` | Get full project configuration |

**Example prompts:**
- *"Find the project named my-api"*
- *"Create a new project for my-frontend repo"*
- *"List all projects in my tenant"*

---

### Application Management

| Tool | Description |
|---|---|
| `listApplications` | Browse or search applications |
| `createApplication` | Create a new application |
| `getApplicationDetails` | Get application details by ID |
| `associateProject` | Link projects to an application |

**Example prompts:**
- *"Show me all applications in my organization"*
- *"Create an application called 'Payment Service'"*
- *"Associate project my-api with the Payment Service application"*

---

### Analytics & Risk

| Tool | Description |
|---|---|
| `listProjectsOverview` | High-level project security status |
| `getProjectsOverviewAggregate` | Organization-wide project metrics |
| `getApplicationsOverviewAggregate` | Organization-wide application metrics |
| `getTenantVulnerabilitiesSummary` | Time-windowed vulnerability analytics |
| `getRiskSummary` | Overall risk assessment |
| `listRiskResults` | Risk findings with filtering |
| `updateRiskResultStatus` | Update finding status (TO_VERIFY, CONFIRMED, URGENT, NOT_EXPLOITABLE) |

**Example prompts:**
- *"Give me a risk summary for my tenant"*
- *"How many critical vulnerabilities were introduced this month?"*
- *"Mark finding XYZ as NOT_EXPLOITABLE"*

---

### Remediation

| Tool | Description |
|---|---|
| `codeRemediation` | AI-generated fixes for SAST findings, secrets, and IaC misconfigurations |
| `packageRemediation` | Safe upgrade paths for vulnerable open-source packages (npm, Maven, PyPI, Go, NuGet) |
| `imageRemediation` | Secure base image alternatives for vulnerable container images |

**Example prompts:**
- *"Fix the SQL injection vulnerability in finding #42"*
- *"What's the safe version of lodash to fix this CVE?"*
- *"Suggest a secure base image for my Dockerfile"*

---

## MCP Resources

The server exposes these read-only resources for context:

| Resource URI | Description |
|---|---|
| `cxone://engines` | Supported scan engine definitions |
| `cxone://severity-levels` | Vulnerability severity level definitions |
| `cxone://finding-states` | Finding lifecycle states |
| `cxone://scan-statuses` | Scan execution status definitions |
| `cxone://capabilities` | Server capabilities and tool routing rules |

---

## MCP Prompts

| Prompt | Description |
|---|---|
| `security-scan` | Guided end-to-end scan workflow — engine selection, project resolution, and results |

Use the `security-scan` prompt to let the AI assistant walk you through a complete security scan interactively.

---

## Example Workflows

### End-to-End Security Scan

```
1. "What scan engines should I use for this project?"     → planScan
2. "Scan the project my-api on the main branch"           → triggerScan
3. "Is the scan done? Show me the results"                → getScanDetails
4. "List all HIGH and CRITICAL findings"                  → listFindings
5. "Fix the SQL injection in finding #12"                 → codeRemediation
```

### Vulnerability Triage

```
1. "Show me the risk summary for my tenant"               → getRiskSummary
2. "List all CONFIRMED critical risk results"             → listRiskResults
3. "Mark finding ABC as NOT_EXPLOITABLE with a note"      → updateRiskResultStatus
```

### Dependency Security

```
1. "Scan my project for vulnerable dependencies"          → triggerScan (SCA)
2. "List all HIGH severity SCA findings"                  → listFindings
3. "What's the safe version of express to fix CVE-XXXX?"  → packageRemediation
```
