# Changelog

All notable changes to the Checkmarx Security MCP Server will be documented below.

---

### Added in cx-cursor-plugin v1.0 (23-07-2026)

#### Cursor Plugin
- Initial release of `cx-cursor-plugin`, a Checkmarx MCP integration for [Cursor IDE](https://cursor.com/)
- MCP server registration through Cursor's plugin marketplace mechanism
- Distributed via Cursor Marketplace under the `security` category

#### Features
- Cursor IDE integration with Checkmarx MCP server.
- Seamless configuration with Checkmarx One API credentials (API Key or OAuth2)
- Support for local development installation from repository

---

### Added in cx-devassist v1.0 (17-07-2026)

#### Claude Code Plugin
- Initial release of `cx-devassist`, a fail-closed Claude Code plugin backed by [Checkmarx CxOne](https://checkmarx.com/)
- Distributed via `.claude-plugin/marketplace.json` under the `security` category

#### Fail-closed PreToolUse Gate
- Two-stage PreToolUse hook chain (`cx_check.sh` → `cx_check.py`, then a native `cx hooks claude-*` scanner) gating `Write` / `Edit` / `MultiEdit` / `NotebookEdit`, `Bash` / `PowerShell`, and MCP tool calls
- Fails closed on any uncertainty — a missing, outdated, incapable, or unauthenticated `cx` binary denies the action with an actionable message instead of letting it through unscanned
- Cross-OS hardening: hooks invoke `sh` (never bare `bash`, which Windows resolves to a WSL stub) and shipped scripts are pinned to LF line endings via `.gitattributes`
- `cx-mcp-guard.sh` centralizes the version/capability decision shared by the MCP bridge spawn (`cx_run.sh`) and the bootstrap installer's verify step, replacing two independently drifting checks
- Structured, redacted JSONL audit logging (`cx_log.py`) of gate and scan decisions to `~/.checkmarx/agent-logs/<assistant>/cx-devassist.jsonl`, including a new `mcp_connect` event and self-explanatory `reason_code` values for scan decisions

#### Skills
- `cx-cli-setup` — guided install, PATH setup, and authentication (API key or browser OAuth) for the `cx` CLI
- `cx-devassist-asca` — on-demand SAST (ASCA) scan of a source file with inline remediation via the Checkmarx MCP server
- `cx-devassist-sca` — on-demand SCA scan of dependency manifests/lockfiles with inline remediation via the Checkmarx MCP server
- Remediation guidance refined to scope fixes to in-scope findings only, reporting pre-existing vulnerabilities as out-of-scope

#### Admin Onboarding
- Optional `config/cx-onboarding.properties` lets an administrator pre-fill the Checkmarx One URL and tenant for OAuth sign-in, with strict validation and no out-of-tree override

#### Remediation MCP
- Bundled `.mcp.json` auto-starts the Checkmarx MCP server (`cx mcp bridge`) for remediation tooling — no manual `claude mcp add` step required

#### Repository restructuring
- Reworked the root README to describe **Checkmarx Agentic AI** as a whole (MCP server + Claude Code plugins), moving MCP-specific documentation to `README-MCP.md`
- License clarified to Apache 2.0 across the plugin and root documentation

---

### Added in v1.0 (24-o6-2026)

#### Core MCP Server
- Initial release of the Checkmarx Security MCP Server
- Multi-protocol transport support: `stdio`, `sse`, and `http` (streamable HTTP)
- Modular architecture enabling independent team contributions per module

#### Authentication
- API Key authentication via `Authorization` header
- OAuth2 authentication with Dynamic Client Registration (DCR) support

#### Scanning Tools (7 tools)
- `planScan` — Recommend scan engines before triggering
- `triggerScan` — Start scans in CLI (local code) or API (repository URL) mode
- `getScanDetails` — Retrieve scan status, progress, and severity summary
- `getLatestScans` — Fetch recent scans for a project
- `listScans` — List scans with status, date range, and branch filters
- `listFindings` — List vulnerabilities with severity filtering
- `getFindingDetails` — Get detailed information for a specific finding

#### Project Management Tools (4 tools)
- `resolveProject` — Resolve a project by name (exact match, candidates, or not found)
- `createProject` — Create a new Checkmarx One project
- `listProjects` — Browse or search all projects
- `getProjectConfig` — Retrieve full project configuration

#### Application Management Tools (4 tools)
- `listApplications` — Browse or search applications
- `createApplication` — Create a new application
- `getApplicationDetails` — Get application details by ID
- `associateProject` — Link projects to an application

#### Analytics & Risk Tools (7 tools)
- `getTenantVulnerabilitiesSummary` — Returns org-wide severity counts by engine over a time window (trends).

#### Remediation Tools (3 tools)
- `codeRemediation` — Provides fixes for code-level issues: SAST, secrets, and IaC misconfigurations.
- `packageRemediation` — Analyzes and remediates a specific vulnerable or malicious package/dependency.
- `imageRemediation` — Provides remediation for container image CVEs and safer base-image alternatives

#### MCP Resources (5 resources)
- `cxone://engines` — Supported scan engine definitions (SAST, SCA, KICS, Secret Detection)
- `cxone://severity-levels` — Vulnerability severity level definitions
- `cxone://finding-states` — Finding lifecycle states
- `cxone://scan-statuses` — Scan execution status definitions
- `cxone://capabilities` — Server capabilities and tool routing rules

#### MCP Prompts (1 prompt)
- `security-scan` — Guided end-to-end scan workflow with engine selection, project resolution, and results

#### Scan Engines Support
- **SAST** — Static Application Security Testing (30+ languages)
- **SCA** — Software Composition Analysis (open-source dependencies)
- **KICS** — Infrastructure as Code security (Terraform, CloudFormation, Kubernetes, Dockerfile)
- **Secret Detection** — Hardcoded credentials, API keys, and tokens

#### Integrations
- Checkmarx One platform (SAST, SCA, KICS, Container Security)
- OpenTelemetry for distributed tracing and structured logging

#### IDE & Client Support
- All MCP client which supports API key and OAuth2 with DCR authentication
- Example: Windsurf, GitHub Copilot, Claude, Cursor etc.

