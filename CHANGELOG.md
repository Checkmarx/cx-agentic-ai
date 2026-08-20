# Changelog

All notable changes to the Checkmarx Security MCP Server will be documented below.

---

### Changed in cx-devassist (unreleased)

#### The readiness gate now blocks only what Checkmarx can actually scan

Previously the gate denied **every** tool call — every shell command and every file write — whenever
`cx` was missing, outdated, unauthenticated or unlicensed. In practice that blocked ordinary
development (`git status`, `npm test`, `mvn verify`, `pytest`, `docker build`) while protecting
nothing: the native shell handler only checks an admin blacklist and dependency installs and **never
inspects file content**, so shell-written code (`cat > app.py`) was already unscanned on a healthy
`cx`. Field logs bore this out — every gate deny observed was "cx not ready", none was a security
finding, and every real finding came from `Write`/`Edit`.

- **Shell commands are no longer gated.** The `Bash|PowerShell` matcher no longer runs the readiness
  gate or the native scanner. Per-command hook cost drops from ~3400 ms to ~170 ms.
- **File writes are gated only for file types an engine can scan** — ASCA (source), KICS (IaC) and SCA
  (dependency manifests). The list is the new `config/cx-scannable-files`, mirroring the engines' own
  filters in `ast-cli`. Writes to `.md`, `.css`, `.sql`, `.html` and the like now proceed, because no
  engine would have scanned them. Note `.json` / `.yaml` **are** gated (KICS scans them), and a plain
  `.tfvars` is **not** (KICS lists only `.auto.tfvars` / `.terraform.tfvars`).
- **Unchanged for scannable files:** the full chain still runs — `CX_BINARY` validation, presence,
  version, capability, authentication, licensing, scanner-readiness, then ASCA/KICS/SCA plus
  blast-radius and file-size policy. Checkmarx MCP calls remain gated, and the install/upgrade
  bootstrap, `cx auth` / `cx configure` recovery and the `cx version` diagnostic all still work.
- **Rollback:** `CX_GATE_ALL_FILES=1` gates every file type again.
- **One** degraded state denies every file write regardless of type: no working Python 3, without which
  the gate cannot evaluate the file-type rule at all. cx present-but-unauthenticated and cx missing
  entirely both allow unscannable writes normally.

#### Added — remembered login environments

`cx auth login` takes two paths (`auth_login.go:57-86` in `ast-cli`). Given connection flags it skips
its prompt and persists **only** the refresh token (`auth_login.go:102`), leaving `cx_base_auth_uri` /
`cx_tenant` off disk; run bare and interactively it prompts via `PromptAuthConnection` and **does**
persist all three (`configuration.go:98-119`). An agent cannot answer a prompt, so an agent-issued
login is always the flag form — the one that persists nothing. Observing the command as it is issued
is therefore how those values are captured, and the `Bash|PowerShell` matcher keeps exactly one hook,
a **non-blocking observer**:

- `hooks/cx_record_login.sh` — records the URL + tenant of a `cx auth login` as *pending*
  (snapshotting the credential timestamp **before** the login runs, which is what later promotion
  requires), then exits 0 on every path. It emits no permission decision and cannot block a command.
  A pure-shell prefilter keeps ordinary commands from spawning Python at all.
- The gate promotes a pending pair to *confirmed* on the next successful authenticated call, and a
  later logged-out deny offers up to 3 confirmed pairs as choices the developer picks from.
  OAuth only — an API-key setup carries no URL/tenant to record.

#### Added
- `config/cx-scannable-files` — the scannable file types, with exactly one reader
  (`cx_check.py`'s `_is_scannable_file`).
- `tests/test_cx_check_scannable_files.py` and `tests/test_cx_check_login_history.py`, plus the shared
  `tests/_gatelib.py` harness. These run via `python -m unittest discover -s tests`; the older suites
  under `tests/hooks/`, `tests/scripts/` and `tests/test_packaging.py` target the copilot plugin and
  currently fail on a stale `plugins/copilot/checkmarx-devassist` path (pre-existing).

#### Notes
- The file-type rule is implemented **once**, in `cx_check.py`. A shell mirror was written so the
  cx-absent and no-Python deny branches could apply it too, then removed: keeping two implementations
  of one security decision in agreement produced three fail-open divergences. Neither branch needed a
  copy in the end — see the cx-absent fix below; the no-Python branch cannot run Python by definition
  and so denies every file write.
- `cx_check.py`'s Bash-only carve-outs (steps 1, 2, 5) and `CX_GATE_ALL_COMMANDS` are unreachable while
  shell is unrouted. They are annotated in place rather than deleted, so re-wiring shell onto the gate
  cannot silently open it.

#### Fixed
- **A trailing slash on `--base-auth-uri` silently discarded the remembered login.** `_ADMIN_URL_RE`
  permits no `/` in its host charset, so `https://host/` never validated even though `cx auth login`
  accepts that spelling and succeeds: `_parse_login_flags` returned `None` and the attempt was
  dropped with no entry and no log line. Observed on a test VM where three successful logins left no
  trace, while a failed one — typed without the slash — became the only remembered pair, and would
  have been promoted to `confirmed` off the credential write of a later, unrecorded, successful
  login. Base URIs are now canonicalized and validated by a single `_valid_base_uri` funnel shared by
  the three boundaries that accept one: command parsing, stored history entries, and the admin
  `config/cx-onboarding.properties`, which lost an admin's pre-fill the same way. A new
  `login_history action=skipped` audit event records any `auth login` that could not be remembered.
- **An invalid `CX_BINARY` sent agents into an unbreakable loop.** The `cx_binary_invalid` deny said
  "unset it to use cx from PATH" and nothing more, so an agent would suggest `/cx-cli-setup`, watch the
  bootstrap install `cx` successfully, and hit the identical deny again — forever — because a pin
  shadows the canonical store the bootstrap writes. Seen twice on a test VM whose `CX_BINARY` pointed
  at a leftover `C:\Cursor-plug\cx.exe`. It now carries the existing `_cx_binary_pin_note()` (already
  wired to `below_min` and `unrunnable`), which states that setup cannot fix it and gives the three
  real options, and the guidance now names the canonical store instead of only PATH.
- **Audit records vanished on Windows hosts reachable only via the `py` launcher.** `cx_run.sh` looked
  for `python3` then `python` at three separate inline sites — none tried `py -3`, which `cx_check.sh`
  had probed all along. On a normal python.org install exposing only `py`, every `scan_decision` and
  `mcp_connect` record was silently dropped, silently because logging is best-effort by contract. The
  three copies are now one `_cxrun_log()` helper that also tries `py -3`; verified by running with
  `python`/`python3` removed from PATH — the pushed version wrote nothing, this one writes the record.
- **A cx-less machine still blocked every file write.** `cx_run.sh`'s cx-unresolvable branch denied all
  `pre-file-write` calls, overriding stage 1 — which had already evaluated the same call correctly and
  logged `allow / unscannable_file`. Because verdicts merge most-restrictive-wins, stage 1 being right
  was not enough. Found by running the plugin on a VM with no cx: writing a one-line `list_files.sh`
  was refused with "the cx CLI could not be resolved … BLOCKED fail-closed", i.e. the original
  "it blocks everything" complaint relocated from shell to file writes. That branch now defers on a
  file write and keeps denying Checkmarx MCP calls. No file-type logic was added to shell to do it.
  Regression-tested in `tests/test_cx_check_scannable_files.py::CxAbsentStageTwo`, which drives the
  real scripts with all three cx resolution tiers defeated.
- `hooks/cx_check.sh` and `hooks/cx_run.sh` had CRLF line endings in the working tree despite
  `.gitattributes` pinning `*.sh` to LF (repo blobs were already LF). A stray `\r` breaks `sh` on
  Windows Git Bash, which the gate treats as a fail-open hole. `cx-scannable-files` is now pinned too.

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

