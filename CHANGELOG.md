# Changelog

All notable changes to the Checkmarx Security MCP Server will be documented below.

---

### Fixed in cx-devassist v1.0.2 (27-08-2026)

#### The gate no longer approves file writes on the developer's behalf

Installing the plugin **silently removed Claude Code's file-write approval prompt**. Writing a file
prompted for approval before installing; after installing, the same write went straight to disk with
no prompt at all. Permission mode was `default` both times and never changed.

Stage 2 (`hooks/cx_run.sh`) runs the native `cx` scanner and relayed its stdout byte-for-byte. On a
clean scan that stdout is `{"hookSpecificOutput":{"permissionDecision":"allow"}}`, and in Claude Code
an `allow` decision does **not** mean "this hook has no objection" — it means *bypass the permission
check entirely*, short-circuiting the evaluator where permission mode, the `settings.json`
allow/deny rules and the interactive prompt all live. Relaying it converted a **user-consent** gate
into a **scanner-verdict** gate for every `Write`, `Edit`, `MultiEdit`, `NotebookEdit` and
`mcp__Checkmarx__*` call the scanner did not flag. A clean scan is not consent: the scanner cannot
know the file was unwanted in the first place.

Stage 1 was already correct and could not compensate. It stays silent for a file no engine can scan
(`.sh`, `.md`, `.css`), and hook verdicts merge most-restrictive-wins — `deny` > `ask` > `allow` >
silence. **Silence is not a veto**, so stage 2's grant won regardless.

- **`hooks/cx_run.sh` never relays a grant.** A deny payload and *every* non-zero exit still relay
  through `hooks/cx_relay.py`, a new filter that removes a grant and forwards everything else
  untouched. The rule is **relay everything EXCEPT an explicit grant** — a denylist of one verdict,
  not an allowlist of one verdict. A deny (with or without whitespace in the JSON), an `ask`, a
  `continue:false`, advisory `additionalContext` and an inline `updatedInput` fix all still reach
  the host byte-for-byte; only the grant key is dropped, and when that was the payload's sole
  content the plugin says nothing at all. Unparseable stdout is relayed verbatim rather than
  swallowed — a dropped deny is a vulnerability on disk, a forwarded oddity is a visible hook error.
  This filter is permanent, not a stopgap: the wrapper must not depend on the binary never
  regressing.
- **`hooks/cx_check.py`: `_allow_with_warning` → `_defer_with_warning`.** The `CX_ALLOW_UNLICENSED=1`
  escape hatch also emitted `allow`, granting permission for a write it had just warned was going
  out UNSCANNED. It now emits `additionalContext` alone, with no `permissionDecision`. The warning
  still reaches the model; the decision goes back to the developer. Renamed because a helper called
  `_allow_*` that no longer allows invites the next author to "restore" the decision.
- **The audit trail is unchanged.** `cx-devassist.jsonl` still records
  `scan_decision decision=allow reason_code=no_issues_found` for a clean scan — it is now the only
  record that the scan happened at all, and a test pins that.
- **Not changed, and NOT clean — out of scope by decision:** `copilot-devassist` and
  `cursor-devassist` both still grant. `copilot-devassist/hooks/cx_check.py:799-805` carries the
  identical Claude-shaped payload on its `else:` branch (the in-file comment about
  `permissionDecision` not being a standard Copilot CLI field covers only the `if _COPILOT_CLI_MODE`
  branch above it, and that flag defaults to `False`). `cursor-devassist` grants in Cursor's own
  vocabulary — `{"permission":"allow"}` in `cx_check.py:1528,1530` and throughout `cx_check.sh` —
  and its `cx_run.sh` still relays the scanner's stdout unconditionally, which is the same
  relay-class defect fixed here. Cursor users very likely lose their approval prompt the same way.
  Tracked separately; do not read this release as clearing those trees.
- **Upstream:** the `cx` binary still emits `allow` from its `agenthooks` handlers; that is tracked
  separately so other hosts get the fix at source.

**Expect a prompt again on every clean write.** That is the point — approving a write is the
developer's call, and the host already offers the standard ways to opt out (`acceptEdits` mode, or a
`permissions.allow` rule). Those are the developer's decisions to make, not the plugin's.

#### Added

- `tests/test_cx_devassist_never_grants.py` — 23 tests. The load-bearing layer drives `cx_run.sh`
  with a fake `cx` pinned via `CX_BINARY` and asserts on stdout: the grant is dropped at every exit
  code, while a compact deny, a **spaced** deny, an `ask`, a `continue:false`, advisory context, an
  `updatedInput` fix and unparseable output all survive. `_defer_with_warning` is covered directly.
  A source scan of the plugin catches a hard-coded grant — with its limit stated in the class
  docstring: it could NOT have caught the original bug, which was a relay of a third-party binary's
  stdout and never literal text in this repo. No `skipUnless` guards the shell layer; an absent
  `bash` raises, because a silent skip there would let the suite report OK without testing the fix.
  Wired into `tests/run-tests.sh` in its own process, like the sibling gate suites — both plugin
  roots ship a module named `cx_check` and whichever imports first wins `sys.modules`.

  Note this is not enforced by CI: no workflow in `.github/workflows/` invokes `run-tests.sh`, and
  that runner already exits non-zero on two pre-existing copilot packaging failures. The suite is a
  local guard, not a merge gate, until that is fixed.

Verified by mutation, not just by passing: the suite fails against the pre-fix code (8 failures) and
also against the first attempted fix (7 failures, 2 errors) — a deny-glob guard that looked correct
and was green under the original, weaker tests.

---

### Changed in cx-devassist v1.0.1 (21-08-2026)

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
  `tests/_gatelib.py` harness. Run them with `tests/run-tests.sh`, which executes each suite in its
  OWN process: both plugin roots ship a module named `cx_check`, so a flat
  `python -m unittest discover -s tests` lets whichever suite imports first win `sys.modules` and
  silently swaps the module under test. Two copilot-side packaging checks fail on a clean tree — a
  marketplace name mismatch, and a `cx-mcp-guard.sh` floor of `2.3.57` against a `cx-min-version` of
  `2.3.58` — both pre-existing and outside this plugin.

#### Added — Apple and Ruby dependency manifests
`config/cx-scannable-files` now lists the SCA manifests for CocoaPods, Carthage, Swift PM, Ruby and
Dart: `Podfile`, `Cartfile`, `Cartfile.private`, `Gemfile`, `Package.swift`, `*.podspec` and
`*.podspec.json`.

Swift PM's multi-toolchain variants (`Package@swift-5.9.swift`) needed a new match kind,
`swiftprefix:` — a `.swift` file is a manifest only when its basename carries that prefix, exactly as
`requirements.txt` is one but `changelog.txt` is not. Gating on the `.swift` extension alone would
have pulled in every Swift source file in the repo; `App.swift` stays ungated, because no engine
scans it.

Both prefix rules are now keyed by extension in `_PREFIX_KINDS_BY_EXT`, from which `_SCANNABLE_KINDS`
is derived, so adding a kind is one entry in one place. That mattered: `swiftprefix:` first shipped in
the config while the parser still recognised four kinds, and an unrecognised kind is dropped
SILENTLY — the line read correctly and gated nothing. Drift guards now fail the build in both
directions: a kind the config declares but the code does not implement, and a kind the code
implements but the config never uses.

Measured across 68 filenames: 8 newly gated, **0 newly ungated**.

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

