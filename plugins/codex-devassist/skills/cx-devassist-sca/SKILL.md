---
name: cx-devassist-sca
description: "Runs a Checkmarx SCA (Software Composition Analysis / OSS) scan on dependency manifests and lockfiles to detect vulnerable and malicious open-source packages, and remediates findings using the Checkmarx MCP tool. Use when a user asks to scan dependencies, check packages, audit a manifest/lockfile (package.json, requirements.txt, go.mod, pom.xml, build.gradle, …), or fix SCA/OSS findings. Invoke as: $cx-devassist-sca"
---

# CX DevAssist SCA

Detects and remediates vulnerable / malicious open-source dependencies using Checkmarx SCA (OSS
realtime). This is the **dependency / package** counterpart to `cx-devassist-asca` (which scans source
code for SAST vulnerabilities).

## When to Use

This skill has two entry points:

1. **On-demand scan** — User asks to scan or audit dependencies (e.g., "scan my dependencies", "check
   package.json", "are my npm/pip packages safe?", "audit go.mod").
2. **Remediation** — User asks to fix SCA/OSS findings, or SCA findings from a hook block need fixing.

> **If SCA findings are already present in context** (e.g., provided by a hook block or a prior scan),
> **skip Flow 1** and go directly to Flow 2 using those findings. Do not re-run the scan.

### Routing — which Checkmarx capability to use

The plugin exposes three scan surfaces; pick by the target, and ask if it is ambiguous:

| The user wants to scan… | Use |
|---|---|
| A **source code file** (`.py`, `.js`, `.java`, `.go`, …) for code vulnerabilities | `cx-devassist-asca` (SAST) |
| A **dependency manifest / lockfile** (package.json, requirements.txt, go.mod, pom.xml, …) | **this skill** (SCA/OSS) |
| An **entire project / repository** at cloud scale, or existing platform scan results | the Checkmarx MCP (Cx1 cloud) tools |

A bare "scan this file" refers to whatever file is in context: a manifest/lockfile → this skill; source
code → `cx-devassist-asca`. If it is unclear which, ask the user.

## Prerequisites

- Checkmarx `cx` CLI installed. On a first-install session `cx` is in the **canonical store** but not
  yet on the agent shell's PATH, so invoke it by its **absolute path** —
  `"$LOCALAPPDATA/Checkmarx/cx/cx.exe"` on Windows, `"$HOME/.checkmarx/bin/cx"` on Unix (these env vars
  are available in the agent's shell) — and fall back to a bare `cx` only when it is already on PATH.
- Checkmarx MCP server connected (required for remediation).

> **Remediation is MCP-only.** Every fix MUST come from `mcp__Checkmarx__packageRemediation`. If that
> tool is not available, you MUST NOT remediate by any other means — no manual edits to the manifest,
> no generic or LLM-guessed version bumps. Stop and recover the MCP first (see Flow 2 → Step 2).

---

## Flow 1: On-Demand Scan

### Step 1 — Identify the Manifest(s) to Scan

Ask the user which manifest/lockfile to scan if not already specified. Recognized manifests include
`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`,
`go.mod`, `go.sum`, `pom.xml`, `build.gradle`, `build.sbt`.

### Step 2 — Run the SCA (OSS realtime) Scan

Invoke cx by its canonical absolute path so it resolves even when cx isn't on the agent shell's PATH
(a first-install session); use a bare `cx` only when cx is already on PATH. `-s` accepts a single file
or several files separated by commas.

```bash
# Unix (macOS/Linux):
"$HOME/.checkmarx/bin/cx" scan oss-realtime -s "<manifest-path>"
# Windows (Git Bash):
"$LOCALAPPDATA/Checkmarx/cx/cx.exe" scan oss-realtime -s "<manifest-path>"
```

### Step 3 — Process Results

The scan returns a JSON response of this shape:

```json
{
  "Packages": [
    {
      "PackageManager": "npm",
      "PackageName": "lodash",
      "PackageVersion": "4.17.15",
      "FilePath": "package.json",
      "Locations": [ { "Line": 12, "StartIndex": 4, "EndIndex": 22 } ],
      "Status": "Vulnerable",
      "Vulnerabilities": [
        { "CVE": "CVE-2020-8203", "Description": "Prototype pollution in lodash", "Severity": "High" }
      ]
    }
  ]
}
```

Interpret each package by its `Status`:
- **`OK`** — clean; no action needed.
- **`Unknown`** — the package could not be resolved against the Checkmarx database. This is **not** a
  guarantee it is safe — tell the user it could not be verified rather than asserting it is clean.
- **`Malicious`** — a known malicious package. Flag it prominently; the safest remediation is removal.
- **Anything else (e.g. `Vulnerable`)** — has known vulnerabilities in `Vulnerabilities[]`.

- **If no package has a `Malicious` or vulnerable `Status`** — inform the user the manifest passed the
  Checkmarx SCA scan with no findings.
- **If there are findings** — report each: `PackageName@PackageVersion` (`PackageManager`), `FilePath`
  and `Locations` line, `Status`, and for each entry in `Vulnerabilities[]` the `CVE`, `Severity`, and
  `Description`. Then ask: **"Would you like me to remediate these findings?"** If yes, go to Flow 2.

---

## Flow 2: Remediation

Triggered after the user confirms in Flow 1, or when SCA findings need fixing. Perform all steps
**completely and autonomously** — no user interaction.

### Step 1 — Gather Finding Details

For each package to remediate, collect `PackageManager`, `PackageName`, `PackageVersion`, and the
`Vulnerabilities` (CVE list) from the scan.

### Step 2 — Call `mcp__Checkmarx__packageRemediation`

For each finding, call the `mcp__Checkmarx__packageRemediation` tool, passing the affected package's
details. **The tool's own input schema (shown when you invoke it) is the source of truth for the exact
field names** — provide at minimum the package manager, name, version, and the CVE(s):

```json
{
  "packageManager": "[PackageManager from scan]",
  "packageName": "[PackageName from scan]",
  "packageVersion": "[PackageVersion from scan]",
  "vulnerabilities": "[CVE(s) from the finding]",
  "type": "sca"
}
```

If the tool's schema names its fields differently, follow the tool's schema — do not fail the call over
field naming.

- If the tool is **available**: parse `remediation_steps` from the response and proceed to Step 3.
- If the tool is **not available**: **STOP. Do NOT remediate by any other means** — no manual manifest
  edit, no guessed version bump. Leave the dependency **unchanged**. Then recover the MCP:

  1. The plugin ships an `.mcp.json` (see `references/mcp.md` in the `cx-cli-setup` skill) —
     Codex CLI's plugin system discovers it and syncs the `Checkmarx` server into
     `~/.codex/config.toml` (or `<repo>/.codex/config.toml`) as `[mcp_servers.Checkmarx]`
     automatically. Do **not** hand-write or edit that `config.toml` stanza yourself — it is
     plugin-managed. If the tool is missing, first confirm cx itself is configured/authenticated —
     verify with `"$HOME/.checkmarx/bin/cx" auth validate` (Unix) /
     `"$LOCALAPPDATA/Checkmarx/cx/cx.exe" auth validate` (Windows), or a bare `cx auth validate` when
     cx is on PATH; if it fails, run `$cx-cli-setup`.
  2. **Retry before asking for a restart.** Whether Codex CLI's plugin-MCP sync takes effect without
     a process restart is not consistently confirmed — it has been observed to connect live in some
     sessions. So immediately re-attempt the `mcp__Checkmarx__packageRemediation` call once. If it now
     succeeds, continue the remediation normally — do not mention a restart at all. Only if the retry
     still shows the tool unavailable, tell the user:

     > "The Checkmarx remediation MCP isn't connected in this session. Please quit this Codex CLI
     > session (e.g. `/exit`) and start it again — optionally with `codex resume --last` to pick this
     > conversation back up — so the plugin's MCP server registration takes effect. Once you're back,
     > ask me to remediate again. I won't apply a non-Checkmarx fix in the meantime."

  Then end the remediation flow without modifying any dependency.

  > Note: do **not** run any `cx_mcp_register.sh` script, and do not hand-edit `config.toml` — this
  > plugin registers its MCP via `.mcp.json`, and quitting and relaunching Codex CLI is the correct
  > recovery (there is no in-session `/restart`).

- If the tool call **errors with "Transport closed"** (or any other connection/transport error) instead
  of returning a result: the MCP server was available but its connection has died mid-session — this is
  a different failure from "tool not available" above and is **not recoverable by config changes**.
  **STOP. Do NOT remediate by any other means.** Leave the dependency **unchanged**, then tell the user:

  > "The Checkmarx remediation MCP's connection was lost mid-session (Transport closed). Codex CLI has
  > no in-session `/restart` or hot-reload for MCP servers, so please **quit this session (e.g.
  > `/exit`) and run `codex resume --last`** to pick this conversation back up — Codex will reconnect
  > the MCP server on the next launch. Once you're back, ask me to "remediate" to continue with remediation and I'll proceed with the
  > remediation for the remaining/unfixed findings — you won't need to repeat the scan or re-describe
  > what's left."

  Then end the remediation flow without modifying any dependency. Do not retry the same tool call in a
  loop — a dead transport will not recover within the same session.

### Step 3 — Apply the Fix

- Execute each instruction in `remediation_steps` in order (typically an upgrade to a fixed version, or
  removal for a malicious package).
- **Only modify the affected dependency entry** in the manifest/lockfile — do not touch unrelated
  dependencies. For each change, track: file modified, package, old version → new version (or removal).
- Regenerate the lockfile if the ecosystem requires it (e.g. `npm install`, `pip install -r`,
  `go mod tidy`) only when the user's workflow expects it; otherwise note that a lockfile refresh is
  needed.

### Step 4 — Re-scan

Re-run the Flow 1 Step 2 command on the same manifest.

The scan reads the WHOLE manifest, so it also reports vulnerable packages you never touched.
**Remediate only the findings that belong to the packages you changed in Step 3** — everything else is
pre-existing and out of scope.

Classify every finding against the packages you changed:

- **In scope — remediate.** Either:
  - the package you upgraded/removed is still reported — your fix did not resolve it; or
  - the version you moved to has findings of its own, including a transitive dependency **that version
    pulled in** — your fix introduced it.
- **Out of scope — do NOT fix, and do not touch that dependency.** Any finding for a package you did not
  change, including a transitive dependency that was already in the tree before your change.

Repeat Flow 2 from Step 2 for the in-scope findings **only**. If an in-scope finding survives a second
remediation attempt, stop and report it unresolved — do not keep looping (version ping-pong, where each
upgrade surfaces the next CVE, is the failure mode this bound exists to stop).

Report the out-of-scope findings in the Step 5 summary as pre-existing and unfixed.

### Step 5 — Output Remediation Summary

```
SCA Remediation Summary

Package:   [PackageName] [old-version] → [new-version | REMOVED]
Manager:   [PackageManager]
Issue:     [CVE list] ([highest severity])
File:      [FilePath]

Pre-existing findings (NOT fixed — outside the scope of this remediation):
- [package@version] — [CVE list] — [severity]
- (omit this section entirely when the re-scan reports none)
```

**Final status:**
- ✅ All fixed: "SCA remediation completed. Affected packages upgraded/removed; they are clean on
  re-scan. Any pre-existing findings in packages I did not change are listed above, unfixed."
- ⚠️ Partially fixed: "SCA remediation partially completed — manual review required (e.g. no fixed
  version exists / breaking upgrade). TODOs noted."
- ❌ Failed: "SCA remediation failed. Reason: [summary]. Unresolved packages listed above."

### Suppression (only when explicitly requested and justified)

If the user decides to accept/ignore a specific finding rather than fix it, use cx's suppression rather
than a manual edit:

```bash
"$HOME/.checkmarx/bin/cx" ignore-vulnerability --scan-type sca --data '<json>'
```

### Constraints

- **All remediation MUST come from `mcp__Checkmarx__packageRemediation`. Never apply a manual, generic,
  or non-MCP fix — if the MCP is unavailable, stop and recover it (Step 2), do not improvise.**
- Do not prompt the user during Flow 2.
- Only modify the dependency entries corresponding to the identified findings.
- Insert clear `TODO` comments where a finding cannot be safely auto-remediated.
- Remediation must be deterministic, auditable, and fully automated.

---
